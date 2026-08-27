import { Injectable, Logger } from '@nestjs/common';
import { DbService } from '../db/db.module.js';
import { KeysService } from '../keys/keys.service.js';
import { RedisService } from '../redis/redis.module.js';
import { MetricsService, type ReadinessComponent } from './metrics.service.js';

/** Per-component readiness verdict. Deliberately coarse — see the controller. */
export type ComponentStatus = 'ok' | 'fail';

export interface ReadinessReport {
  ready: boolean;
  checks: Record<ReadinessComponent, ComponentStatus>;
}

/** Probe timeout: a hung dependency must read as "not ready", not hang the probe. */
const PROBE_TIMEOUT_MS = 2000;

async function withTimeout<T>(work: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} probe timed out`)), PROBE_TIMEOUT_MS);
        // Do not hold the event loop open on a probe timer.
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Readiness checks for an orchestrator (09 §2 Phase 3 — incident/ops maturity).
 *
 * "Ready" means this replica can actually complete an authentication, so each
 * check exercises the real dependency rather than a cached flag:
 *   - **Postgres** — every flow reads or writes it, and the audit append that
 *     must accompany every security event is a Postgres transaction (07 §4).
 *   - **Redis** — challenges, nonces, rate limits and the token denylist live
 *     there; without it the broker cannot issue a single-use challenge (T4)
 *     and cannot honour a token revocation (06 §4).
 *   - **Signing key** — a replica that cannot SIGN cannot mint an id_token, so
 *     the probe performs a real signature rather than asserting a row exists.
 *     This is the check that will catch an expired KMS credential once key
 *     custody moves to KMS/HSM (decision #5).
 *
 * Failure detail never reaches the response body — an unauthenticated probe
 * endpoint that reports "postgres: password authentication failed" is an
 * information leak. Detail goes to the structured log.
 */
@Injectable()
export class HealthService {
  private readonly logger = new Logger('HealthService');

  constructor(
    private readonly dbService: DbService,
    private readonly redis: RedisService,
    private readonly keys: KeysService,
    private readonly metrics: MetricsService,
  ) {}

  async readiness(): Promise<ReadinessReport> {
    const [postgres, redis, signingKey] = await Promise.all([
      this.check('postgres', async () => {
        await this.dbService.pool.query('SELECT 1');
      }),
      this.check('redis', async () => {
        const pong = await this.redis.client.ping();
        if (pong !== 'PONG') throw new Error(`unexpected PING reply: ${pong}`);
      }),
      this.check('signing_key', async () => {
        await this.keys.probeSigning();
      }),
    ]);
    const checks: Record<ReadinessComponent, ComponentStatus> = {
      postgres,
      redis,
      signing_key: signingKey,
    };
    return { ready: postgres === 'ok' && redis === 'ok' && signingKey === 'ok', checks };
  }

  private async check(
    component: ReadinessComponent,
    probe: () => Promise<void>,
  ): Promise<ComponentStatus> {
    try {
      await withTimeout(probe(), component);
      this.metrics.recordReadiness(component, true);
      return 'ok';
    } catch (err) {
      // Operator-facing only; the probe response stays detail-free.
      this.logger.warn(
        `readiness check failed: component=${component} error=${
          err instanceof Error ? err.message : 'unknown'
        }`,
      );
      this.metrics.recordReadiness(component, false);
      return 'fail';
    }
  }
}
