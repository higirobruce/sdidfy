import { Global, Injectable, Logger, Module } from '@nestjs/common';
import { and, eq } from 'drizzle-orm';
import { loadConfig } from '../config.js';
import { DbService } from '../db/db.module.js';
import { deviceBindings } from '../db/schema.js';
import { MetricsService } from '../observability/metrics.service.js';
import { createApnsTransport } from './apns.transport.js';
import { createFcmTransport } from './fcm.transport.js';
import {
  PushNotConfiguredError,
  type PushPlatform,
  type PushTransport,
} from './push-transport.js';

/**
 * Wake-only push delivery (05 §5, T6).
 *
 * `wake(citizenId)` fans out to every ACTIVE binding of that citizen that has
 * registered a push token, and sends a payload containing nothing but a type
 * and a version — see `push-payload.ts` for why, and for the structural reason
 * a caller cannot add anything to it (the transport takes only a token).
 *
 * TWO PROPERTIES THIS SERVICE MUST HAVE, both load-bearing:
 *
 *  1. **It never throws.** Push initiation happens inside `/oidc/bc-authorize`
 *     and `/oidc/authorize`. If a Google outage or a missing credential could
 *     fail those, an RP-facing authentication request would fail for a reason
 *     that has nothing to do with the citizen's identity. Push is an
 *     optimisation over the app's own polling of `/v1/device/ciba/pending`,
 *     so every failure path here is metric + log, never an exception.
 *  2. **It is fire-and-forget for the caller's latency.** Awaited so tests are
 *     deterministic, but each transport carries its own timeout so a hung
 *     provider bounds the delay rather than holding the RP's request open.
 */
@Injectable()
export class PushService {
  private readonly logger = new Logger('PushService');
  private readonly transports: Record<PushPlatform, PushTransport>;

  constructor(
    private readonly dbService: DbService,
    private readonly metrics: MetricsService,
  ) {
    const config = loadConfig();
    this.transports = {
      fcm: createFcmTransport({
        projectId: config.FCM_PROJECT_ID,
        credentialsJson: config.FCM_CREDENTIALS_JSON,
        timeoutMs: config.PUSH_TIMEOUT_MS,
      }),
      apns: createApnsTransport({
        teamId: config.APNS_TEAM_ID,
        keyId: config.APNS_KEY_ID,
        privateKeyP8: config.APNS_PRIVATE_KEY_P8,
        topic: config.APNS_TOPIC,
        production: config.APNS_PRODUCTION,
        pushType: config.APNS_PUSH_TYPE,
        timeoutMs: config.PUSH_TIMEOUT_MS,
      }),
    };
  }

  /** True when at least one transport holds credentials (runbook/readiness aid). */
  get anyTransportConfigured(): boolean {
    return this.transports.fcm.configured || this.transports.apns.configured;
  }

  /**
   * Wake every active device of a citizen. NO transaction detail is passed in
   * or sent out — the signature takes a citizen id purely to look up device
   * addresses, and nothing derived from it reaches the wire (T6).
   */
  async wake(citizenId: string): Promise<void> {
    let targets: Array<{ id: string; platform: string | null; token: string | null }>;
    try {
      targets = await this.dbService.db
        .select({
          id: deviceBindings.id,
          platform: deviceBindings.pushPlatform,
          token: deviceBindings.pushToken,
        })
        .from(deviceBindings)
        .where(and(eq(deviceBindings.citizenId, citizenId), eq(deviceBindings.status, 'active')));
    } catch (err) {
      this.metrics.recordPushDelivery('none', 'lookup_failed');
      this.logger.warn(`push lookup failed: ${err instanceof Error ? err.message : 'unknown'}`);
      return;
    }

    const deliverable = targets.filter(
      (t): t is { id: string; platform: PushPlatform; token: string } =>
        (t.platform === 'fcm' || t.platform === 'apns') && typeof t.token === 'string' && t.token !== '',
    );
    if (deliverable.length === 0) {
      // Normal today: no device has registered a token because no app build
      // ships with push yet. The app polls, so this is not an error.
      this.metrics.recordPushDelivery('none', 'no_token');
      this.logger.debug('push wake: citizen has no registered device push token');
      return;
    }

    await Promise.all(deliverable.map((target) => this.deliver(target)));
  }

  private async deliver(target: { id: string; platform: PushPlatform; token: string }): Promise<void> {
    const transport = this.transports[target.platform];
    try {
      const outcome = await transport.send(target.token);
      this.metrics.recordPushDelivery(target.platform, outcome.status);
      if (outcome.status === 'unregistered') {
        // The provider says this address is dead. Clear it: keeping it would
        // mean retrying forever and holding a stale device address we have no
        // basis to retain (07 §6).
        await this.clearToken(target.id, 'provider-unregistered');
      } else if (outcome.status === 'failed') {
        this.logger.warn(`push delivery failed (${target.platform}): ${outcome.detail}`);
      }
    } catch (err) {
      if (err instanceof PushNotConfiguredError) {
        // Expected in every environment today. Logged at warn once per send
        // rather than error: it is a known gap, not an incident.
        this.metrics.recordPushDelivery(target.platform, 'not_configured');
        this.logger.warn(err.message);
        return;
      }
      this.metrics.recordPushDelivery(target.platform, 'error');
      this.logger.warn(
        `push transport threw (${target.platform}): ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
  }

  /**
   * Register or ROTATE a device's push token. Rotation is the same operation
   * as registration on purpose: FCM/APNs reissue tokens without warning (app
   * reinstall, restore from backup, provider policy), so the app re-registers
   * whatever it currently holds and the newest value simply wins.
   */
  async registerToken(bindingId: string, platform: PushPlatform, token: string): Promise<void> {
    await this.dbService.db
      .update(deviceBindings)
      .set({ pushPlatform: platform, pushToken: token, pushTokenUpdatedAt: new Date() })
      .where(eq(deviceBindings.id, bindingId));
  }

  /**
   * Remove a device's push address. Called on binding revocation (06 §4) —
   * a revoked device must stop being woken immediately, and its address is no
   * longer ours to hold — and when a provider reports the token is dead.
   */
  async clearToken(bindingId: string, reason: string): Promise<void> {
    await this.dbService.db
      .update(deviceBindings)
      .set({ pushPlatform: null, pushToken: null, pushTokenUpdatedAt: new Date() })
      .where(eq(deviceBindings.id, bindingId));
    this.logger.debug(`push token cleared (reason=${reason})`);
  }
}

@Global()
@Module({
  providers: [PushService],
  exports: [PushService],
})
export class PushModule {}
