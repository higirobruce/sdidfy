import {
  Global,
  Inject,
  Injectable,
  Logger,
  Module,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import * as jose from 'jose';
import { randomBytes } from 'node:crypto';
import type { AuditAction } from '@sdid/shared';
import { AuditService } from '../audit/audit.service.js';
import { loadConfig, type BrokerConfig } from '../config.js';
import { DbService } from '../db/db.module.js';
import { MetricsService } from '../observability/metrics.service.js';
import { createHsmPkcs11Custody } from './hsm-pkcs11.custody.js';
import {
  assertJwsSignatureShape,
  type CustodyEvent,
  type KeyCustody,
  type PublicJwks,
  type RotationResult,
  type SigningAlg,
} from './key-custody.js';
import { createKmsCustody } from './kms.custody.js';
import { PostgresDevKeyCustody } from './postgres-dev.custody.js';

/**
 * Broker token signing (04 §4, 06 §3, T13).
 *
 * This service owns the *protocol* half of signing — JWS assembly, claims,
 * verification against the JWKS, the readiness probe, and the key-usage audit.
 * It owns none of the *custody* half: which keys exist, where they live, and
 * who performs the signature all sit behind the injected `KeyCustody`
 * (`key-custody.ts`), which resolves spec open decision #5 in structure.
 *
 * WHY THE JWS IS ASSEMBLED BY HAND. `jose.SignJWT(...).sign(key)` needs a
 * local `KeyLike` and has no way to call out to a remote signer, so using it
 * would force the private key back into this process — the exact thing T13
 * exists to prevent. Instead the protected header and payload are encoded
 * here, the signing input is handed to `custody.sign()`, and the returned
 * signature is appended. `jose` still does all VERIFICATION, which needs only
 * public keys.
 *
 * The public surface (`issuer`, `jwks()`, `signJwt()`, `verifyJwt()`,
 * `probeSigning()`) is unchanged, so no call site moved.
 */

/** DI token for the custody boundary. */
export const KEY_CUSTODY = 'KEY_CUSTODY';

const ALG: SigningAlg = 'ES256';

/** Audience of the readiness probe token. It is signed and then discarded. */
const PROBE_AUDIENCE = 'readiness-probe';

/**
 * Minimum gap between two immediate `key.signing_failed` audit rows for the
 * same kid. A custody outage is not one event: /readyz probes every few
 * seconds and every RP request retries, so an unthrottled row-per-failure
 * would write thousands of rows through a globally-locked append (07 §4)
 * during exactly the incident when the audit trail must stay responsive. The
 * suppressed count is not lost — it is folded into the next usage summary.
 */
const SIGNING_FAILURE_AUDIT_INTERVAL_MS = 60_000;

/** Per-kid tallies awaiting the next usage summary. */
interface UsageTally {
  alg: SigningAlg;
  /** Signatures that went into a token handed to somebody. */
  signatures: number;
  /** Readiness-probe signatures. Counted apart so the trail stays meaningful. */
  probeSignatures: number;
  failures: number;
  /** Failures that did NOT get their own audit row, because of the throttle. */
  suppressedFailureRows: number;
}

const b64url = (input: string | Uint8Array): string =>
  (typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input)).toString('base64url');

@Injectable()
export class KeysService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('KeysService');

  /** Snapshot of the public JWKS. Refreshed at init, on rotation, on probe. */
  private publicJwks: PublicJwks = { keys: [] };
  private readonly usage = new Map<string, UsageTally>();
  private readonly lastFailureAuditAt = new Map<string, number>();
  /**
   * Lifecycle events the custody boundary reported since the last drain. One
   * listener is registered for the service's whole life (registering a fresh
   * one per rotation would leak listeners); `drainLifecycleEvents()` appends
   * them, because a listener cannot await.
   */
  private readonly pendingEvents: CustodyEvent[] = [];
  /** null until the first health check — the first verdict is always audited. */
  private lastHealthy: boolean | null = null;
  private usageTimer: NodeJS.Timeout | null = null;
  private shuttingDown = false;

  constructor(
    @Inject(KEY_CUSTODY) private readonly custody: KeyCustody,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  async onModuleInit(): Promise<void> {
    // Subscribe BEFORE init: a dev first boot generates a key inside init(),
    // and a key coming into existence is a security event that must be in the
    // trail (T13).
    this.custody.onEvent((event) => this.pendingEvents.push(event));
    await this.custody.init();
    this.publicJwks = await this.custody.listPublicJwks();
    await this.drainLifecycleEvents();

    const intervalMs = loadConfig().KEY_USAGE_SUMMARY_INTERVAL_SECONDS * 1000;
    this.usageTimer = setInterval(() => {
      // A failed summary append must not become an unhandled rejection that
      // kills the process — the tokens it was tallying were minted correctly.
      // `sdid_broker_audit_append_failures_total` is the page-worthy signal
      // for the underlying problem (07 §4); the tally is kept and rolls into
      // the next tick, so nothing is lost.
      void this.flushUsageSummary('interval').catch((err: unknown) => {
        this.logger.error(
          `periodic key usage summary failed: ${err instanceof Error ? err.message : 'unknown'}`,
        );
      });
    }, intervalMs);
    // Never hold the event loop open for a bookkeeping timer.
    this.usageTimer.unref?.();
  }

  async onModuleDestroy(): Promise<void> {
    this.shuttingDown = true;
    if (this.usageTimer) {
      clearInterval(this.usageTimer);
      this.usageTimer = null;
    }
    // Flush what this replica signed before it disappears. Best-effort by
    // necessity: Postgres may already be closing underneath us, and losing a
    // shutdown summary must not turn a clean stop into a crash.
    await this.flushUsageSummary('shutdown');
    await this.custody.close();
  }

  /**
   * Reload the custody view. Kept for compatibility with the pre-custody API
   * (and used by tests); the work itself now belongs to the provider.
   */
  async ensureActiveKey(): Promise<void> {
    await this.custody.init();
    this.publicJwks = await this.custody.listPublicJwks();
  }

  get issuer(): string {
    return loadConfig().BROKER_ISSUER;
  }

  jwks(): jose.JSONWebKeySet {
    return this.publicJwks;
  }

  /** Sign a JWT with the active broker key. `jti` is always set (revocation denylist). */
  async signJwt(
    payload: Record<string, unknown>,
    opts: { audience: string; ttlSeconds: number; jti?: string },
  ): Promise<string> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    return this.signCompactJws(
      {
        ...payload,
        iss: this.issuer,
        aud: opts.audience,
        iat: nowSeconds,
        exp: nowSeconds + opts.ttlSeconds,
        jti: opts.jti ?? randomBytes(16).toString('hex'),
      },
      'token',
    );
  }

  /** Verify a broker-issued JWT (first-party sessions, access tokens at /userinfo). */
  async verifyJwt(token: string, opts?: { audience?: string }): Promise<jose.JWTPayload> {
    const keyset = jose.createLocalJWKSet(this.jwks());
    const { payload } = await jose.jwtVerify(token, keyset, {
      issuer: this.issuer,
      audience: opts?.audience,
    });
    return payload;
  }

  /**
   * Readiness probe (/readyz): can this replica actually SIGN?
   *
   * The old implementation signed with a `KeyLike` imported once at boot, and
   * its comment predicted that "the key is present" and "the key is usable"
   * would diverge once custody moved to KMS/HSM. That divergence is now real,
   * so the probe exercises the whole custody path end to end:
   *
   *   1. `healthCheck()` — reaches the backend (an expired credential, a
   *      revoked grant, an unreachable HSM, a missing adapter all surface
   *      here), and a transition between healthy and unhealthy is audited.
   *   2. a real signature through `custody.sign()` — an authorised credential
   *      can still be refused for this particular key.
   *   3. verification against the published JWKS — catches the case that
   *      matters most and is easiest to miss: custody signs happily, but with
   *      a key whose public half is not the one relying parties will use, so
   *      every token we mint is unverifiable. Better to fail readiness than to
   *      hand out tokens nobody accepts.
   *
   * The probe token is never returned to anyone: it exists only to be signed.
   */
  async probeSigning(): Promise<void> {
    const health = await this.custody.healthCheck();
    await this.noteHealth(health.healthy, health.detail);
    if (!health.healthy) {
      throw new Error(`key custody unhealthy (${health.provider}): ${health.detail}`);
    }
    // Refresh the JWKS snapshot: healthCheck() has just re-read the backend,
    // so a key rotated by another replica lands here without a restart.
    this.publicJwks = await this.custody.listPublicJwks();
    if (this.publicJwks.keys.length === 0) {
      throw new Error('key custody published an empty JWKS');
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    const token = await this.signCompactJws(
      {
        probe: true,
        iss: this.issuer,
        aud: PROBE_AUDIENCE,
        iat: nowSeconds,
        exp: nowSeconds + 60,
      },
      'probe',
    );
    await jose.jwtVerify(token, jose.createLocalJWKSet(this.jwks()), {
      issuer: this.issuer,
      audience: PROBE_AUDIENCE,
    });
  }

  /**
   * Promote a fresh key and retire the current one, keeping retired keys in
   * the JWKS for overlap (06 §3).
   *
   * Deliberately NOT exposed over HTTP. Key rotation is an infrastructure
   * operation performed against the custody backend under its own controls,
   * not something the admin API token should be able to trigger (T12) — the
   * runbook (§4) drives it per provider.
   */
  async rotate(): Promise<RotationResult> {
    // Flush first, so the outgoing key's tally is attributed to the window in
    // which it was actually the signing key.
    await this.flushUsageSummary('rotation');
    const result = await this.custody.rotate();
    this.publicJwks = await this.custody.listPublicJwks();
    await this.drainLifecycleEvents();
    await this.audit.append({
      actor: { type: 'system' },
      action: 'key.rotated',
      result: 'success',
      context: {
        provider: this.custody.provider,
        promotedKid: result.promotedKid,
        retiredKids: result.retiredKids,
        alg: result.alg,
        // The overlap window is the operational fact an incident reviewer
        // wants next to a rotation: retired keys must stay published at least
        // this long or live tokens stop verifying.
        overlapSeconds: loadConfig().SESSION_TTL_SECONDS,
      },
    });
    return result;
  }

  /**
   * Emit the periodic per-kid usage summary (T13 "key-usage audit").
   *
   * One row per WINDOW, not one row per token. At national scale a row per
   * minted token would swamp the append-only chain — every append serialises
   * on a global advisory lock (07 §4) — and would bury the events that
   * actually need to be found. What accountability needs is: which key signed,
   * how much, and did anything fail. That is what this row carries.
   *
   * Public so the runbook's rotation flow and the tests can force a flush.
   */
  async flushUsageSummary(reason: 'interval' | 'rotation' | 'shutdown'): Promise<void> {
    if (this.usage.size === 0) return;
    const keys = [...this.usage.entries()].map(([kid, tally]) => ({
      kid,
      alg: tally.alg,
      signatures: tally.signatures,
      probeSignatures: tally.probeSignatures,
      failures: tally.failures,
      suppressedFailureRows: tally.suppressedFailureRows,
    }));
    try {
      await this.audit.append({
        actor: { type: 'system' },
        action: 'key.usage_summary',
        result: keys.some((k) => k.failures > 0) ? 'failure' : 'success',
        context: {
          provider: this.custody.provider,
          reason,
          windowSeconds: loadConfig().KEY_USAGE_SUMMARY_INTERVAL_SECONDS,
          keys,
        },
      });
    } catch (err) {
      // The tallies are deliberately NOT cleared on failure: they roll into
      // the next window rather than vanishing, so an audit outage costs
      // resolution, not accountability.
      if (this.shuttingDown) {
        // Teardown races the DB pool closing. Losing the last summary is a
        // gap in a tally, not an unaudited state change, and must not turn a
        // clean shutdown into a crash.
        this.logger.warn(
          `key usage summary not written at shutdown: ${err instanceof Error ? err.message : 'unknown'}`,
        );
        return;
      }
      throw err;
    }
    // Subtract what was reported rather than clearing the map: signing carries
    // on during the await, and those signatures belong to the NEXT window.
    for (const reported of keys) {
      const tally = this.usage.get(reported.kid);
      if (!tally) continue;
      tally.signatures -= reported.signatures;
      tally.probeSignatures -= reported.probeSignatures;
      tally.failures -= reported.failures;
      tally.suppressedFailureRows -= reported.suppressedFailureRows;
      if (
        tally.signatures === 0 &&
        tally.probeSignatures === 0 &&
        tally.failures === 0 &&
        tally.suppressedFailureRows === 0
      ) {
        this.usage.delete(reported.kid);
      }
    }
  }

  // --- internals ---------------------------------------------------------

  /**
   * Assemble a compact JWS around a custody signature.
   *
   * This is the whole reason the custody interface is sign-as-a-service: the
   * only thing that crosses the boundary is `signingInput` in and a signature
   * out. No key material is ever in scope in this method.
   */
  private async signCompactJws(
    claims: Record<string, unknown>,
    purpose: 'token' | 'probe',
  ): Promise<string> {
    const kid = await this.custody.activeKid();
    const header = { alg: ALG, kid, typ: 'JWT' };
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
    let signature: Uint8Array;
    try {
      signature = await this.custody.sign(kid, Buffer.from(signingInput, 'utf8'));
      // A provider bug that returns DER (or anything else) must fail the mint
      // rather than ship a token every relying party rejects.
      assertJwsSignatureShape(signature, ALG);
    } catch (err) {
      await this.recordSigningFailure(kid, purpose, err);
      throw err;
    }
    this.tally(kid, purpose === 'probe' ? 'probeSignatures' : 'signatures');
    this.metrics.recordSigningOperation({ kid, alg: ALG });
    return `${signingInput}.${b64url(signature)}`;
  }

  private tally(kid: string, field: keyof Omit<UsageTally, 'alg'>): void {
    const tally = this.usage.get(kid) ?? {
      alg: ALG,
      signatures: 0,
      probeSignatures: 0,
      failures: 0,
      suppressedFailureRows: 0,
    };
    tally[field] += 1;
    this.usage.set(kid, tally);
  }

  /**
   * A failed signature is an immediate, security-relevant event: a token was
   * not minted, and the cause is a custody problem (T13). It gets its own
   * audit row — throttled per kid, with the suppressed count carried into the
   * next summary so the trail stays honest about volume.
   */
  private async recordSigningFailure(kid: string, purpose: string, err: unknown): Promise<void> {
    this.metrics.recordSigningError({ kid, alg: ALG });
    this.tally(kid, 'failures');
    const now = Date.now();
    const last = this.lastFailureAuditAt.get(kid) ?? 0;
    if (now - last < SIGNING_FAILURE_AUDIT_INTERVAL_MS) {
      this.tally(kid, 'suppressedFailureRows');
      return;
    }
    this.lastFailureAuditAt.set(kid, now);
    try {
      await this.audit.append({
        actor: { type: 'system' },
        action: 'key.signing_failed',
        result: 'failure',
        context: {
          provider: this.custody.provider,
          kid,
          alg: ALG,
          purpose,
          error: err instanceof Error ? `${err.name}: ${err.message}` : 'unknown',
          throttleSeconds: SIGNING_FAILURE_AUDIT_INTERVAL_MS / 1000,
        },
      });
    } catch (auditErr) {
      // The operation is already failing; the caller must see the SIGNING
      // error, not an audit error that would mislead the diagnosis. This is
      // the one place the "a failed audit fails the operation" rule does not
      // apply, because the operation has already failed.
      this.logger.error(
        `could not audit a signing failure: ${
          auditErr instanceof Error ? auditErr.message : 'unknown'
        }`,
      );
    }
  }

  /** Audit a custody health transition — not every probe, only the changes. */
  private async noteHealth(healthy: boolean, detail: string): Promise<void> {
    if (this.lastHealthy === healthy) return;
    const previous = this.lastHealthy;
    this.lastHealthy = healthy;
    // The very first probe of a healthy boundary is not an incident; recording
    // it would put a row in the chain on every replica start.
    if (previous === null && healthy) return;
    try {
      await this.audit.append({
        actor: { type: 'system' },
        action: 'key.custody_health_changed',
        result: healthy ? 'success' : 'failure',
        context: {
          provider: this.custody.provider,
          healthy,
          previous,
          // `detail` is provider text about reachability and key counts. It
          // never carries key material — that is a contract requirement of
          // KeyCustody, not a hope (see key-custody.ts).
          detail,
        },
      });
    } catch (err) {
      this.logger.error(
        `could not audit a custody health transition: ${
          err instanceof Error ? err.message : 'unknown'
        }`,
      );
    }
  }

  /** Append every buffered lifecycle event, oldest first, then clear. */
  private async drainLifecycleEvents(): Promise<void> {
    while (this.pendingEvents.length > 0) {
      const event = this.pendingEvents.shift() as CustodyEvent;
      await this.auditLifecycleEvent(event);
    }
  }

  private async auditLifecycleEvent(event: CustodyEvent): Promise<void> {
    const action: AuditAction =
      event.type === 'key_generated'
        ? 'key.generated'
        : event.type === 'key_promoted'
          ? 'key.promoted'
          : 'key.retired';
    await this.audit.append({
      actor: { type: 'system' },
      action,
      result: 'success',
      context: { provider: event.provider, kid: event.kid, alg: event.alg, ...event.detail },
    });
  }
}

/**
 * Build the custody boundary this deployment runs (decision #5).
 *
 * Fail-closed by construction: `postgres-dev` refuses to build in production
 * (its own constructor throws, on top of the config guard rail), and the two
 * seams return a boundary that refuses every operation with
 * `KeyCustodyNotConfiguredError` rather than one that quietly reports "no
 * keys". Nothing here can produce a broker that boots without custody and
 * discovers it at the first citizen's login.
 */
export function createKeyCustody(config: BrokerConfig, dbService: DbService): KeyCustody {
  switch (config.KEY_CUSTODY) {
    case 'kms':
      return createKmsCustody({
        endpoint: config.KMS_ENDPOINT,
        keyGroup: config.KMS_KEY_GROUP,
        credentials: config.KMS_CREDENTIALS,
      });
    case 'hsm':
      return createHsmPkcs11Custody({
        libraryPath: config.HSM_PKCS11_LIBRARY,
        slot: config.HSM_SLOT,
        keyLabel: config.HSM_KEY_LABEL,
        pin: config.HSM_PIN,
      });
    case 'postgres-dev':
    default:
      return new PostgresDevKeyCustody(dbService.pool, config.NODE_ENV);
  }
}

@Global()
@Module({
  providers: [
    {
      provide: KEY_CUSTODY,
      useFactory: (dbService: DbService): KeyCustody => createKeyCustody(loadConfig(), dbService),
      inject: [DbService],
    },
    KeysService,
  ],
  exports: [KeysService, KEY_CUSTODY],
})
export class KeysModule {}
