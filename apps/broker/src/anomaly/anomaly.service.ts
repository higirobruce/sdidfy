import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { AuditAction, AuditEventInput } from '@sdid/shared';
import { createHmac } from 'node:crypto';
import { AuditService } from '../audit/audit.service.js';
import { loadConfig, type BrokerConfig } from '../config.js';
import { MetricsService, type AnomalyPattern } from '../observability/metrics.service.js';
import { RedisService } from '../redis/redis.module.js';

/**
 * Anomaly detection over the audit stream (spec 06 §5, T7/T9/T14).
 *
 * ===================== DETECTION ONLY — NEVER AUTOMATIC ACTION =============
 * Nothing in this file blocks, bans, suspends, throttles or revokes anything.
 * That is a deliberate design decision, not an unfinished feature.
 *
 * This is the authentication path for a NATIONAL identity service. Every
 * detector here works on a coarse signal — a source address, an RP id, a
 * binding id — and every one of those signals has a benign explanation that
 * occurs in normal operation:
 *   - Many distinct NIDs from one IP is an attacker probing the register …
 *     and is also a CNAM enrolment desk, a university campus, a district
 *     office, or an entire mobile network behind one carrier-grade NAT.
 *   - An attestation-rejection burst is a rooted-device farm … and is also a
 *     bad app release, an expired app-signing certificate, or a Play Integrity
 *     regression on one Android build.
 *   - A CIBA flood is a malicious RP … and is also a pilot RP's load test.
 * Auto-banning on any of these locks citizens out of services they have a
 * right to use, with no self-service path back (03 §5 recovery is a full
 * re-enrolment). A false positive here is a denial of a public service; a
 * false negative is an alert a human reviews minutes later. The asymmetry is
 * decisive, so the detector's only outputs are an AUDIT ROW, a METRIC and a
 * LOG LINE. Rate limits and lockouts (`RateLimitService`, 06 §5) remain the
 * automated controls — they are bounded, self-healing and per-actor.
 * ==========================================================================
 *
 * Two ways signals reach this service, for one reason: the audit trail is
 * append-only and retained for years (07 §4/§6), so a source IP must never be
 * written into it.
 *   1. **Audit-stream subscription** — patterns whose signal is fully present
 *      in the audit row (per-RP, per-binding). `AuditService` notifies
 *      observers after a successful append.
 *   2. **Direct calls from the request path** — patterns keyed by SOURCE IP.
 *      The IP is hashed here with a dedicated pepper, lives only in a
 *      short-TTL Redis key, and only a truncated hash prefix ever reaches the
 *      audit row, as a correlation handle. The raw IP goes to the operational
 *      log, which has its own (short) retention — 06 §7's point that the audit
 *      stream and operational logs are separate streams.
 */

/** A detection, as recorded. `sourceHandle` is never a raw IP. */
export interface AnomalyDetection {
  pattern: AnomalyPattern;
  /** Truncated peppered hash of the source, or the rp/binding scope key. */
  sourceHandle: string;
  observed: number;
  threshold: number;
  windowSeconds: number;
}

/**
 * The shared audit vocabulary (`AUDIT_ACTIONS` in @sdid/shared) has no
 * `security.anomaly_detected` member and lives outside this app's ownership,
 * so detections are recorded under `admin.action` with a `system` actor and an
 * `op` discriminator in context — exactly the pattern the admin controller
 * already uses for `reverify-sweep`. When the shared vocabulary gains a
 * dedicated action, this constant is the only thing that changes.
 */
const ANOMALY_AUDIT_ACTION: AuditAction = 'admin.action';
export const ANOMALY_AUDIT_OP = 'anomaly-detected';

@Injectable()
export class AnomalyService implements OnModuleInit {
  private readonly logger = new Logger('AnomalyService');

  constructor(
    private readonly redis: RedisService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  onModuleInit(): void {
    // Subscribe rather than poll: an append is the event, and polling an
    // append-only table would either miss rows or re-scan them forever.
    this.audit.subscribe((event) => {
      void this.onAuditEvent(event);
    });
  }

  private get config(): BrokerConfig {
    return loadConfig();
  }

  /**
   * Peppered, truncated source handle. Not reversible without the pepper, and
   * short enough that it is a correlation handle rather than a stable
   * pseudo-identifier for an address (a 16-hex prefix still distinguishes
   * sources within a window, which is all a detector needs).
   */
  private sourceHandle(raw: string): string {
    return createHmac('sha256', this.config.ANOMALY_SOURCE_PEPPER).update(raw).digest('hex').slice(0, 16);
  }

  // --- audit-stream detectors --------------------------------------------

  /**
   * Called by AuditService after every successful append. MUST NOT throw: an
   * observer error would otherwise be able to influence an authentication that
   * has already been recorded as complete.
   */
  private async onAuditEvent(event: AuditEventInput): Promise<void> {
    if (!this.config.ANOMALY_ENABLED) return;
    try {
      switch (event.action) {
        case 'ciba.request_created':
          // T9: an RP hammering backchannel initiation — either compromised or
          // being used to spray approval prompts at citizens.
          if (event.rpId) {
            await this.count(
              'ciba_initiation_flood',
              `rp:${event.rpId}`,
              this.config.ANOMALY_CIBA_INITIATION_THRESHOLD,
              this.config.ANOMALY_CIBA_INITIATION_WINDOW_SECONDS,
              { rpId: event.rpId },
            );
          }
          break;
        case 'ciba.request_denied':
          // T7 (consent fatigue / relay): a spike of denials the CITIZEN
          // flagged as suspicious is the strongest signal we have that someone
          // is pushing approval prompts at people. Citizens telling us
          // directly is high-signal, so the threshold is intentionally low.
          if (event.rpId && event.context?.['reportedSuspicious'] === true) {
            await this.count(
              'suspicious_denial_spike',
              `rp:${event.rpId}`,
              this.config.ANOMALY_SUSPICIOUS_DENIAL_THRESHOLD,
              this.config.ANOMALY_SUSPICIOUS_DENIAL_WINDOW_SECONDS,
              { rpId: event.rpId },
            );
          }
          break;
        case 'auth.login_failed':
          // T1/T4: repeated signature failures against ONE binding — a stolen
          // device being attacked, or a replay attempt. The lockout is the
          // control; this is the visibility.
          if (event.deviceBindingId && event.context?.['reason'] === 'signature_invalid') {
            await this.count(
              'signature_failure_burst',
              `binding:${event.deviceBindingId}`,
              this.config.ANOMALY_SIGNATURE_FAILURE_THRESHOLD,
              this.config.ANOMALY_SIGNATURE_FAILURE_WINDOW_SECONDS,
              { deviceBindingId: event.deviceBindingId },
            );
          }
          break;
        default:
          break;
      }
    } catch (err) {
      // Redis unavailable, or an audit append failed. Detection is a
      // best-effort overlay: never let it disturb the flow that produced it.
      this.logger.warn(
        `anomaly evaluation failed for ${event.action}: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
  }

  // --- request-path detectors (source-IP keyed) --------------------------

  /**
   * T14 — enrolment probing: one source trying many DISTINCT identities.
   * Counting distinct pseudo-NIDs (not attempts) is what separates probing
   * from a single citizen retrying, which the per-NID rate limit already
   * covers. The pseudo-NIDs live in a short-TTL Redis set and never leave it.
   */
  async recordEnrolmentAttempt(sourceIp: string, pseudoNid: string): Promise<void> {
    if (!this.config.ANOMALY_ENABLED) return;
    const window = this.config.ANOMALY_ENROL_PROBE_WINDOW_SECONDS;
    const threshold = this.config.ANOMALY_ENROL_PROBE_DISTINCT_NIDS;
    const handle = this.sourceHandle(sourceIp);
    try {
      const key = `anom:enrol:src:${handle}`;
      await this.redis.client.sadd(key, pseudoNid);
      await this.redis.client.expire(key, window);
      const distinct = await this.redis.client.scard(key);
      if (distinct >= threshold) {
        await this.raise(
          { pattern: 'enrolment_probing', sourceHandle: handle, observed: distinct, threshold, windowSeconds: window },
          { sourceIp },
        );
      }
    } catch (err) {
      this.logger.warn(
        `enrolment-probing evaluation failed: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
  }

  /**
   * T2/T3 — repeated attestation rejections from one source. Counts rejections
   * only (not `verifier_unavailable`, which is our outage, not their attack).
   */
  async recordAttestationRejection(sourceIp: string, rejectionCode: string): Promise<void> {
    if (!this.config.ANOMALY_ENABLED) return;
    const handle = this.sourceHandle(sourceIp);
    try {
      await this.count(
        'attestation_rejection_burst',
        `src:${handle}`,
        this.config.ANOMALY_ATTESTATION_REJECTION_THRESHOLD,
        this.config.ANOMALY_ATTESTATION_REJECTION_WINDOW_SECONDS,
        { lastRejectionCode: rejectionCode },
        { sourceIp, sourceHandle: handle },
      );
    } catch (err) {
      this.logger.warn(
        `attestation-rejection evaluation failed: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
  }

  // --- machinery ----------------------------------------------------------

  /** Fixed-window counter; raises once the threshold is crossed. */
  private async count(
    pattern: AnomalyPattern,
    scopeKey: string,
    threshold: number,
    windowSeconds: number,
    auditContext: Record<string, unknown>,
    logFields: Record<string, unknown> = {},
  ): Promise<void> {
    const key = `anom:${pattern}:${scopeKey}`;
    const observed = await this.redis.client.incr(key);
    if (observed === 1) await this.redis.client.expire(key, windowSeconds);
    if (observed < threshold) return;
    const sourceHandle = scopeKey.startsWith('src:') ? scopeKey.slice(4) : scopeKey;
    await this.raise(
      { pattern, sourceHandle, observed, threshold, windowSeconds },
      logFields,
      auditContext,
    );
  }

  /**
   * Record a detection exactly once per window. Without the `SET NX`
   * suppression key a sustained attack would append one audit row per event
   * past the threshold — turning an alert into a flood, and an append-only
   * table into the attacker's write amplifier.
   */
  private async raise(
    detection: AnomalyDetection,
    logFields: Record<string, unknown> = {},
    auditContext: Record<string, unknown> = {},
  ): Promise<void> {
    const suppressionKey = `anom:alerted:${detection.pattern}:${detection.sourceHandle}`;
    const first = await this.redis.client.set(
      suppressionKey,
      '1',
      'EX',
      detection.windowSeconds,
      'NX',
    );
    if (first !== 'OK') return;

    this.metrics.recordAnomaly(detection.pattern);
    // Operational log carries the raw source (short retention, operator-only);
    // the audit row below never does.
    this.logger.warn(
      `anomaly detected: pattern=${detection.pattern} observed=${detection.observed} ` +
        `threshold=${detection.threshold} window=${detection.windowSeconds}s ` +
        `source=${JSON.stringify(logFields)}`,
    );
    await this.audit.append({
      actor: { type: 'system' },
      action: ANOMALY_AUDIT_ACTION,
      ...(typeof auditContext['rpId'] === 'string' ? { rpId: auditContext['rpId'] } : {}),
      ...(typeof auditContext['deviceBindingId'] === 'string'
        ? { deviceBindingId: auditContext['deviceBindingId'] }
        : {}),
      result: 'failure',
      context: {
        op: ANOMALY_AUDIT_OP,
        pattern: detection.pattern,
        observed: detection.observed,
        threshold: detection.threshold,
        windowSeconds: detection.windowSeconds,
        // A correlation handle, not an address: peppered and truncated.
        sourceHandle: detection.sourceHandle,
        // Stated in the row itself so an auditor reading this years from now
        // knows the broker took no action on the citizen or the RP.
        action: 'none — detection only, human review required',
        ...auditContext,
      },
    });
  }
}
