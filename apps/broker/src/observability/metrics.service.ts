import { Injectable } from '@nestjs/common';
import type { MatchScoreBand } from '@sdid/shared';
import { loadConfig } from '../config.js';
import { Counter, Gauge, Histogram, MetricsRegistry } from './metrics.registry.js';

/**
 * The broker's metric vocabulary (09 §2 Phase 3, 06 §5/§7).
 *
 * Every family declared here is operational: it answers "is the trust chain
 * working, and is someone attacking it?". Nothing here is a business analytic
 * about a citizen, and no family carries an identifying label — see the
 * cardinality/privacy note in `metrics.registry.ts`. The bounded label
 * vocabularies are spelled out next to each family so a future addition has to
 * argue with a comment before widening one.
 *
 * Naming follows Prometheus convention: `sdid_broker_<subsystem>_<unit>`,
 * counters end in `_total`, durations are seconds.
 */

/** Terminal outcomes of an enrolment attempt (03 §2, 03 §7). Bounded set. */
export type EnrolmentOutcome =
  | 'success'
  | 'attestation_rejected'
  | 'attestation_unavailable'
  | 'match_failed'
  | 'pad_failed'
  | 'identity_not_matchable'
  | 'device_limit_reached'
  | 'modality_unsupported'
  | 'sdid_unavailable'
  | 'error';

/** Where a device signature was being verified (never a binding id). */
export type SignatureContext = 'activation' | 'login' | 'ciba-decision' | 'unspecified';

/** The abuse patterns the anomaly detector watches for (06 §5). */
export type AnomalyPattern =
  | 'enrolment_probing'
  | 'attestation_rejection_burst'
  | 'ciba_initiation_flood'
  | 'signature_failure_burst'
  | 'suspicious_denial_spike';

/** Readiness components (see health/). Bounded by the checks we run. */
export type ReadinessComponent = 'postgres' | 'redis' | 'signing_key';

@Injectable()
export class MetricsService {
  readonly registry: MetricsRegistry;

  // --- enrolment + biometrics (03, 07 §4) ---------------------------------
  private readonly enrolmentAttempts: Counter;
  private readonly attestationVerdicts: Counter;
  private readonly biometricMatches: Counter;

  // --- protocol (04) ------------------------------------------------------
  private readonly cibaRequests: Counter;
  private readonly cibaDecisions: Counter;
  private readonly cibaExpiries: Counter;
  private readonly tokensIssued: Counter;

  // --- trust chain (06) ---------------------------------------------------
  private readonly signatureFailures: Counter;
  private readonly rateLimitHits: Counter;
  private readonly lockouts: Counter;
  private readonly anomalies: Counter;

  // --- dependencies (02 §4, 07 §4) ----------------------------------------
  private readonly sdidCallDuration: Histogram;
  private readonly sdidCircuitOpen: Gauge;
  private readonly sdidCircuitRejections: Counter;
  private readonly auditAppends: Counter;
  private readonly auditAppendFailures: Counter;
  private readonly pushDeliveries: Counter;

  // --- process/self -------------------------------------------------------
  private readonly httpRequests: Counter;
  private readonly httpDuration: Histogram;
  private readonly readiness: Gauge;
  private readonly droppedSeries: Gauge;
  private readonly buildInfo: Gauge;

  constructor() {
    // Strict label checking in TEST ONLY. An identifying label value must fail
    // loudly where it is free to fail — CI — and must degrade quietly
    // everywhere a citizen is waiting: neither production nor a development
    // broker may have an authentication broken by a metrics bug. The
    // non-strict path substitutes a placeholder and counts it instead.
    this.registry = new MetricsRegistry(loadConfig().NODE_ENV === 'test');
    const r = this.registry;

    this.enrolmentAttempts = r.counter(
      'sdid_broker_enrolment_attempts_total',
      'Enrolment attempts by terminal outcome (03 §2). No identity labels.',
      ['outcome'],
    );
    this.attestationVerdicts = r.counter(
      'sdid_broker_attestation_verdicts_total',
      'Device/app attestation verdicts by platform, mode and rejection code (05 §4, T2/T3/T4).',
      ['platform', 'mode', 'outcome', 'code'],
    );
    this.biometricMatches = r.counter(
      'sdid_broker_biometric_match_total',
      'Biometric 1:1 match outcomes by COARSE SCORE BAND and PAD result (07 §4). ' +
        'Bands only — a raw score is never emitted, and nothing here ties to an identity.',
      ['band', 'matched', 'pad'],
    );

    this.cibaRequests = r.counter(
      'sdid_broker_ciba_requests_total',
      'Backchannel authentication requests created, by flow (04 §3).',
      ['flow'],
    );
    this.cibaDecisions = r.counter(
      'sdid_broker_ciba_decisions_total',
      'Citizen decisions on pending requests: approve/deny, and whether the citizen ' +
        'flagged the prompt as suspicious (T7).',
      ['decision', 'flow', 'suspicious'],
    );
    this.cibaExpiries = r.counter(
      'sdid_broker_ciba_expiries_total',
      'Authentication requests that expired without a citizen decision (04 §3).',
      ['flow'],
    );
    this.tokensIssued = r.counter(
      'sdid_broker_tokens_issued_total',
      'Token responses minted, by OAuth grant type (04 §4).',
      ['grant_type'],
    );

    this.signatureFailures = r.counter(
      'sdid_broker_signature_verification_failures_total',
      'Device signature verifications that failed, by the flow verifying them (01 §2.2). ' +
        'Never labelled with the binding — see the anomaly detector for per-binding bursts.',
      ['context'],
    );
    this.rateLimitHits = r.counter(
      'sdid_broker_rate_limit_hits_total',
      'Requests refused by a fixed-window rate limit, by limit scope (06 §5).',
      ['scope'],
    );
    this.lockouts = r.counter(
      'sdid_broker_lockout_hits_total',
      'Requests refused because a failure lockout was already in force (03 §7, 06 §5).',
      ['scope'],
    );
    this.anomalies = r.counter(
      'sdid_broker_anomaly_detections_total',
      'Abuse patterns detected on the audit stream (06 §5). Detection only — the broker ' +
        'never auto-bans, so an alert here is a signal for a human, not an action taken.',
      ['pattern'],
    );

    this.sdidCallDuration = r.histogram(
      'sdid_broker_sdid_call_duration_seconds',
      'SDID adapter call latency by operation and outcome (02 §4).',
      ['operation', 'outcome'],
    );
    this.sdidCircuitOpen = r.gauge(
      'sdid_broker_sdid_circuit_open',
      'Last observed SDID circuit-breaker state: 1 when a call was rejected by an open ' +
        'circuit, 0 after the next success. Inferred broker-side from adapter errors — ' +
        'the adapter does not expose breaker state through the SdidProvider contract.',
    );
    this.sdidCircuitRejections = r.counter(
      'sdid_broker_sdid_circuit_rejections_total',
      'SDID calls rejected outright by the open circuit breaker (02 §4).',
    );
    this.auditAppends = r.counter(
      'sdid_broker_audit_appends_total',
      'Append-only audit rows written (07 §4).',
    );
    this.auditAppendFailures = r.counter(
      'sdid_broker_audit_append_failures_total',
      'Audit appends that FAILED. Audit is not best-effort: a failure here fails the ' +
        'operation it was recording, so any non-zero rate is a page-worthy condition (07 §4).',
    );
    this.pushDeliveries = r.counter(
      'sdid_broker_push_deliveries_total',
      'Wake-only push deliveries by platform and outcome (05 §5, T6).',
      ['platform', 'outcome'],
    );

    this.httpRequests = r.counter(
      'sdid_broker_http_requests_total',
      'HTTP requests by controller handler and status class. Handler names, never URLs — ' +
        'a URL can carry a login_hint (pairwise subject) or an authorization code.',
      ['handler', 'status'],
    );
    this.httpDuration = r.histogram(
      'sdid_broker_http_request_duration_seconds',
      'HTTP request duration by controller handler.',
      ['handler'],
    );
    this.readiness = r.gauge(
      'sdid_broker_readiness',
      'Last readiness-probe result per dependency: 1 healthy, 0 unhealthy (/readyz).',
      ['component'],
    );
    this.droppedSeries = r.gauge(
      'sdid_broker_metrics_dropped_series',
      'Label combinations dropped at the per-family cardinality ceiling. Non-zero means a ' +
        'metric is being labelled with something unbounded — fix the call site.',
    );
    this.buildInfo = r.gauge(
      'sdid_broker_build_info',
      'Build/runtime info as labels; the value is always 1.',
      ['node', 'env'],
    );
    this.buildInfo.set(1, {
      // process.version is 'v22.x.y' — the leading 'v' keeps it out of the
      // "looks like a version-less blob" rejection and stays a bounded value.
      node: process.version,
      env: loadConfig().NODE_ENV,
    });
  }

  // --- recording API ------------------------------------------------------
  // Thin, named methods rather than exposing raw metrics: the label vocabulary
  // stays in this file, where the privacy rules are, instead of spreading to
  // every call site.

  recordEnrolmentAttempt(outcome: EnrolmentOutcome): void {
    this.enrolmentAttempts.inc({ outcome });
  }

  /** `code` is the verifier's rejection code, or 'none' when accepted. */
  recordAttestationVerdict(input: {
    platform: string;
    mode: 'mock' | 'strict';
    outcome: 'accepted' | 'rejected' | 'unavailable';
    code?: string;
  }): void {
    this.attestationVerdicts.inc({
      platform: input.platform,
      mode: input.mode,
      outcome: input.outcome,
      code: input.code ?? 'none',
    });
  }

  /**
   * Score BAND only (07 §4). The raw score never leaves the match engine, and
   * even the band is recorded without any subject label — a per-citizen band
   * series would be a biometric-adjacent identifier in the monitoring estate.
   */
  recordBiometricMatch(result: { matched: boolean; scoreBand: MatchScoreBand; padPassed: boolean }): void {
    this.biometricMatches.inc({
      band: result.scoreBand,
      matched: String(result.matched),
      pad: result.padPassed ? 'pass' : 'fail',
    });
  }

  recordCibaRequest(flow: string): void {
    this.cibaRequests.inc({ flow });
  }

  recordCibaDecision(input: { decision: 'approve' | 'deny'; flow: string; suspicious: boolean }): void {
    this.cibaDecisions.inc({
      decision: input.decision,
      flow: input.flow,
      suspicious: String(input.suspicious),
    });
  }

  recordCibaExpiry(flow: string): void {
    this.cibaExpiries.inc({ flow });
  }

  recordTokensIssued(grantType: string): void {
    this.tokensIssued.inc({ grant_type: grantType });
  }

  recordSignatureFailure(context: SignatureContext): void {
    this.signatureFailures.inc({ context });
  }

  recordRateLimitHit(scope: string): void {
    this.rateLimitHits.inc({ scope });
  }

  recordLockoutHit(scope: string): void {
    this.lockouts.inc({ scope });
  }

  recordAnomaly(pattern: AnomalyPattern): void {
    this.anomalies.inc({ pattern });
  }

  recordSdidCall(input: { operation: string; outcome: string; durationMs: number }): void {
    this.sdidCallDuration.observe(input.durationMs / 1000, {
      operation: input.operation,
      outcome: input.outcome,
    });
  }

  /** Called with true when a call is rejected by the breaker, false on success. */
  recordSdidCircuitState(open: boolean): void {
    this.sdidCircuitOpen.set(open ? 1 : 0);
    if (open) this.sdidCircuitRejections.inc();
  }

  recordAuditAppend(ok: boolean): void {
    if (ok) this.auditAppends.inc();
    else this.auditAppendFailures.inc();
  }

  recordPushDelivery(platform: string, outcome: string): void {
    this.pushDeliveries.inc({ platform, outcome });
  }

  recordHttpRequest(input: { handler: string; statusCode: number; durationMs: number }): void {
    // Status CLASS, not the exact code: bounded, and enough to alert on.
    // 0 means the handler threw before a status was decided (see the logging
    // interceptor) — the exception filter maps it, we record it as `error`.
    const statusClass =
      input.statusCode > 0 ? `${Math.floor(input.statusCode / 100)}xx` : 'error';
    this.httpRequests.inc({ handler: input.handler, status: statusClass });
    this.httpDuration.observe(input.durationMs / 1000, { handler: input.handler });
  }

  recordReadiness(component: ReadinessComponent, healthy: boolean): void {
    this.readiness.set(healthy ? 1 : 0, { component });
  }

  /** Exposition text, with self-metrics refreshed first. */
  render(): string {
    this.droppedSeries.set(this.registry.droppedSeries());
    return this.registry.render();
  }
}

/**
 * Map a rate-limit/lockout Redis key to a BOUNDED scope label. The keys embed
 * identifiers (`enrol:nid:<pseudoNid>`, `login:<bindingId>`), which must never
 * become label values, so only the known prefixes are recognised and anything
 * else collapses to 'other'.
 */
export function rateLimitScope(key: string): string {
  const known = ['enrol:attest:ip', 'enrol:nid', 'enrol:ip', 'ciba:rp', 'login'];
  for (const prefix of known) {
    if (key === prefix || key.startsWith(`${prefix}:`)) return prefix;
  }
  return 'other';
}
