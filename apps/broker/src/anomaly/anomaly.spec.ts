import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { uuidv7 } from '@sdid/shared';
import { AuditService } from '../audit/audit.service.js';
import { resetConfigForTest } from '../config.js';
import { MetricsService } from '../observability/metrics.service.js';
import { cleanTestData, createTestApp, type TestContext } from '../modules/enrolment/testkit.js';
import { AnomalyService, ANOMALY_AUDIT_OP } from './anomaly.service.js';

/**
 * Thresholds are driven down to small numbers via env so the suite exercises
 * the crossing behaviour rather than the production defaults (which are, by
 * design, hundreds of events). The DEFAULTS themselves are documented in
 * config.ts and docs/runbook.md; what matters here is that a threshold fires
 * exactly once per window and that nothing identifying reaches the audit row.
 */
const ENV_OVERRIDES: Record<string, string> = {
  ANOMALY_ENABLED: 'true',
  ANOMALY_SOURCE_PEPPER: 'test-anomaly-pepper',
  ANOMALY_ENROL_PROBE_DISTINCT_NIDS: '3',
  ANOMALY_ENROL_PROBE_WINDOW_SECONDS: '60',
  ANOMALY_ATTESTATION_REJECTION_THRESHOLD: '3',
  ANOMALY_ATTESTATION_REJECTION_WINDOW_SECONDS: '60',
  ANOMALY_CIBA_INITIATION_THRESHOLD: '3',
  ANOMALY_CIBA_INITIATION_WINDOW_SECONDS: '60',
  ANOMALY_SIGNATURE_FAILURE_THRESHOLD: '3',
  ANOMALY_SIGNATURE_FAILURE_WINDOW_SECONDS: '60',
  ANOMALY_SUSPICIOUS_DENIAL_THRESHOLD: '2',
  ANOMALY_SUSPICIOUS_DENIAL_WINDOW_SECONDS: '60',
};

/** Read one counter series out of the rendered exposition text. */
function counterValue(text: string, name: string, labels: string): number {
  const line = text.split('\n').find((l) => l.startsWith(`${name}{${labels}}`));
  return line ? Number(line.slice(line.lastIndexOf(' ') + 1)) : 0;
}

describe('anomaly detection over the audit stream (06 §5) — DETECTION ONLY', () => {
  let ctx: TestContext;
  let anomaly: AnomalyService;
  let audit: AuditService;
  let metrics: MetricsService;
  const saved: Record<string, string | undefined> = {};

  beforeAll(async () => {
    for (const [k, v] of Object.entries(ENV_OVERRIDES)) {
      saved[k] = process.env[k];
      process.env[k] = v;
    }
    resetConfigForTest();
    ctx = await createTestApp();
    await cleanTestData(ctx);
    anomaly = ctx.app.get(AnomalyService);
    audit = ctx.app.get(AuditService);
    metrics = ctx.app.get(MetricsService);
  });

  afterAll(async () => {
    await ctx.app.close();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    resetConfigForTest();
  });

  beforeEach(async () => {
    // Detector windows live in Redis; clear them so each case starts cold.
    const client = ctx.redis.client;
    let cursor = '0';
    do {
      const [next, keys] = await client.scan(cursor, 'MATCH', 'anom:*', 'COUNT', 500);
      cursor = next;
      if (keys.length > 0) await client.del(...keys);
    } while (cursor !== '0');
  });

  function anomalyCount(text: string, pattern: string): number {
    return counterValue(text, 'sdid_broker_anomaly_detections_total', `pattern="${pattern}"`);
  }

  it('enrolment probing: fires on DISTINCT identities from one source, not on retries', async () => {
    const before = anomalyCount(metrics.render(), 'enrolment_probing');
    const ip = '203.0.113.10';

    // One identity retried many times is NOT probing — that is the per-NID
    // rate limit's job, and flagging it would alarm on a struggling citizen.
    for (let i = 0; i < 6; i += 1) await anomaly.recordEnrolmentAttempt(ip, 'pseudo-aaa');
    expect(anomalyCount(metrics.render(), 'enrolment_probing')).toBe(before);

    // Three DISTINCT identities from the same source crosses the threshold.
    await anomaly.recordEnrolmentAttempt(ip, 'pseudo-bbb');
    await anomaly.recordEnrolmentAttempt(ip, 'pseudo-ccc');
    expect(anomalyCount(metrics.render(), 'enrolment_probing')).toBe(before + 1);
  });

  it('enrolment probing: fires ONCE per window, however long the attack runs', async () => {
    const ip = '203.0.113.11';
    const before = anomalyCount(metrics.render(), 'enrolment_probing');
    for (let i = 0; i < 25; i += 1) await anomaly.recordEnrolmentAttempt(ip, `pseudo-${i}`);
    // Without suppression this would append 23 audit rows and 23 metric hits.
    expect(anomalyCount(metrics.render(), 'enrolment_probing')).toBe(before + 1);
  });

  it('enrolment probing: separate sources are counted separately', async () => {
    const before = anomalyCount(metrics.render(), 'enrolment_probing');
    for (const ip of ['203.0.113.20', '203.0.113.21']) {
      for (const n of ['x', 'y', 'z']) await anomaly.recordEnrolmentAttempt(ip, `pseudo-${n}`);
    }
    expect(anomalyCount(metrics.render(), 'enrolment_probing')).toBe(before + 2);
  });

  it('attestation rejections: bursts from one source cross the threshold (T2/T3)', async () => {
    const before = anomalyCount(metrics.render(), 'attestation_rejection_burst');
    const ip = '203.0.113.30';
    await anomaly.recordAttestationRejection(ip, 'device_integrity_failed');
    await anomaly.recordAttestationRejection(ip, 'device_integrity_failed');
    expect(anomalyCount(metrics.render(), 'attestation_rejection_burst')).toBe(before);
    await anomaly.recordAttestationRejection(ip, 'app_mismatch');
    expect(anomalyCount(metrics.render(), 'attestation_rejection_burst')).toBe(before + 1);
  });

  it('CIBA initiation flood: driven by the audit stream, per RP (T9)', async () => {
    const before = anomalyCount(metrics.render(), 'ciba_initiation_flood');
    const rpId = uuidv7();
    const citizenId = uuidv7();
    for (let i = 0; i < 3; i += 1) {
      await audit.append({
        actor: { type: 'rp', id: rpId },
        action: 'ciba.request_created',
        subjectRef: citizenId,
        rpId,
        result: 'success',
        context: { flow: 'ciba' },
      });
    }
    // Observers are notified synchronously post-commit, but their own work is
    // async — give the microtask queue a turn.
    await new Promise((r) => setTimeout(r, 50));
    expect(anomalyCount(metrics.render(), 'ciba_initiation_flood')).toBe(before + 1);
  });

  it('signature-failure burst: per binding, only for signature_invalid (T1/T4)', async () => {
    const before = anomalyCount(metrics.render(), 'signature_failure_burst');
    const bindingId = uuidv7();
    const citizenId = uuidv7();
    // A challenge_invalid failure is a different problem and must not count.
    await audit.append({
      actor: { type: 'citizen', id: citizenId },
      action: 'auth.login_failed',
      subjectRef: citizenId,
      deviceBindingId: bindingId,
      result: 'failure',
      context: { reason: 'challenge_invalid' },
    });
    for (let i = 0; i < 3; i += 1) {
      await audit.append({
        actor: { type: 'citizen', id: citizenId },
        action: 'auth.login_failed',
        subjectRef: citizenId,
        deviceBindingId: bindingId,
        result: 'failure',
        context: { reason: 'signature_invalid' },
      });
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(anomalyCount(metrics.render(), 'signature_failure_burst')).toBe(before + 1);
  });

  it('suspicious-denial spike: only citizen-flagged denials count (T7)', async () => {
    const before = anomalyCount(metrics.render(), 'suspicious_denial_spike');
    const rpId = uuidv7();
    const citizenId = uuidv7();
    // Ordinary denials are a normal, healthy outcome — never an anomaly.
    for (let i = 0; i < 5; i += 1) {
      await audit.append({
        actor: { type: 'citizen', id: citizenId },
        action: 'ciba.request_denied',
        subjectRef: citizenId,
        rpId,
        result: 'denied',
        context: { flow: 'ciba' },
      });
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(anomalyCount(metrics.render(), 'suspicious_denial_spike')).toBe(before);

    for (let i = 0; i < 2; i += 1) {
      await audit.append({
        actor: { type: 'citizen', id: citizenId },
        action: 'ciba.request_denied',
        subjectRef: citizenId,
        rpId,
        result: 'denied',
        context: { flow: 'ciba', reportedSuspicious: true },
      });
    }
    await new Promise((r) => setTimeout(r, 50));
    expect(anomalyCount(metrics.render(), 'suspicious_denial_spike')).toBe(before + 1);
  });

  it('writes an audit row that records the detection and that NO action was taken', async () => {
    const ip = '198.51.100.7';
    for (const n of ['p', 'q', 'r']) await anomaly.recordEnrolmentAttempt(ip, `pseudo-${n}`);
    await new Promise((r) => setTimeout(r, 50));

    const { rows } = await ctx.db.pool.query(
      `SELECT actor, action, result, context FROM audit_events
        WHERE context->>'op' = $1 AND context->>'pattern' = 'enrolment_probing'
        ORDER BY seq DESC LIMIT 1`,
      [ANOMALY_AUDIT_OP],
    );
    expect(rows).toHaveLength(1);
    const row = rows[0] as { actor: { type: string }; result: string; context: Record<string, unknown> };
    expect(row.actor.type).toBe('system');
    expect(row.result).toBe('failure');
    expect(row.context['threshold']).toBe(3);
    expect(String(row.context['action'])).toContain('detection only');
    // The source is a peppered, truncated handle — never the address itself.
    expect(JSON.stringify(row.context)).not.toContain(ip);
    expect(String(row.context['sourceHandle'])).toMatch(/^[0-9a-f]{16}$/);
  });

  it('never revokes, suspends or locks anything on detection (the cardinal rule)', async () => {
    const ip = '198.51.100.8';
    for (const n of ['s', 't', 'u', 'v']) await anomaly.recordEnrolmentAttempt(ip, `pseudo-${n}`);
    await new Promise((r) => setTimeout(r, 50));
    // Detection writes only its own audit row; a lockout would have created a
    // `lockout:` key and a revocation would have touched a binding.
    const lockoutKeys = await ctx.redis.client.keys('lockout:*');
    expect(lockoutKeys.filter((k) => k.includes('198.51.100.8'))).toHaveLength(0);
    const { rows } = await ctx.db.pool.query(
      "SELECT count(*)::int AS n FROM device_bindings WHERE revoke_reason LIKE 'anomaly%'",
    );
    expect((rows[0] as { n: number }).n).toBe(0);
  });

  it('does nothing at all when disabled', async () => {
    process.env['ANOMALY_ENABLED'] = 'false';
    resetConfigForTest();
    try {
      const before = anomalyCount(metrics.render(), 'enrolment_probing');
      const ip = '198.51.100.9';
      for (const n of ['a', 'b', 'c', 'd', 'e']) await anomaly.recordEnrolmentAttempt(ip, `pseudo-${n}`);
      expect(anomalyCount(metrics.render(), 'enrolment_probing')).toBe(before);
    } finally {
      process.env['ANOMALY_ENABLED'] = 'true';
      resetConfigForTest();
    }
  });
});
