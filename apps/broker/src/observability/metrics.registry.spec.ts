import { describe, expect, it } from 'vitest';
import {
  MAX_SERIES_PER_METRIC,
  MetricsRegistry,
  REJECTED_LABEL_VALUE,
  UnsafeLabelValueError,
  unsafeLabelReason,
} from './metrics.registry.js';
import { signingKeyLabel } from './metrics.service.js';

/**
 * The registry is hand-rolled, so its exposition format is our responsibility:
 * a malformed family is silently dropped by Prometheus, which looks exactly
 * like "the broker is not recording anything". These tests pin the format.
 *
 * The label-safety tests are a PRIVACY control, not a formatting nicety —
 * see the header of metrics.registry.ts.
 */
describe('metrics registry — exposition format', () => {
  it('renders a counter with HELP, TYPE and label pairs', () => {
    const r = new MetricsRegistry(true);
    const c = r.counter('sdid_broker_test_total', 'A test counter.', ['outcome']);
    c.inc({ outcome: 'success' });
    c.inc({ outcome: 'success' });
    c.inc({ outcome: 'failure' }, 3);

    const text = r.render();
    expect(text).toContain('# HELP sdid_broker_test_total A test counter.');
    expect(text).toContain('# TYPE sdid_broker_test_total counter');
    expect(text).toContain('sdid_broker_test_total{outcome="success"} 2');
    expect(text).toContain('sdid_broker_test_total{outcome="failure"} 3');
    expect(text.endsWith('\n')).toBe(true);
  });

  it('renders an unlabelled counter with no brace block', () => {
    const r = new MetricsRegistry(true);
    r.counter('sdid_broker_plain_total', 'No labels.').inc();
    expect(r.render()).toContain('\nsdid_broker_plain_total 1');
  });

  it('renders a gauge that can go up and down', () => {
    const r = new MetricsRegistry(true);
    const g = r.gauge('sdid_broker_gauge', 'A gauge.', ['component']);
    g.set(1, { component: 'redis' });
    g.set(0, { component: 'redis' });
    expect(r.render()).toContain('sdid_broker_gauge{component="redis"} 0');
  });

  it('renders histogram buckets cumulatively, ending at +Inf == _count', () => {
    const r = new MetricsRegistry(true);
    const h = r.histogram('sdid_broker_dur_seconds', 'Durations.', ['op'], [0.1, 1]);
    h.observe(0.05, { op: 'reassert' });
    h.observe(0.5, { op: 'reassert' });
    h.observe(5, { op: 'reassert' });

    const text = r.render();
    expect(text).toContain('# TYPE sdid_broker_dur_seconds histogram');
    expect(text).toContain('sdid_broker_dur_seconds_bucket{op="reassert",le="0.1"} 1');
    // Cumulative: 0.05 and 0.5 are both <= 1.
    expect(text).toContain('sdid_broker_dur_seconds_bucket{op="reassert",le="1"} 2');
    expect(text).toContain('sdid_broker_dur_seconds_bucket{op="reassert",le="+Inf"} 3');
    expect(text).toContain('sdid_broker_dur_seconds_count{op="reassert"} 3');
    expect(text).toContain('sdid_broker_dur_seconds_sum{op="reassert"} 5.55');
  });

  it('escapes backslashes, quotes and newlines in label values', () => {
    // Not reachable through the safe-label check, but the escaper is what
    // stands between a malformed value and an unparseable scrape.
    const r = new MetricsRegistry(false);
    const c = r.counter('sdid_broker_esc_total', 'Escaping.', ['v']);
    c.inc({ v: 'a"b\\c\nd' });
    expect(r.render()).toContain('sdid_broker_esc_total{v="__rejected__"} 1');
  });

  it('rejects a metric name registered twice', () => {
    const r = new MetricsRegistry(true);
    r.counter('sdid_broker_dup_total', 'One.');
    expect(() => r.counter('sdid_broker_dup_total', 'Two.')).toThrow(/already registered/);
  });
});

describe('metrics registry — identifying label values are refused (privacy)', () => {
  it.each([
    ['a raw 16-digit NID', '1199880012345678'],
    ['a NID embedded in a longer value', 'nid-1199880012345678'],
    ['a citizen/binding uuid', '01a03c53-d40f-7caf-8a81-e0893a6d3906'],
    ['a pseudo-NID / hash', 'a3f1c0de9b8877665544332211aabbccddeeff0011223344'],
    ['an opaque base64url nonce', 'kZ9x2QpL7vRt4wYn8mBc3d'],
  ])('flags %s', (_label, value) => {
    expect(unsafeLabelReason(value)).not.toBeNull();
  });

  it.each([
    ['an enum outcome', 'sdid_identity_not_matchable'],
    ['a score band', 'no-match'],
    ['an assurance level', 'AL2'],
    ['a grant type urn', 'urn:openid:params:grant-type:ciba'],
    ['a handler name', 'EnrolmentController.start'],
    ['a rate-limit scope', 'enrol:attest:ip'],
    ['an adapter method name', 'getReferenceBiometric'],
    ['an adapter error class', 'SdidMalformedResponseError'],
    ['an empty label', ''],
  ])('allows %s', (_label, value) => {
    expect(unsafeLabelReason(value)).toBeNull();
  });

  it('throws in strict mode so the bug fails in CI, not in production', () => {
    const r = new MetricsRegistry(true);
    const c = r.counter('sdid_broker_strict_total', 'Strict.', ['subject']);
    expect(() => c.inc({ subject: '1199880012345678' })).toThrow(UnsafeLabelValueError);
  });

  it('substitutes rather than throws in non-strict mode (metrics never break auth)', () => {
    const r = new MetricsRegistry(false);
    const c = r.counter('sdid_broker_lenient_total', 'Lenient.', ['subject']);
    expect(() => c.inc({ subject: '1199880012345678' })).not.toThrow();
    const text = r.render();
    expect(text).toContain(`sdid_broker_lenient_total{subject="${REJECTED_LABEL_VALUE}"} 1`);
    expect(text).not.toContain('1199880012345678');
  });

  it('stops creating series at the cardinality ceiling instead of growing unbounded', () => {
    const r = new MetricsRegistry(false);
    const c = r.counter('sdid_broker_card_total', 'Cardinality.', ['k']);
    for (let i = 0; i < MAX_SERIES_PER_METRIC + 25; i += 1) c.inc({ k: `v-${i}` });
    const seriesLines = r
      .render()
      .split('\n')
      .filter((l) => l.startsWith('sdid_broker_card_total{'));
    expect(seriesLines).toHaveLength(MAX_SERIES_PER_METRIC);
    expect(r.droppedSeries()).toBe(25);
  });
});

/**
 * `signingKeyLabel` exists because a kid is public but SHAPED like an
 * identifier (06 §3, T13) — see its doc comment. These tests pin the property
 * that matters: whatever a KMS calls its keys, the label survives the
 * registry's identity-shape rules in STRICT mode, which is where a mislabelled
 * series must fail.
 */
describe('signing-key metric labels (T13)', () => {
  const kids = [
    'a1b2c3d4e5f60718', // the dev store's 16 hex chars
    '550e8400-e29b-41d4-a716-446655440000', // a uuid, as many KMS use
    'projects/gor/locations/rw/keyRings/broker/cryptoKeys/sign/cryptoKeyVersions/7',
    'arn:aws:kms:rw-central-1:123456789012:key/550e8400-e29b-41d4-a716-446655440000',
    'pkcs11:token=broker;object=sdid-broker-signing-2026',
    '',
  ];

  it('produces a label value every kid shape can carry, in strict mode', () => {
    const r = new MetricsRegistry(true);
    const c = r.counter('sdid_broker_signing_label_total', 'Label test.', ['kid', 'alg']);
    for (const kid of kids) {
      expect(() => c.inc({ kid: signingKeyLabel(kid), alg: 'ES256' })).not.toThrow();
      expect(unsafeLabelReason(signingKeyLabel(kid))).toBeNull();
    }
  });

  it('keeps the distinguishing tail, so two keys never collapse into one series', () => {
    const a = signingKeyLabel('projects/gor/keyRings/broker/cryptoKeyVersions/7');
    const b = signingKeyLabel('projects/gor/keyRings/broker/cryptoKeyVersions/8');
    expect(a).not.toBe(b);
    expect(signingKeyLabel('a1b2c3d4e5f60718')).toBe('a1b2c3d4e5f6');
    expect(signingKeyLabel('')).toBe('unknown');
  });
});
