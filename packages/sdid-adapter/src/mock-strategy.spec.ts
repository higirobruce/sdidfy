import { afterEach, describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS, mockBiometricBytes } from '@sdid/shared';
import { MockSdidStrategy } from './mock-strategy.js';
import { SdidUnavailableError, SdidUnknownIdentityError } from './errors.js';
import { sdidSubjectForNid } from './pseudonym.js';

const KNOWN = MOCK_TEST_NIDS[0];
const UNKNOWN = '1190000000000000';

afterEach(() => {
  delete process.env.SDID_MOCK_LATENCY_MS;
  delete process.env.SDID_MOCK_FAILURE_RATE;
});

describe('MockSdidStrategy', () => {
  it('returns the canonical mock reference bytes for a known NID', async () => {
    const strategy = new MockSdidStrategy();
    const res = await strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' });
    expect(Buffer.from(res.reference.data)).toEqual(
      Buffer.from(mockBiometricBytes(KNOWN, 'face')),
    );
    expect(res.reference.format).toBe('mock');
    expect(res.sdidSubject).toBe(sdidSubjectForNid(KNOWN));
    expect(res.sdidSubject).toMatch(/^sdid-[0-9a-f]{16}$/);
    expect(res.txnRef).toMatch(/^mock-[0-9a-f]{12}$/);
  });

  it('knows exactly the seeded test NIDs', async () => {
    const strategy = new MockSdidStrategy();
    for (const nid of MOCK_TEST_NIDS) {
      await expect(
        strategy.getReferenceBiometric({ nid, modality: 'fingerprint' }),
      ).resolves.toBeDefined();
    }
    await expect(
      strategy.getReferenceBiometric({ nid: UNKNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('unknown-identity error message never contains the NID', async () => {
    const strategy = new MockSdidStrategy();
    const err = await strategy.getAttributes(UNKNOWN, ['profile']).catch((e: Error) => e);
    expect(err).toBeInstanceOf(SdidUnknownIdentityError);
    expect((err as Error).message).not.toContain(UNKNOWN);
  });

  it('returns a plausible Kigali-district address under the address scope', async () => {
    const strategy = new MockSdidStrategy();
    const attrs = await strategy.getAttributes(KNOWN, ['address']);
    expect(attrs.address).toMatch(/(Gasabo|Kicukiro|Nyarugenge), Kigali, Rwanda$/);
    expect(attrs.faceReferenceAvailable).toBe(true);
  });

  it('failNextCalls injects N failures then recovers', async () => {
    const strategy = new MockSdidStrategy({ failNextCalls: 2 });
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await expect(strategy.reassert(KNOWN)).resolves.toEqual(
      expect.objectContaining({ valid: true, assurance: 'AL2' }),
    );
  });

  it('failureRate 1 always fails', async () => {
    const strategy = new MockSdidStrategy({ failureRate: 1 });
    await expect(
      strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('env SDID_MOCK_FAILURE_RATE overrides constructor options', async () => {
    process.env.SDID_MOCK_FAILURE_RATE = '1';
    const strategy = new MockSdidStrategy({ failureRate: 0 });
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('env SDID_MOCK_LATENCY_MS overrides constructor options', async () => {
    process.env.SDID_MOCK_LATENCY_MS = '40';
    const strategy = new MockSdidStrategy({ latencyMs: 0 });
    const started = Date.now();
    await strategy.reassert(KNOWN);
    expect(Date.now() - started).toBeGreaterThanOrEqual(35);
  });

  it('reassert accepts the sdidSubject and reports unknown ids invalid (no throw)', async () => {
    const strategy = new MockSdidStrategy();
    const bySubject = await strategy.reassert(sdidSubjectForNid(KNOWN));
    expect(bySubject).toEqual(expect.objectContaining({ valid: true, assurance: 'AL2' }));
    const unknown = await strategy.reassert(UNKNOWN);
    expect(unknown).toEqual(expect.objectContaining({ valid: false, assurance: 'AL1' }));
  });
});
