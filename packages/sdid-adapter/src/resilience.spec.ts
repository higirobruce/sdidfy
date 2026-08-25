import { describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS, type SdidProvider } from '@sdid/shared';
import { MockSdidStrategy } from './mock-strategy.js';
import { ResilientSdidProvider } from './resilience.js';
import {
  SdidCircuitOpenError,
  SdidMalformedResponseError,
  SdidTimeoutError,
  SdidUnavailableError,
  SdidUnknownIdentityError,
} from './errors.js';

const KNOWN = MOCK_TEST_NIDS[0];
const FAST = { retryBaseDelayMs: 1 } as const;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Counts calls and delegates to a per-call behavior. */
function countingStrategy(behavior: () => Promise<unknown>): {
  provider: SdidProvider;
  calls: () => number;
} {
  let calls = 0;
  const call = <T>(): Promise<T> => {
    calls += 1;
    return behavior() as Promise<T>;
  };
  return {
    provider: {
      getReferenceBiometric: () => call(),
      getAttributes: () => call(),
      reassert: () => call(),
    },
    calls: () => calls,
  };
}

describe('ResilientSdidProvider', () => {
  it('retries transient failures and succeeds within the retry budget', async () => {
    const provider = new ResilientSdidProvider(
      new MockSdidStrategy({ failNextCalls: 2 }),
      { retries: 2, ...FAST },
    );
    const res = await provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' });
    expect(res.reference.data.byteLength).toBeGreaterThan(0);
    expect(provider.circuitState).toBe('closed');
  });

  it('surfaces SdidUnavailableError once retries are exhausted', async () => {
    const provider = new ResilientSdidProvider(
      new MockSdidStrategy({ failNextCalls: 3 }),
      { retries: 2, ...FAST },
    );
    await expect(
      provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('never retries SdidUnknownIdentityError and does not trip the breaker', async () => {
    const { provider: inner, calls } = countingStrategy(() =>
      Promise.reject(new SdidUnknownIdentityError()),
    );
    const provider = new ResilientSdidProvider(inner, { retries: 2, ...FAST });
    await expect(provider.getAttributes('nope', ['profile'])).rejects.toBeInstanceOf(
      SdidUnknownIdentityError,
    );
    expect(calls()).toBe(1);
    expect(provider.circuitState).toBe('closed');
  });

  it('applies the per-call timeout to each attempt', async () => {
    const { provider: inner } = countingStrategy(() => new Promise(() => undefined)); // hangs forever
    const provider = new ResilientSdidProvider(inner, { timeoutMs: 15, retries: 0 });
    const err = await provider.reassert(KNOWN).catch((e: Error) => e);
    expect(err).toBeInstanceOf(SdidTimeoutError);
    expect(err).toBeInstanceOf(SdidUnavailableError);
  });

  it('opens the breaker after 5 consecutive failures and short-circuits further calls', async () => {
    const { provider: inner, calls } = countingStrategy(() =>
      Promise.reject(new SdidUnavailableError('down')),
    );
    const provider = new ResilientSdidProvider(inner, {
      retries: 0,
      breakerFailureThreshold: 5,
      breakerResetMs: 60_000,
      ...FAST,
    });
    for (let i = 0; i < 5; i += 1) {
      await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    }
    expect(provider.circuitState).toBe('open');
    expect(calls()).toBe(5);
    // 6th call is rejected without touching the strategy.
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidCircuitOpenError);
    expect(calls()).toBe(5);
  });

  it('half-opens after the reset window; a successful probe closes the circuit', async () => {
    let healthy = false;
    const strategy = new MockSdidStrategy();
    const { provider: inner } = countingStrategy(() =>
      healthy ? strategy.reassert(KNOWN) : Promise.reject(new SdidUnavailableError('down')),
    );
    const provider = new ResilientSdidProvider(inner, {
      retries: 0,
      breakerFailureThreshold: 2,
      breakerResetMs: 20,
      ...FAST,
    });
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    expect(provider.circuitState).toBe('open');
    await sleep(30);
    expect(provider.circuitState).toBe('half-open');
    healthy = true;
    await expect(provider.reassert(KNOWN)).resolves.toEqual(
      expect.objectContaining({ valid: true }),
    );
    expect(provider.circuitState).toBe('closed');
  });

  it('a failed half-open probe re-opens the circuit', async () => {
    const { provider: inner } = countingStrategy(() =>
      Promise.reject(new SdidUnavailableError('still down')),
    );
    const provider = new ResilientSdidProvider(inner, {
      retries: 0,
      breakerFailureThreshold: 1,
      breakerResetMs: 20,
      ...FAST,
    });
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    expect(provider.circuitState).toBe('open');
    await sleep(30);
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    expect(provider.circuitState).toBe('open');
  });

  describe('zod boundary validation rejects malformed strategy output', () => {
    const bad = (overrides: Partial<Record<keyof SdidProvider, () => Promise<unknown>>>) => {
      const inner = {
        getReferenceBiometric: overrides.getReferenceBiometric ?? (() => Promise.reject()),
        getAttributes: overrides.getAttributes ?? (() => Promise.reject()),
        reassert: overrides.reassert ?? (() => Promise.reject()),
      } as unknown as SdidProvider;
      return new ResilientSdidProvider(inner, { retries: 0, ...FAST });
    };

    it('empty biometric reference bytes', async () => {
      const provider = bad({
        getReferenceBiometric: () =>
          Promise.resolve({
            reference: { modality: 'face', data: new Uint8Array(0), format: 'mock' },
            sdidSubject: 'sdid-0011223344556677',
            txnRef: 'mock-abcdefabcdef',
          }),
      });
      await expect(
        provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
      ).rejects.toBeInstanceOf(SdidMalformedResponseError);
    });

    it('empty sdidSubject / txnRef', async () => {
      const provider = bad({
        getReferenceBiometric: () =>
          Promise.resolve({
            reference: { modality: 'face', data: new Uint8Array([1]), format: 'mock' },
            sdidSubject: '',
            txnRef: '',
          }),
      });
      await expect(
        provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
      ).rejects.toBeInstanceOf(SdidMalformedResponseError);
    });

    it('non-Uint8Array reference data (e.g. base64 string) never propagates', async () => {
      const provider = bad({
        getReferenceBiometric: () =>
          Promise.resolve({
            reference: { modality: 'face', data: 'AAAA', format: 'mock' },
            sdidSubject: 'sdid-0011223344556677',
            txnRef: 'mock-abcdefabcdef',
          }),
      });
      await expect(
        provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
      ).rejects.toBeInstanceOf(SdidMalformedResponseError);
    });

    it('malformed reassert result', async () => {
      const provider = bad({
        reassert: () => Promise.resolve({ valid: 'yes', assurance: 'AL9', txnRef: '' }),
      });
      await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidMalformedResponseError);
    });

    it('validation errors never echo response values', async () => {
      const provider = bad({
        reassert: () =>
          Promise.resolve({ valid: true, assurance: 'SECRET-VALUE-123', txnRef: 'x' }),
      });
      const err = await provider.reassert(KNOWN).catch((e: Error) => e);
      expect(err).toBeInstanceOf(SdidMalformedResponseError);
      expect((err as Error).message).not.toContain('SECRET-VALUE-123');
    });
  });
});
