import { describe, expect, it } from 'vitest';
import { MobileError } from './errors.js';
import {
  assertPinnedTransport,
  backoffDelay,
  FetchTransport,
  isRetryableStatus,
  sendWithRetry,
  TransportFailure,
  transportFailureToError,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
  type RetryPolicy,
} from './transport.js';

const REQUEST: HttpRequest = {
  method: 'GET',
  url: 'http://broker.test/v1/device/bindings',
  headers: {},
  timeoutMs: 1000,
};

/** No real waiting, deterministic jitter. */
const POLICY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 100,
  maxDelayMs: 1000,
  random: () => 0.5,
  sleep: async () => undefined,
};

class ScriptedTransport implements HttpTransport {
  readonly pinned = true;
  calls = 0;

  constructor(private readonly script: (call: number) => HttpResponse) {}

  async send(): Promise<HttpResponse> {
    this.calls += 1;
    return this.script(this.calls);
  }
}

class FailingTransport implements HttpTransport {
  readonly pinned = true;
  calls = 0;

  constructor(private readonly kind: 'timeout' | 'unreachable' = 'unreachable') {}

  async send(): Promise<HttpResponse> {
    this.calls += 1;
    throw new TransportFailure(this.kind, 'no route');
  }
}

describe('sendWithRetry — safe calls', () => {
  it('retries a transport failure up to maxAttempts, then surfaces it', async () => {
    const transport = new FailingTransport();
    await expect(
      sendWithRetry({ transport, request: REQUEST, idempotency: 'safe', policy: POLICY }),
    ).rejects.toMatchObject({ code: 'server_unreachable' });
    expect(transport.calls).toBe(3);
  });

  it('returns the first success and stops retrying', async () => {
    const transport = new ScriptedTransport((call) =>
      call < 2 ? { status: 503, body: '' } : { status: 200, body: '{"ok":true}' },
    );
    const res = await sendWithRetry({
      transport,
      request: REQUEST,
      idempotency: 'safe',
      policy: POLICY,
    });
    expect(res.status).toBe(200);
    expect(transport.calls).toBe(2);
  });

  it('does NOT retry a 429 — retrying into a rate limit causes the lockout', async () => {
    const transport = new ScriptedTransport(() => ({ status: 429, body: '' }));
    const res = await sendWithRetry({
      transport,
      request: REQUEST,
      idempotency: 'safe',
      policy: POLICY,
    });
    expect(res.status).toBe(429);
    expect(transport.calls).toBe(1);
  });

  it('does not retry a 4xx verdict', async () => {
    const transport = new ScriptedTransport(() => ({ status: 403, body: '' }));
    await sendWithRetry({ transport, request: REQUEST, idempotency: 'safe', policy: POLICY });
    expect(transport.calls).toBe(1);
  });
});

describe('sendWithRetry — nonce-consuming calls (T4)', () => {
  it('never retries, and reports `interrupted` so the citizen restarts the flow', async () => {
    const transport = new FailingTransport('timeout');
    const error = await sendWithRetry({
      transport,
      request: { ...REQUEST, method: 'POST' },
      idempotency: 'consumes-nonce',
      policy: POLICY,
    }).catch((e: unknown) => e as MobileError);

    expect(transport.calls).toBe(1);
    expect(error).toBeInstanceOf(MobileError);
    expect((error as MobileError).code).toBe('interrupted');
    // "start again" is retryable in the UI sense — but as a fresh flow, not a
    // replay of the spent challenge.
    expect((error as MobileError).userRetryable).toBe(true);
  });

  it('does not retry a 503 either — the nonce may already be burned', async () => {
    const transport = new ScriptedTransport(() => ({ status: 503, body: '' }));
    const res = await sendWithRetry({
      transport,
      request: { ...REQUEST, method: 'POST' },
      idempotency: 'consumes-nonce',
      policy: POLICY,
    });
    expect(res.status).toBe(503);
    expect(transport.calls).toBe(1);
  });
});

describe('backoff', () => {
  it('grows exponentially and is capped', () => {
    const policy: RetryPolicy = { ...POLICY, random: () => 1 };
    expect(backoffDelay(1, policy)).toBe(100);
    expect(backoffDelay(2, policy)).toBe(200);
    expect(backoffDelay(3, policy)).toBe(400);
    expect(backoffDelay(20, policy)).toBe(1000);
  });

  it('applies full jitter — the delay is in [0, ceiling)', () => {
    const policy: RetryPolicy = { ...POLICY, random: () => 0 };
    expect(backoffDelay(3, policy)).toBe(0);
  });

  it('treats only gateway-ish statuses as retryable', () => {
    expect([502, 503, 504].every(isRetryableStatus)).toBe(true);
    expect([200, 400, 401, 403, 429, 500].some(isRetryableStatus)).toBe(false);
  });
});

describe('transport failure mapping', () => {
  it('maps each kind to its own citizen-facing message', () => {
    expect(transportFailureToError(new TransportFailure('timeout')).messageKey).toBe(
      'errors.network_timeout',
    );
    expect(transportFailureToError(new TransportFailure('offline')).messageKey).toBe(
      'errors.network_unreachable',
    );
    expect(transportFailureToError(new TransportFailure('unreachable')).messageKey).toBe(
      'errors.server_unreachable',
    );
  });
});

describe('certificate pinning gate (T5)', () => {
  it('refuses to run an unpinned transport in a release build', () => {
    const unpinned = new FetchTransport();
    expect(unpinned.pinned).toBe(false);
    expect(() => assertPinnedTransport(unpinned, true)).toThrow(MobileError);
    expect(() => assertPinnedTransport(unpinned, false)).not.toThrow();
  });
});

describe('FetchTransport', () => {
  it('turns a fetch rejection into a TransportFailure, never a raw error', async () => {
    const transport = new FetchTransport(async () => {
      throw new TypeError('Network request failed');
    });
    await expect(transport.send(REQUEST)).rejects.toBeInstanceOf(TransportFailure);
  });

  it('returns non-2xx responses instead of throwing', async () => {
    const transport = new FetchTransport(
      async () => new Response('{"error":"rate_limited"}', { status: 429 }),
    );
    const res = await transport.send(REQUEST);
    expect(res).toEqual({ status: 429, body: '{"error":"rate_limited"}' });
  });
});
