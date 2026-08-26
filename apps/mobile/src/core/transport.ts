/**
 * HTTP transport for the device backchannel (04 §3, 05 §5, T4/T5).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TLS / PINNING (T5) — NOT enforceable from this file
 * ─────────────────────────────────────────────────────────────────────────────
 * The threat model requires TLS 1.3 plus **certificate pinning in the app**.
 * JavaScript `fetch` in React Native has no pinning control: it goes through
 * NSURLSession / OkHttp, and the pin has to be installed there. So pinning is
 * a NATIVE requirement (see src/native/CONTRACT.md §4: an OkHttp
 * `CertificatePinner` and an `URLSessionDelegate` doing
 * `SecTrustEvaluateWithError` + SPKI comparison, with a backup pin and a
 * documented rotation path). `FetchTransport` below is correct-but-unpinned
 * and is what the vitest suite exercises; a build that ships it unpinned to a
 * citizen does not meet T5. `assertPinnedTransport()` exists so the app can
 * fail closed at start-up in a release build.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * RETRY POLICY — why most calls are NOT retried
 * ─────────────────────────────────────────────────────────────────────────────
 * The broker consumes single-use nonces and challenges with GETDEL, *before*
 * verifying anything (T4, runbook §7/§10). So for any call that consumes one —
 * `/enrol/start`, `/enrol/activate`, `/device/login`, `/device/ciba/decision` —
 * a transport error leaves us unable to tell whether the server processed it,
 * and a blind retry is guaranteed to fail with `challenge_invalid` while
 * looking to the citizen like a flaky app. Those calls are marked
 * `consumes-nonce`: zero retries, and a network failure surfaces as
 * `interrupted` ("start again"), which is honest.
 *
 * Only `safe` calls (nonce mint, challenge fetch, and the read-only list
 * views) are retried, with exponential backoff and full jitter, and only on a
 * transport failure or a 502/503/504. A 429 is never auto-retried — retrying
 * into a rate limit is how a lockout happens (runbook §7).
 */
import { MobileError } from './errors.js';

export interface HttpRequest {
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
}

export interface HttpResponse {
  status: number;
  body: string;
}

/** Reason a request never produced an HTTP response. */
export type TransportFailureKind = 'offline' | 'timeout' | 'unreachable';

export class TransportFailure extends Error {
  constructor(
    readonly kind: TransportFailureKind,
    message?: string,
    readonly cause?: unknown,
  ) {
    super(message ?? kind);
    this.name = 'TransportFailure';
  }
}

/**
 * The seam the whole client sits on. A native pinned implementation and the
 * vitest fake both satisfy it.
 * Implementations MUST throw `TransportFailure` (never a raw fetch error) when
 * no response arrived, and MUST NOT throw for non-2xx statuses.
 */
export interface HttpTransport {
  send(request: HttpRequest): Promise<HttpResponse>;
  /**
   * True when this transport enforces certificate pinning (T5). Release builds
   * refuse to run without it; dev builds against `http://localhost:3100` do not.
   */
  readonly pinned: boolean;
}

/** Fail closed in release builds if the transport is not pinned (T5). */
export function assertPinnedTransport(transport: HttpTransport, isRelease: boolean): void {
  if (isRelease && !transport.pinned) {
    throw MobileError.local('unknown', {
      detail: 'release build requires a certificate-pinned transport (T5)',
    });
  }
}

/** Plain `fetch` transport — correct, unpinned, used by tests and dev builds. */
export class FetchTransport implements HttpTransport {
  readonly pinned = false;

  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async send(request: HttpRequest): Promise<HttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), request.timeoutMs);
    try {
      const res = await this.fetchImpl(request.url, {
        method: request.method,
        headers: request.headers,
        ...(request.body !== undefined ? { body: request.body } : {}),
        signal: controller.signal,
      });
      return { status: res.status, body: await res.text() };
    } catch (cause) {
      if (controller.signal.aborted) {
        throw new TransportFailure('timeout', 'request timed out', cause);
      }
      // RN/undici surface DNS, connection-refused and airplane-mode alike as a
      // generic TypeError. We cannot reliably distinguish "no radio" from
      // "server down", so both map to `unreachable` and the citizen-facing
      // message stays about checking their connection.
      throw new TransportFailure('unreachable', 'network request failed', cause);
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface RetryPolicy {
  /** Total attempts for a `safe` call, including the first. */
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Injectable for tests; defaults to Math.random. */
  random?: () => number;
  /** Injectable for tests; defaults to setTimeout. */
  sleep?: (ms: number) => Promise<void>;
}

export const DEFAULT_RETRY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 300,
  maxDelayMs: 4_000,
};

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Exponential backoff with FULL jitter — avoids a synchronised retry storm. */
export function backoffDelay(attempt: number, policy: RetryPolicy): number {
  const random = policy.random ?? Math.random;
  const ceiling = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** (attempt - 1));
  return Math.floor(random() * ceiling);
}

/** Statuses worth retrying on a `safe` call. 429 is deliberately absent. */
export function isRetryableStatus(status: number): boolean {
  return status === 502 || status === 503 || status === 504;
}

/** Map a transport failure onto the citizen-facing local error codes. */
export function transportFailureToError(failure: TransportFailure): MobileError {
  switch (failure.kind) {
    case 'timeout':
      return MobileError.local('network_timeout', { detail: failure.message, cause: failure });
    case 'offline':
      return MobileError.local('network_unreachable', { detail: failure.message, cause: failure });
    case 'unreachable':
    default:
      return MobileError.local('server_unreachable', { detail: failure.message, cause: failure });
  }
}

export type Idempotency =
  /** Safe to repeat: no server-side single-use state is consumed. */
  | 'safe'
  /** Consumes a single-use nonce/challenge (T4) — never retried. */
  | 'consumes-nonce';

export interface SendWithRetryOptions {
  transport: HttpTransport;
  request: HttpRequest;
  idempotency: Idempotency;
  policy?: RetryPolicy;
}

/**
 * Send with the policy above. Returns the (possibly non-2xx) response; status
 * interpretation is the caller's job.
 */
export async function sendWithRetry(options: SendWithRetryOptions): Promise<HttpResponse> {
  const policy = options.policy ?? DEFAULT_RETRY;
  const sleep = policy.sleep ?? defaultSleep;
  const attempts = options.idempotency === 'safe' ? Math.max(1, policy.maxAttempts) : 1;

  let lastFailure: MobileError | null = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await options.transport.send(options.request);
      if (attempt < attempts && isRetryableStatus(response.status)) {
        await sleep(backoffDelay(attempt, policy));
        continue;
      }
      return response;
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      lastFailure = transportFailureToError(error);
      if (options.idempotency === 'consumes-nonce') {
        // We cannot know whether the server burned the nonce. Telling the
        // citizen to start over is the only honest answer (T4).
        throw MobileError.local('interrupted', {
          detail: `${options.request.method} interrupted (${error.kind})`,
          cause: error,
        });
      }
      if (attempt >= attempts) throw lastFailure;
      await sleep(backoffDelay(attempt, policy));
    }
  }
  /* c8 ignore next */
  throw lastFailure ?? MobileError.local('unknown', { detail: 'retry loop exhausted' });
}
