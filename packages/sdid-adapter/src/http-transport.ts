import { z } from 'zod';
import {
  SdidMalformedResponseError,
  SdidTimeoutError,
  SdidUnavailableError,
  SdidUnknownIdentityError,
} from './errors.js';

/**
 * The HTTP seam every real strategy calls through (02 §4: the adapter is the
 * only module that talks to SDID). Injecting a transport is what lets the
 * shared contract suite (09 §3) run both real strategies against a fake SDID
 * with no network, so cutover is proved by the same tests the mock passes.
 *
 * Deliberately minimal and byte-oriented: A2 may well answer "binary template"
 * rather than JSON, and a JSON-only seam would have to be rebuilt then.
 */
export interface SdidHttpRequest {
  method: 'GET' | 'POST' | 'PUT';
  /** Absolute URL. Build with `joinUrl` so path config stays relative. */
  url: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
}

export interface SdidHttpResponse {
  status: number;
  /** Lower-cased header names. */
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface SdidHttpTransport {
  send(req: SdidHttpRequest, signal: AbortSignal): Promise<SdidHttpResponse>;
}

/**
 * Default transport: Node 22 global fetch. No third-party HTTP client — the
 * adapter is the module with SDID credentials in scope (02 §4), so its
 * dependency surface stays as small as possible.
 *
 * NOTE (A4/C1): outbound reachability and any TLS/mTLS client-cert material are
 * deployment concerns. When A3 answers "mTLS", this is the single place that
 * needs an undici Agent — nothing above it changes.
 */
export function createFetchTransport(): SdidHttpTransport {
  return {
    async send(req, signal) {
      let res: Response;
      try {
        res = await fetch(req.url, {
          method: req.method,
          headers: req.headers ?? {},
          // Uint8Array is a valid BodyInit; undefined for GET.
          body: req.body as RequestInit['body'],
          signal,
          redirect: 'error', // never follow a redirect to an unvetted host
        });
      } catch (err) {
        // AbortError arrives here when the resilience layer's timeout fires.
        if (err instanceof Error && err.name === 'AbortError') {
          throw new SdidTimeoutError(0);
        }
        // Message is a transport-level failure (DNS/TLS/connect) — never
        // identity data — but we still keep it terse.
        throw new SdidUnavailableError(
          `SDID transport failure: ${err instanceof Error ? err.name : 'unknown'}`,
        );
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return {
        status: res.status,
        headers,
        body: new Uint8Array(await res.arrayBuffer()),
      };
    },
  };
}

/**
 * Send one request with a socket-level deadline, guaranteeing the adapter error
 * taxonomy no matter which transport is injected (02 §4). The contract-level
 * timeout is still the resilience wrapper's; this one exists so an abandoned
 * attempt cannot hold a connection — or an unsettled promise — open behind it.
 */
export async function sendWithDeadline(
  transport: SdidHttpTransport,
  req: SdidHttpRequest,
  timeoutMs: number,
): Promise<SdidHttpResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await transport.send(req, controller.signal);
  } catch (err) {
    if (err instanceof SdidUnavailableError) throw err; // already in the taxonomy
    if (err instanceof Error && err.name === 'AbortError') throw new SdidTimeoutError(timeoutMs);
    throw new SdidUnavailableError(
      `SDID transport failure: ${err instanceof Error ? err.name : 'unknown'}`,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Join a base URL and a configured relative path without doubling slashes. */
export function joinUrl(base: string, path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  return `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}

/** True for statuses that carry a usable body. */
export function isOk(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * Map an HTTP status onto the adapter error taxonomy (errors.ts).
 * The mapping is deliberately conservative — the only status we allow to mean
 * "this citizen is not known to SDID" is one the deployment explicitly listed,
 * because reporting an outage as an unknown identity would fail a legitimate
 * enrolment and look, in audit, like a failed identity claim (03 §7).
 *
 * @param notFoundStatuses statuses that genuinely mean "no such identity".
 */
export function throwForStatus(
  status: number,
  context: string,
  notFoundStatuses: readonly number[] = [404],
): never {
  if (notFoundStatuses.includes(status)) throw new SdidUnknownIdentityError();
  if (status === 401 || status === 403) {
    // Our client credentials are rejected/expired (A3 rotation policy) — an
    // availability problem on our side of the trust boundary, never the
    // citizen's. Callers invalidate any cached token before the retry.
    throw new SdidUnavailableError(`SDID rejected client authentication (${context}, ${status})`);
  }
  if (status === 429) {
    // Quota (A5 — limits still unknown).
    throw new SdidUnavailableError(`SDID rate-limited the adapter (${context}, 429)`);
  }
  throw new SdidUnavailableError(`SDID returned HTTP ${status} (${context})`);
}

/**
 * Parse a response body as JSON and validate it against `schema` (02 §4:
 * boundary validation, a malformed SDID response never propagates).
 * Errors carry zod issue paths/codes and never the received values, which
 * could be identity data.
 */
export function parseJsonBody<T>(
  res: SdidHttpResponse,
  schema: z.ZodType<T>,
  context: string,
): T {
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(res.body).toString('utf8'));
  } catch {
    throw new SdidMalformedResponseError(`${context}: body is not valid JSON`);
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`)
      .join('; ');
    throw new SdidMalformedResponseError(`${context}: ${detail}`);
  }
  return parsed.data;
}
