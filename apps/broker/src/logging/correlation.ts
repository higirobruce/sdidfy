import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

export interface RequestContext {
  /** Correlates every log line emitted while handling one request. */
  requestId: string;
}

/**
 * Request-scoped context carried without threading a parameter through every
 * service. AsyncLocalStorage survives `await` boundaries, which a plain
 * module-level variable would not — two concurrent enrolments would otherwise
 * swap correlation ids mid-flight.
 */
const storage = new AsyncLocalStorage<RequestContext>();

export function currentRequestId(): string | undefined {
  return storage.getStore()?.requestId;
}

export function runWithRequestContext<T>(ctx: RequestContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

/** Header both accepted and echoed, matching the common ingress convention. */
export const REQUEST_ID_HEADER = 'x-request-id';

/**
 * An inbound correlation id is UNTRUSTED input that ends up in log files and
 * log queries, so it is accepted only in a narrow shape and length: anything
 * else (log-injection newlines, a 4 KB header, an attacker's marker) is
 * discarded in favour of a fresh uuid. We honour a caller-supplied id at all
 * because a GoR ingress or a relying party's trace id makes cross-system
 * incident reconstruction possible (06 §7 — the same reason SDID's `txnRef`
 * rides in the audit trail).
 */
const SAFE_REQUEST_ID = /^[A-Za-z0-9_.:-]{8,64}$/;

export function sanitizeRequestId(raw: unknown): string {
  if (typeof raw === 'string' && SAFE_REQUEST_ID.test(raw)) return raw;
  return randomUUID();
}

/**
 * Express middleware establishing the request context. Registered in main.ts
 * before the Nest router so EVERY line logged during a request — including
 * from the global exception filter — carries the same `requestId`.
 */
export function correlationMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = sanitizeRequestId(req.headers[REQUEST_ID_HEADER]);
  // Echo it back so a caller (or an operator with a curl transcript) can hand
  // us the id from a failed request and we can find the exact log lines.
  res.setHeader(REQUEST_ID_HEADER, requestId);
  runWithRequestContext({ requestId }, () => {
    next();
  });
}
