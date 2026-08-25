/**
 * Typed errors the adapter surfaces to the broker (spec 02 §4).
 * Messages NEVER contain raw NIDs, biometric bytes, or attribute values —
 * callers map these to generic user-facing failures (anti-probing, 03 §7)
 * and the detail lives server-side in the audit trail.
 */

/** The claimed identity is not known to SDID. Never retried; callers map to a generic failure. */
export class SdidUnknownIdentityError extends Error {
  constructor() {
    super('identity not known to SDID');
    this.name = 'SdidUnknownIdentityError';
  }
}

/** SDID could not be reached / answered unusably (maps to error code `sdid_unavailable`). */
export class SdidUnavailableError extends Error {
  constructor(message = 'SDID unavailable') {
    super(message);
    this.name = 'SdidUnavailableError';
  }
}

/** Per-call timeout elapsed (02 §4). Subtype of unavailable so callers need one branch. */
export class SdidTimeoutError extends SdidUnavailableError {
  constructor(timeoutMs: number) {
    super(`SDID call timed out after ${timeoutMs}ms`);
    this.name = 'SdidTimeoutError';
  }
}

/** Circuit breaker is open — SDID is not being called at all right now (02 §4). */
export class SdidCircuitOpenError extends SdidUnavailableError {
  constructor() {
    super('SDID circuit breaker is open');
    this.name = 'SdidCircuitOpenError';
  }
}

/**
 * Strategy output failed boundary validation (02 §4: a malformed SDID response
 * never propagates to the broker). Message carries zod issue paths/codes only —
 * never received values, which could include identity data.
 */
export class SdidMalformedResponseError extends SdidUnavailableError {
  constructor(detail: string) {
    super(`malformed SDID response: ${detail}`);
    this.name = 'SdidMalformedResponseError';
  }
}
