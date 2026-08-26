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

/**
 * A real strategy was asked to do something whose mechanics are still an open
 * SDID integration question (02 §3 — A1 interface shape, A2 reference-template
 * mechanics) and no deployment-supplied adapter filled the gap.
 *
 * Deliberately NOT a subtype of SdidUnavailableError: this is our own
 * misconfiguration, not an SDID outage. It must never be retried, must never
 * trip the circuit breaker, and must never be silently degraded into "identity
 * unknown" — a guess here would return wrong data about a citizen. It carries
 * only the option path and the open-question id; never identity data.
 */
export class SdidConfigurationError extends Error {
  constructor(
    /** Dotted option path the deployment must supply, e.g. `oidc.referenceBiometric`. */
    readonly optionPath: string,
    /** Open question(s) this gap is blocked on, e.g. `A2`. */
    readonly openQuestion: string,
    detail: string,
  ) {
    super(
      `SDID adapter not configured: ${optionPath} is required — ${detail} ` +
        `(blocked on docs/SPEC.md 02 §3 ${openQuestion}; do not guess a default)`,
    );
    this.name = 'SdidConfigurationError';
  }
}
