/**
 * Stable machine-readable error codes across the bridge.
 * User-facing messages stay generic (03 §7 — never reveal why a match failed);
 * the detail lives server-side in the audit trail.
 */
export const ERROR_CODES = [
  'invalid_request',
  'enrolment_failed', // generic: covers match failure, PAD failure, unknown NID (anti-probing, 03 §7)
  'attestation_rejected',
  'binding_not_found',
  'binding_not_active',
  'challenge_invalid', // expired, unknown, or reused nonce (T4)
  'signature_invalid',
  'assurance_insufficient',
  'rate_limited',
  'locked_out',
  'unauthorized_client',
  'access_denied',
  'authorization_pending',
  'expired_token',
  'slow_down',
  'invalid_grant',
  'invalid_client',
  'invalid_scope',
  'unknown_user_id',
  'sdid_unavailable',
  'internal_error',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export class BridgeError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message?: string,
    public readonly httpStatus: number = 400,
  ) {
    super(message ?? code);
    this.name = 'BridgeError';
  }
}
