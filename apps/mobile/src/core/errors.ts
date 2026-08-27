/**
 * Typed error handling for the authenticator (03 §7, 05 §7).
 *
 * Two hard rules encoded here:
 *  1. **No raw server string ever reaches a citizen.** The broker's
 *     `error_description` is deliberately generic (see BridgeErrorFilter), but
 *     it is still English prose produced server-side. We map the machine
 *     `error` code to a `MessageKey` and render it through i18n; the
 *     description is dropped on the floor, not stored, not shown, not logged.
 *  2. **Fail closed on the unknown.** An error code we do not recognise maps
 *     to `errors.unknown` and is NOT retryable — an unrecognised failure is
 *     never optimistically re-attempted.
 */
import { ERROR_CODES, type ErrorCode } from '@sdid/shared';
import type { MessageKey } from '../i18n/types.js';

/** Failures that never reach the broker — device, transport, or app-local. */
export const LOCAL_ERROR_CODES = [
  'network_unreachable',
  'network_timeout',
  'server_unreachable',
  'unexpected_response',
  'biometric_unavailable',
  'biometric_not_enrolled',
  'biometric_cancelled',
  'biometric_failed',
  'secure_hardware_unavailable',
  'keystore_failed',
  'attestation_failed_local',
  'not_enrolled',
  'interrupted',
  'unknown',
] as const;
export type LocalErrorCode = (typeof LOCAL_ERROR_CODES)[number];

export type MobileErrorCode = ErrorCode | LocalErrorCode;

/**
 * Where the failure came from. Drives UX: `protocol` errors are the broker's
 * verdict and are final for this attempt; `transport` errors may be worth a
 * retry; `device` errors need the citizen to fix something on the phone.
 */
export type MobileErrorSource = 'protocol' | 'transport' | 'device' | 'client';

/** Every broker error code → the citizen-facing message key (03 §7). */
const PROTOCOL_MESSAGE_KEYS: Record<ErrorCode, MessageKey> = {
  invalid_request: 'errors.invalid_request',
  enrolment_failed: 'errors.enrolment_failed',
  attestation_rejected: 'errors.attestation_rejected',
  attestation_unavailable: 'errors.attestation_unavailable',
  binding_not_found: 'errors.binding_not_found',
  binding_not_active: 'errors.binding_not_active',
  challenge_invalid: 'errors.challenge_invalid',
  signature_invalid: 'errors.signature_invalid',
  assurance_insufficient: 'errors.assurance_insufficient',
  rate_limited: 'errors.rate_limited',
  locked_out: 'errors.locked_out',
  unauthorized_client: 'errors.unauthorized_client',
  access_denied: 'errors.access_denied',
  authorization_pending: 'errors.authorization_pending',
  expired_token: 'errors.expired_token',
  slow_down: 'errors.slow_down',
  invalid_grant: 'errors.invalid_grant',
  invalid_client: 'errors.invalid_client',
  invalid_scope: 'errors.invalid_scope',
  unknown_user_id: 'errors.unknown_user_id',
  sdid_unavailable: 'errors.sdid_unavailable',
  internal_error: 'errors.internal_error',
};

const LOCAL_MESSAGE_KEYS: Record<LocalErrorCode, MessageKey> = {
  network_unreachable: 'errors.network_unreachable',
  network_timeout: 'errors.network_timeout',
  server_unreachable: 'errors.server_unreachable',
  unexpected_response: 'errors.unexpected_response',
  biometric_unavailable: 'errors.biometric_unavailable',
  biometric_not_enrolled: 'errors.biometric_not_enrolled',
  biometric_cancelled: 'errors.biometric_cancelled',
  biometric_failed: 'errors.biometric_failed',
  secure_hardware_unavailable: 'errors.secure_hardware_unavailable',
  keystore_failed: 'errors.keystore_failed',
  attestation_failed_local: 'errors.attestation_failed_local',
  not_enrolled: 'errors.not_enrolled',
  interrupted: 'errors.interrupted',
  unknown: 'errors.unknown',
};

const MESSAGE_KEYS: Record<MobileErrorCode, MessageKey> = {
  ...PROTOCOL_MESSAGE_KEYS,
  ...LOCAL_MESSAGE_KEYS,
};

/**
 * Codes for which offering the citizen a "try again" button is honest.
 * Note what is NOT here: `challenge_invalid` and `signature_invalid` mean the
 * single-use nonce is gone (T4) — the flow must be restarted from the top, not
 * retried — and `attestation_rejected`, which is a refusal, not a hiccup.
 */
const USER_RETRYABLE = new Set<MobileErrorCode>([
  'attestation_unavailable',
  'sdid_unavailable',
  'internal_error',
  'rate_limited',
  'slow_down',
  'network_unreachable',
  'network_timeout',
  'server_unreachable',
  'biometric_cancelled',
  'biometric_failed',
  'interrupted',
]);

/**
 * Codes that mean this device's binding is finished and the app must drop its
 * local state and send the citizen back to enrolment (03 §5, 06 §4).
 */
const TERMINAL_FOR_BINDING = new Set<MobileErrorCode>([
  'binding_not_found',
  'binding_not_active',
]);

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && (ERROR_CODES as readonly string[]).includes(value);
}

export function messageKeyForCode(code: MobileErrorCode): MessageKey {
  return MESSAGE_KEYS[code] ?? 'errors.unknown';
}

export interface MobileErrorInit {
  source: MobileErrorSource;
  /** HTTP status, when the failure came back from the broker. */
  httpStatus?: number;
  /**
   * Non-citizen-facing diagnostic detail, for the app's own log only.
   * MUST NOT contain biometric bytes, a raw NID, a session token, a nonce, or
   * a server `error_description` (07 §1, 03 §7).
   */
  detail?: string;
  cause?: unknown;
}

/**
 * The single error type the core throws. UI code never inspects `message`;
 * it renders `t(error.messageKey)`.
 */
export class MobileError extends Error {
  readonly code: MobileErrorCode;
  readonly source: MobileErrorSource;
  readonly messageKey: MessageKey;
  readonly httpStatus: number | undefined;
  readonly detail: string | undefined;
  /** True when a plain "try again" is a sensible offer for this code. */
  readonly userRetryable: boolean;
  /** True when the local binding is dead and enrolment must be redone. */
  readonly terminalForBinding: boolean;

  constructor(code: MobileErrorCode, init: MobileErrorInit) {
    // `message` is a developer string; it is never rendered to a citizen.
    super(`${init.source}:${code}${init.detail ? ` (${init.detail})` : ''}`);
    this.name = 'MobileError';
    this.code = code;
    this.source = init.source;
    this.messageKey = messageKeyForCode(code);
    this.httpStatus = init.httpStatus;
    this.detail = init.detail;
    this.userRetryable = USER_RETRYABLE.has(code);
    this.terminalForBinding = TERMINAL_FOR_BINDING.has(code);
    if (init.cause !== undefined) {
      (this as { cause?: unknown }).cause = init.cause;
    }
  }

  static local(code: LocalErrorCode, init?: Omit<MobileErrorInit, 'source'>): MobileError {
    const source: MobileErrorSource =
      code === 'network_unreachable' || code === 'network_timeout' || code === 'server_unreachable'
        ? 'transport'
        : code === 'unexpected_response' || code === 'unknown' || code === 'interrupted'
          ? 'client'
          : 'device';
    return new MobileError(code, { ...(init ?? {}), source });
  }

  /**
   * Build from a broker error body. An unknown/absent `error` field becomes
   * `unknown` — fail closed rather than guessing a friendlier code.
   */
  static fromBrokerBody(body: unknown, httpStatus: number): MobileError {
    const raw = (body as { error?: unknown } | null | undefined)?.error;
    if (isErrorCode(raw)) {
      return new MobileError(raw, { source: 'protocol', httpStatus });
    }
    return new MobileError('unknown', {
      source: 'protocol',
      httpStatus,
      // The code is a fixed enum, so echoing an *unrecognised* one is safe and
      // is the only way to debug a broker/app version skew. The description is
      // still discarded.
      detail: typeof raw === 'string' ? `unmapped_code=${raw.slice(0, 64)}` : 'no_error_code',
    });
  }
}

export function isMobileError(value: unknown): value is MobileError {
  return value instanceof MobileError;
}

/** Coerce anything thrown into a MobileError, so callers have one shape. */
export function toMobileError(value: unknown): MobileError {
  if (isMobileError(value)) return value;
  return MobileError.local('unknown', {
    detail: value instanceof Error ? value.name : typeof value,
    cause: value,
  });
}
