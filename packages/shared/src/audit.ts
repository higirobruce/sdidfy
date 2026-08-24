import type { AssuranceLevel } from './assurance.js';
import type { MatchScoreBand } from './match.js';

/** Audit actions (07 §4). Every security-relevant event maps to one of these. */
export const AUDIT_ACTIONS = [
  'enrolment.started',
  'enrolment.match_completed',
  'enrolment.binding_created',
  'enrolment.binding_activated',
  'enrolment.failed',
  'auth.challenge_issued',
  'auth.login_succeeded',
  'auth.login_failed',
  'ciba.request_created',
  'ciba.request_approved',
  'ciba.request_denied',
  'ciba.request_expired',
  'ciba.tokens_issued',
  'oidc.code_issued',
  'oidc.tokens_issued',
  'token.revoked',
  'consent.granted',
  'consent.revoked',
  'device.revoked',
  'rp.registered',
  'rp.updated',
  'rp.suspended',
  'sdid.reference_fetched',
  'sdid.reassert',
  'admin.action',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export type AuditActorType = 'citizen' | 'rp' | 'admin' | 'system';

export interface AuditActor {
  type: AuditActorType;
  /** Internal id (citizen uuid, rp uuid, admin principal) — never a raw NID. */
  id?: string;
}

/**
 * Payload accepted by the audit service. The service adds ts, id, and the
 * tamper-evident hash chain (prev_hash/hash) — callers never set those.
 * NEVER put biometric bytes, raw NIDs, or token values in `context`.
 */
export interface AuditEventInput {
  actor: AuditActor;
  action: AuditAction;
  /** Pseudonymised subject reference (pseudo_nid or citizen id). */
  subjectRef?: string;
  rpId?: string;
  deviceBindingId?: string;
  assurance?: AssuranceLevel;
  matchResult?: { matched: boolean; scoreBand: MatchScoreBand; padPassed: boolean };
  sdidTxnRef?: string;
  result: 'success' | 'failure' | 'denied';
  context?: Record<string, unknown>;
}
