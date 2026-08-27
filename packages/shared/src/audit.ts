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
  // --- Broker signing-key custody (06 §3, T13, decision #5) --------------
  // T13's control set is "KMS/HSM custody, no plaintext keys in app memory,
  // rotation w/ /jwks overlap, key-usage audit". The last of those needs its
  // own vocabulary: every key lifecycle event is security-relevant and must be
  // attributable, and folding them into `admin.action` (as anomaly detection
  // had to) would make them unqueryable next to the rest of the trail.
  //
  // The split is deliberate. Lifecycle and failure events get an IMMEDIATE row
  // each — they are rare and each one matters. Signing itself does NOT: at
  // national scale one row per minted token would swamp the append-only chain
  // (every append takes a global advisory lock, 07 §4), so signature volume is
  // counted per kid in memory and flushed as a periodic `key.usage_summary`.
  /** A new signing keypair came into existence inside the custody boundary. */
  'key.generated',
  /** A key became the one the broker signs with. */
  'key.promoted',
  /** A key stopped signing but stays in the JWKS for overlap (06 §3). */
  'key.retired',
  /** A promote-and-retire cycle completed (the umbrella event for the pair). */
  'key.rotated',
  /** A custody `sign()` call failed — a token was NOT minted. Throttled. */
  'key.signing_failed',
  /** Periodic per-kid signature tally. NOT one row per token — see above. */
  'key.usage_summary',
  /** The custody boundary changed between healthy and unhealthy. */
  'key.custody_health_changed',
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
