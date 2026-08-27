import { createHmac } from 'node:crypto';

/**
 * Pseudonymous SDID subject for a NID: 'sdid-' + first 16 hex chars of
 * HMAC-SHA256(pepper, nid) (Q8 — pseudonymised NID). This is the only identity form that
 * may appear in audit records; raw NIDs never leave the call path. The pepper
 * is a keying secret so a DB dump alone cannot be reversed to raw NIDs.
 */
export function sdidSubjectForNid(nid: string, pepper: string): string {
  return `sdid-${createHmac('sha256', pepper).update(nid).digest('hex').slice(0, 16)}`;
}

const SUBJECT_SHAPE = /^sdid-[0-9a-f]{16}$/;

/** True when an id is already in pseudonymous sdidSubject form. */
export function isSdidSubject(id: string): boolean {
  return SUBJECT_SHAPE.test(id);
}

/**
 * Audit subject ref for whatever id a call received. An id already in
 * sdidSubject form passes through unchanged (v1 /userinfo calls with the
 * stored sdidSubject — re-hashing it would break audit correlation with the
 * enrolment records); a raw NID is hashed so it never reaches the audit trail.
 */
export function auditSubjectRef(id: string, pepper: string): string {
  return isSdidSubject(id) ? id : sdidSubjectForNid(id, pepper);
}
