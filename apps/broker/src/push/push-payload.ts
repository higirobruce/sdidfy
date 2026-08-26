/**
 * The wake-only push payload (05 §5, 06 T6).
 *
 * ===================== WHAT THIS PAYLOAD MAY NEVER CARRY ===================
 * No auth data. No relying-party name or logo. No binding message. No scopes.
 * No `auth_req_id`. No citizen, pseudo-NID, pairwise subject or binding id.
 * Nothing that identifies WHO is being asked or WHAT is being asked for.
 *
 * The reason is that a push payload is unauthenticated data delivered by a
 * third party (Google/Apple) to a device we do not control, and it is visible
 * on the lock screen. If the payload carried the request, an attacker who
 * could spoof or tamper with a push could fabricate an approval prompt — the
 * exact relay/consent-fatigue attack in T7 — and a shoulder-surfer could read
 * which service a citizen is signing in to. Instead the push says only "wake
 * up", and the app then PULLS the real pending request over the authenticated
 * backchannel (`GET /v1/device/ciba/pending`, 04 §3 step 5) where the broker's
 * TLS identity and the device session are what establish trust.
 *
 * The transport interface below enforces this structurally: `send()` takes a
 * device token and nothing else, so there is no parameter through which a
 * caller could smuggle request detail into a notification.
 * ==========================================================================
 */

/** Payload version, so the app can reject a shape it does not understand. */
export const WAKE_PAYLOAD_VERSION = 1;
export const WAKE_PAYLOAD_TYPE = 'sdid.wake';

/**
 * FCM data-only message body. Data-only (no `notification` block) on purpose:
 * the OS hands it straight to the app instead of rendering server-supplied
 * text, so nothing the broker sends can appear on screen.
 */
export function fcmWakeData(): Record<string, string> {
  return { type: WAKE_PAYLOAD_TYPE, v: String(WAKE_PAYLOAD_VERSION) };
}

/**
 * APNs payload. Two shapes, both content-free:
 *  - `background`: `content-available: 1`, no user-visible component at all.
 *    Cleanest, but iOS throttles background pushes aggressively and may delay
 *    them for minutes — which is fatal for a 180 s CIBA window.
 *  - `alert`: a `loc-key` ONLY. The device renders a string from the app's own
 *    localisation bundle (Kinyarwanda/English/French — 05 §7); the broker
 *    never sends display text, so still nothing about the request leaks.
 */
export function apnsWakePayload(pushType: 'alert' | 'background'): Record<string, unknown> {
  const aps: Record<string, unknown> =
    pushType === 'background'
      ? { 'content-available': 1 }
      : { alert: { 'loc-key': 'push.wake' }, sound: 'default', 'content-available': 1 };
  return { aps, type: WAKE_PAYLOAD_TYPE, v: WAKE_PAYLOAD_VERSION };
}

/**
 * Keys that must never appear anywhere in a push payload. Exported so the
 * unit test asserts the rule rather than a hand-copied snapshot of the shape:
 * a future edit that adds `rpName` to be helpful fails the test.
 */
export const FORBIDDEN_PAYLOAD_KEYS: readonly string[] = [
  'nid',
  'pseudoNid',
  'sub',
  'subject',
  'citizenId',
  'bindingId',
  'authReqId',
  'auth_req_id',
  'rpId',
  'rpName',
  'rp_name',
  'clientId',
  'scope',
  'scopes',
  'bindingMessage',
  'binding_message',
  'challenge',
  'nonce',
  'token',
  'signature',
  'assurance',
  'body',
  'title',
];
