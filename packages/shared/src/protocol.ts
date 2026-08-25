/**
 * Challenge-signing protocol — the spine of the trust chain.
 *
 * The broker issues a challenge {challengeId, nonce, payload}; the device
 * signs the exact UTF-8 bytes of `payload` with its hardware-backed ES256
 * key and returns the signature base64url-encoded (JWS raw r||s form, as
 * produced by WebCrypto / Node subtle ECDSA-SHA256).
 *
 * Payload format (versioned, canonical — both sides build it identically):
 *   sdid-bridge:v1:<purpose>:<challengeId>:<nonce>
 * where <purpose> is one of:
 *   activation                      — enrolment proof-of-possession (03 §2 step 9)
 *   login                           — direct first-party login (01 §2.2)
 *   ciba-approve:<authReqId>        — CIBA approval, bound to the auth request (T4)
 *   ciba-deny:<authReqId>           — explicit denial (also signed, so denials are authentic)
 * Challenges are single-use, short-TTL, stored server-side in Redis (T4).
 *
 * One purpose — `attestation` — is NOT a signing payload: the nonce is carried
 * *inside* the platform attestation token (Play Integrity / App Attest both
 * bind a caller-supplied nonce under their own signature), so the device never
 * signs a `sdid-bridge:` payload for it. It is modelled here anyway because it
 * shares the single-use, short-TTL, purpose-tagged Redis record and the same
 * anti-replay property (T4): without a server-issued nonce, an attestation
 * token harvested from one genuine device replays from any other.
 */
export const CHALLENGE_PROTOCOL_VERSION = 'v1';

export type ChallengePurpose =
  | { kind: 'activation' }
  | { kind: 'login' }
  | { kind: 'attestation' }
  | { kind: 'ciba-approve'; authReqId: string }
  | { kind: 'ciba-deny'; authReqId: string };

export function purposeString(p: ChallengePurpose): string {
  switch (p.kind) {
    case 'activation':
      return 'activation';
    case 'login':
      return 'login';
    case 'attestation':
      return 'attestation';
    case 'ciba-approve':
      return `ciba-approve:${p.authReqId}`;
    case 'ciba-deny':
      return `ciba-deny:${p.authReqId}`;
  }
}

export function buildChallengePayload(
  purpose: ChallengePurpose,
  challengeId: string,
  nonce: string,
): string {
  return `sdid-bridge:${CHALLENGE_PROTOCOL_VERSION}:${purposeString(purpose)}:${challengeId}:${nonce}`;
}

export interface IssuedChallenge {
  challengeId: string;
  nonce: string;
  /** The exact string the device must sign (UTF-8). */
  payload: string;
  expiresAt: string; // ISO timestamp
}

/** amr values minted into tokens (04 §4). */
export const AMR_VALUES = ['hwk', 'bio'] as const;

/** CIBA grant type (OpenID CIBA Core). */
export const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';

/** OIDC scopes the broker understands in v1. */
export const SUPPORTED_SCOPES = ['openid', 'profile', 'address'] as const;
