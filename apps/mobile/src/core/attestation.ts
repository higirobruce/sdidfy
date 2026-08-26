/**
 * Attestation — proving "genuine app, sound device, hardware-held key"
 * (05 §4, 03 §2 step 1, T2/T3/T4).
 *
 * The nonce round-trip is the anti-replay spine (docs/runbook.md §10):
 *
 *   POST /v1/enrol/attestation-challenge  →  { nonceId, nonce, expiresAt }
 *   nonce  ──▶ Play Integrity / App Attest, which binds it UNDER the platform
 *              signature so it cannot be swapped afterwards
 *   POST /v1/enrol/start { attestation: { platform, token, keyAttestation?,
 *                                         nonceId } }
 *
 * Without the nonce, an attestation token harvested from one genuine device
 * replays from any other (T4). The broker consumes the nonce with GETDEL
 * *before* running the verifier and does not return it on failure, so:
 *
 *   ⚠ EVERY enrolment attempt — including a retry after a failure — needs a
 *     FRESH nonce. And on Android it needs a fresh KEY too, because the
 *     challenge is baked into the attestation certificate chain at key
 *     generation. `ProtocolClient.enrol` therefore always does
 *     nonce → generate → attest → start, never reusing either.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * BYTE-LEVEL ENCODINGS THE NATIVE SIDE MUST MATCH (runbook §10)
 * ─────────────────────────────────────────────────────────────────────────────
 * These are not negotiable at runtime and there is no fallback: get one wrong
 * and every enrolment fails with a uniform `attestation_rejected` whose audit
 * row reads `nonce_mismatch` with nothing else to go on.
 *
 *  Android challenge      the UTF-8 bytes of the `nonce` STRING as received —
 *                         not the base64url-decoded 32 bytes, not a
 *                         re-encoding. Passed to `setAttestationChallenge()`
 *                         at `KeyStore.generate` time.
 *  Android keyAttestation the X.509 chain LEAF FIRST; JSON array of base64
 *                         DER (a PEM bundle or comma/whitespace-separated
 *                         base64 DER are also accepted).
 *  iOS clientDataHash     `SHA256(utf8(nonce))`. Apple binds
 *                         `SHA256(authData ‖ clientDataHash)` into the
 *                         credCert extension 1.2.840.113635.100.8.2.
 *  iOS token              base64 of the CBOR App Attest object
 *                         (`fmt`/`attStmt`/`authData`) exactly as
 *                         `DCAppAttestService` returns it. No separate
 *                         `keyAttestation` — on iOS the object IS the key
 *                         attestation.
 *  Key identity           the attested key MUST be the same keypair whose
 *                         public JWK goes out as `devicePublicKeyJwk`.
 *                         Attesting a separately generated key fails
 *                         `key_mismatch`.
 */
import type { PublicKeyJwk } from './types.js';
import type { AttestationPayload } from './wire.js';

export type AttestationPlatform = 'android' | 'ios' | 'sim';

export interface AttestInput {
  /** The broker's nonce string, passed through untouched. */
  nonce: string;
  /** Alias of the key being enrolled — the attested key must be this one. */
  keyAlias: string;
  /** The public JWK that will be sent as `devicePublicKeyJwk`. */
  publicJwk: PublicKeyJwk;
  /**
   * Android only: the key-attestation chain produced at generation time,
   * forwarded so a provider can return it as part of the payload.
   */
  keyAttestation?: string;
}

/**
 * Produces the `attestation` object for `POST /v1/enrol/start`. The `nonceId`
 * is filled in by the protocol client, not by the provider — the provider only
 * ever sees the nonce value it must bind.
 */
export interface Attestation {
  platform(): AttestationPlatform;
  /**
   * Throws MobileError('attestation_failed_local') when the platform refuses
   * to produce a token at all (no Play Services, App Attest unsupported,
   * device offline for the Play Integrity round-trip). That is a *local*
   * failure: it is not a verdict about the device, and the app must not
   * present it as "your phone is not trusted".
   */
  attest(input: AttestInput): Promise<Omit<AttestationPayload, 'nonceId'>>;
}
