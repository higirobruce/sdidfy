/**
 * KeyStore — the hardware-bound device keypair (05 §3, 06 §3, T1/T2/T3).
 *
 * This is the single most load-bearing interface in the app: the whole trust
 * chain reduces to "only this phone, with this citizen's live biometric, can
 * produce a signature that verifies against the public key bound at enrolment"
 * (03 §1). Everything above it — the protocol client, the screens — is
 * replaceable; this is not.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT A NATIVE IMPLEMENTATION MUST GUARANTEE
 * ─────────────────────────────────────────────────────────────────────────────
 * These are requirements on the *native* module, not on this TypeScript. The
 * TS layer cannot check any of them; `src/native/CONTRACT.md` restates each
 * one against the concrete iOS/Android API that provides it.
 *
 * 1. NON-EXPORTABLE (05 §3, T3). The private key is generated inside the
 *    Secure Enclave / StrongBox-or-TEE Keystore and never exists as bytes
 *    outside it. There is no "export", "backup", "wrap" or "migrate to new
 *    phone" path — by design, because that is also what makes device loss
 *    recoverable only by full re-enrolment (03 §5) and makes the key
 *    unphishable (T11). A native `sign` that loads key material into RN's JS
 *    heap violates this even if it "works".
 *
 * 2. BIOMETRIC-GATED, FRESH PER SIGNATURE (05 §3, T1). Key *use* is authorised
 *    by a live biometric each time:
 *      - Android: `setUserAuthenticationRequired(true)` with
 *        `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` — a
 *        validity duration of 0 means "one authentication authorises exactly
 *        one crypto operation", which is the property we need. Also
 *        `setInvalidatedByBiometricEnrolment(true)`: adding a new fingerprint
 *        must destroy the key, otherwise a coerced enrolment inherits the
 *        binding.
 *      - iOS: the key's SecAccessControl carries `.biometryCurrentSet` plus
 *        `.privateKeyUsage`; `.biometryCurrentSet` invalidates the key when
 *        the enrolled biometric set changes, which is the iOS analogue.
 *    The prompt MUST be raised by the platform as part of the signing
 *    operation, not by JS beforehand — see `sign()` below.
 *
 * 3. HARDWARE-BACKED AND ATTESTABLE (05 §3, T2). Prefer StrongBox
 *    (`setIsStrongBoxBacked(true)`, fall back to TEE on `StrongBoxUnavailable`)
 *    and report which was used, because that decides the assurance cap the
 *    broker applies (06 §6: software-held ⇒ AL1). On Android, generation must
 *    accept the broker's attestation challenge (see `generate`), because
 *    Android bakes the challenge into the certificate chain *at generation
 *    time* — it cannot be added later.
 *
 * 4. ONE KEY PER BINDING, DELETABLE. Keys are addressed by a stable alias.
 *    Deleting the alias must actually destroy the hardware key, so that
 *    revoking a binding locally leaves nothing usable behind.
 *
 * 5. NO SECRET EVER LEAVES. Never write key material, the signed payloads'
 *    inputs, or biometric data to app storage, logs, crash reports, or backups
 *    (05 §3). Exclude the keychain items from iCloud/Google backup
 *    (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `allowBackup=false`).
 */
import type { PublicKeyJwk } from './types.js';

/** Which secure element actually holds the key — decides the assurance cap. */
export type KeySecurityLevel =
  /** Android StrongBox / iOS Secure Enclave — a discrete secure element. */
  | 'strongbox'
  /** Android TEE-backed Keystore — hardware-isolated, not a separate chip. */
  | 'tee'
  /**
   * No hardware isolation. Enrolment MUST refuse this for AL2+ (06 §6); the
   * in-memory test KeyStore reports it so no test can accidentally look like
   * a real device.
   */
  | 'software';

export interface KeyStoreCapabilities {
  /** False ⇒ the app cannot enrol at all on this device. */
  available: boolean;
  securityLevel: KeySecurityLevel;
  /** True when the platform can emit a key attestation for generated keys. */
  supportsKeyAttestation: boolean;
}

export interface GenerateKeyOptions {
  /** Stable alias for this binding's key. */
  alias: string;
  /**
   * The broker's attestation nonce, EXACTLY as returned by
   * `POST /v1/enrol/attestation-challenge` (the base64url string itself).
   *
   * Android: passed verbatim as the UTF-8 bytes of this string to
   * `setAttestationChallenge()` — NOT the base64url-decoded 32 bytes
   * (docs/runbook.md §10 "Client contract"). It must be supplied at
   * generation; there is no way to attach it afterwards, which is why a fresh
   * enrolment attempt needs a fresh nonce AND a fresh key.
   *
   * iOS: ignored here — App Attest binds `SHA256(utf8(nonce))` as the
   * `clientDataHash` at attestation time (see `Attestation`), not at key
   * generation.
   */
  attestationChallenge?: string;
}

export interface GeneratedKey {
  alias: string;
  publicJwk: PublicKeyJwk;
  securityLevel: KeySecurityLevel;
  /**
   * Android: the X.509 key-attestation chain, LEAF FIRST, as a JSON array of
   * base64 DER strings (the broker also accepts a PEM bundle or a
   * comma/whitespace-separated list — runbook §10).
   * iOS: absent; on iOS the App Attest object IS the key attestation.
   */
  keyAttestation?: string;
}

/**
 * Why the signature is being requested. The native module renders this into
 * the platform biometric prompt, so the citizen sees *what they are
 * authorising* at the moment they authorise it (05 §7: plain language on every
 * security prompt). The strings are already localised by the caller.
 */
export interface SignPromptSpec {
  title: string;
  subtitle?: string;
  /** Localised label for the prompt's cancel affordance. */
  cancelLabel: string;
}

export interface KeyStore {
  capabilities(): Promise<KeyStoreCapabilities>;

  /** True when `alias` currently names a usable key on this device. */
  hasKey(alias: string): Promise<boolean>;

  /**
   * Generate a fresh non-exportable, biometric-gated EC P-256 keypair.
   * Overwrites any existing key at `alias` (a re-enrolment is a new key).
   */
  generate(options: GenerateKeyOptions): Promise<GeneratedKey>;

  exportPublicJwk(alias: string): Promise<PublicKeyJwk>;

  /**
   * Sign the EXACT UTF-8 bytes of `payload` with ECDSA P-256 / SHA-256 and
   * return the raw `r||s` signature, base64url — the wire form the broker
   * verifies (packages/shared/src/protocol.ts).
   *
   * The biometric prompt is raised INSIDE this call, by the platform, as the
   * authorisation for this one key operation. There is deliberately no
   * `unlock()` method: a separate "authenticate, then sign" API is a
   * time-of-check/time-of-use hole — malware that wins the race between the
   * two signs a payload the citizen never saw (T1, T7). One prompt, one
   * signature, one payload.
   *
   * Throws MobileError('biometric_cancelled' | 'biometric_failed' |
   * 'biometric_not_enrolled' | 'keystore_failed').
   */
  sign(alias: string, payload: string, prompt: SignPromptSpec): Promise<string>;

  /** Destroy the key. Must be irreversible. */
  delete(alias: string): Promise<void>;
}
