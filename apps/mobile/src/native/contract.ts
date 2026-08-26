/**
 * TypeScript declarations for the four native modules this app needs
 * (05 §8: "native modules: secure key generation/signing, attestation,
 * biometric prompts").
 *
 * This file is PURE TypeScript — no `react-native` import — so it typechecks
 * and is reviewable in this monorepo today. The glue that actually reaches
 * `NativeModules` lives in the sibling `*.rn.ts` files, which are excluded
 * from `tsconfig.json` because `react-native` is not installed here.
 *
 * The Swift/Kotlin each module must implement, and the security properties
 * each implementation must guarantee, are specified in `./CONTRACT.md`.
 * Nothing in this repository implements them: there is no Swift and no Kotlin
 * here, deliberately, because plausible-looking native code that has never
 * been compiled or run on a device is worse than none.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * BRIDGE RULES (apply to every method below)
 * ─────────────────────────────────────────────────────────────────────────────
 * - All arguments and results are JSON-safe primitives. Binary values cross as
 *   base64 / base64url STRINGS, with the encoding named in each signature.
 *   Never as `number[]`, and never as anything holding key material.
 * - Rejections carry a stable `code` from `NativeErrorCode` in `error.code`.
 *   Free-text messages are for the developer log only and never reach a
 *   citizen (03 §7) — the TS layer maps `code` to a MobileError.
 * - No method may log its arguments or results. A biometric sample, a nonce,
 *   a signature and a public key are all either sensitive or fingerprintable.
 */

/** Stable rejection codes every native module uses. */
export const NATIVE_ERROR_CODES = [
  /** No secure element / no Keystore / API level too low. */
  'E_SECURE_HARDWARE_UNAVAILABLE',
  /** StrongBox requested but unavailable and the fallback was refused. */
  'E_STRONGBOX_UNAVAILABLE',
  /** The alias does not name a key (or it was invalidated by re-enrolment). */
  'E_KEY_NOT_FOUND',
  /** Key generation/signing failed inside the platform for another reason. */
  'E_KEYSTORE',
  /** The citizen dismissed the biometric prompt. */
  'E_BIOMETRIC_CANCELLED',
  /** The biometric was presented and not recognised (after platform retries). */
  'E_BIOMETRIC_FAILED',
  /** No biometric is enrolled in the OS. */
  'E_BIOMETRIC_NOT_ENROLLED',
  /** Hardware present but temporarily locked out by the platform. */
  'E_BIOMETRIC_LOCKOUT',
  /** Play Integrity / App Attest could not produce a token at all. */
  'E_ATTESTATION_UNAVAILABLE',
  /** Camera permission refused, or the capture session could not start. */
  'E_CAPTURE_UNAVAILABLE',
  /** The citizen backed out of the face capture. */
  'E_CAPTURE_CANCELLED',
  /** Liveness/PAD did not pass locally (ISO 30107 L2, T8). */
  'E_CAPTURE_LIVENESS_FAILED',
] as const;
export type NativeErrorCode = (typeof NATIVE_ERROR_CODES)[number];

export interface NativeRejection {
  code: NativeErrorCode | string;
  message?: string;
}

// ── 1. SdidKeyStore ─────────────────────────────────────────────────────────

export interface NativeKeyCapabilities {
  available: boolean;
  /** 'strongbox' | 'tee' | 'software' — see KeySecurityLevel. */
  securityLevel: string;
  supportsKeyAttestation: boolean;
}

export interface NativeGeneratedKey {
  /** Base64url `x` and `y` of the P-256 public point, JWK style. */
  publicKeyX: string;
  publicKeyY: string;
  securityLevel: string;
  /**
   * Android: JSON array of base64 DER certificates, LEAF FIRST.
   * iOS: omitted — App Attest carries the key attestation instead.
   */
  keyAttestation?: string;
}

/**
 * Secure-element keypair (05 §3).
 * `generate` MUST create a NON-EXPORTABLE EC P-256 key whose use requires a
 * fresh strong-biometric authentication, and MUST accept the broker's
 * attestation challenge at generation time (Android bakes it into the
 * certificate chain there and nowhere else).
 */
export interface SdidKeyStoreNativeModule {
  capabilities(): Promise<NativeKeyCapabilities>;
  hasKey(alias: string): Promise<boolean>;
  /**
   * @param attestationChallenge the broker's nonce STRING; Android passes its
   *        UTF-8 bytes to `setAttestationChallenge()` (runbook §10). Pass an
   *        empty string when no attestation is wanted.
   */
  generate(alias: string, attestationChallenge: string): Promise<NativeGeneratedKey>;
  exportPublicKey(alias: string): Promise<{ publicKeyX: string; publicKeyY: string }>;
  /**
   * Raise the biometric prompt AND sign in one platform operation.
   * @param payload the exact string to sign; the native side signs its UTF-8 bytes
   * @returns base64url of the raw r||s signature (NOT DER — see CONTRACT.md §1.4)
   */
  sign(
    alias: string,
    payload: string,
    promptTitle: string,
    promptSubtitle: string,
    cancelLabel: string,
  ): Promise<string>;
  deleteKey(alias: string): Promise<void>;
}

// ── 2. SdidAttestation ──────────────────────────────────────────────────────

export interface NativeAttestationResult {
  /** 'android' | 'ios'. */
  platform: string;
  /** Android: the Play Integrity token. iOS: base64 CBOR App Attest object. */
  token: string;
  /** Android only: the key-attestation chain (see NativeGeneratedKey). */
  keyAttestation?: string;
}

export interface SdidAttestationNativeModule {
  /**
   * @param nonce the broker's nonce STRING, untouched.
   *        Android → Play Integrity `requestHash` = the nonce string.
   *        iOS → `clientDataHash` = SHA256(utf8(nonce)).
   * @param keyAlias the key being enrolled; the attested key MUST be this one.
   */
  attest(nonce: string, keyAlias: string): Promise<NativeAttestationResult>;
}

// ── 3. SdidBiometrics ───────────────────────────────────────────────────────

export interface NativeBiometricCapabilities {
  available: boolean;
  enrolled: boolean;
  /** Android BIOMETRIC_STRONG (class 3) / iOS Face ID or Touch ID. */
  strong: boolean;
  /** Subset of 'face' | 'fingerprint' | 'iris'. */
  kinds: string[];
}

export interface SdidBiometricsNativeModule {
  capabilities(): Promise<NativeBiometricCapabilities>;
  /**
   * Presentation-only confirmation. NOT authorisation for anything
   * cryptographic — key use is authorised inside `SdidKeyStore.sign`.
   */
  confirm(title: string, subtitle: string, cancelLabel: string): Promise<boolean>;
  /**
   * True while the screen is being recorded or an overlay window is on top
   * (05 §9). Best effort: iOS exposes `UIScreen.isCaptured`; Android exposes
   * overlay state via `FLAG_WINDOW_IS_OBSCURED` on touch events and
   * `setRecordingCallback` on API 34+. Where the platform cannot tell, return
   * false and say so in the module's docs — do not guess "true".
   */
  isScreenCompromised(): Promise<boolean>;
}

// ── 4. SdidFaceCapture ──────────────────────────────────────────────────────

export interface NativeCaptureResult {
  /** base64 of the captured image bytes. */
  data: string;
  /** PAD method identifier, e.g. 'active-blink'. */
  livenessMethod: string;
  /** 0..1 PAD confidence (ISO/IEC 30107 L2, T8). */
  livenessScore: number;
}

/**
 * Enrolment-only face capture with liveness. This is the ONLY native surface
 * that handles biometric bytes; see CONTRACT.md §4 for the memory discipline
 * it must follow (07 §1): no file, no cache, no log, buffers zeroed, and no
 * frame retained after the session ends.
 */
export interface SdidFaceCaptureNativeModule {
  capture(instruction: string, cancelLabel: string): Promise<NativeCaptureResult>;
  /** Zero and release the last capture. Called from a `finally` on the TS side. */
  release(): Promise<void>;
}

// ── Native error → MobileError code ─────────────────────────────────────────

/**
 * The one place native failures become app failures. Anything unrecognised
 * maps to `keystore_failed`/`unknown` at the call site — fail closed, never
 * assume a benign cause.
 */
export const NATIVE_ERROR_MAP = {
  E_SECURE_HARDWARE_UNAVAILABLE: 'secure_hardware_unavailable',
  E_STRONGBOX_UNAVAILABLE: 'secure_hardware_unavailable',
  E_KEY_NOT_FOUND: 'keystore_failed',
  E_KEYSTORE: 'keystore_failed',
  E_BIOMETRIC_CANCELLED: 'biometric_cancelled',
  E_BIOMETRIC_FAILED: 'biometric_failed',
  E_BIOMETRIC_NOT_ENROLLED: 'biometric_not_enrolled',
  E_BIOMETRIC_LOCKOUT: 'biometric_failed',
  E_ATTESTATION_UNAVAILABLE: 'attestation_failed_local',
  E_CAPTURE_UNAVAILABLE: 'biometric_unavailable',
  E_CAPTURE_CANCELLED: 'biometric_cancelled',
  E_CAPTURE_LIVENESS_FAILED: 'biometric_failed',
} as const satisfies Record<NativeErrorCode, string>;
