/**
 * BiometricPrompt + FaceCapture (05 §2, 05 §3, 03 §2 step 3).
 *
 * Two DIFFERENT things that both say "biometric", kept apart on purpose:
 *
 *  - `BiometricPrompt` — the device-native Face ID / fingerprint check. It
 *    proves *the phone's owner is present*. It is used for capability checks
 *    and for confirmations that do not sign anything. It is NOT how a
 *    signature is authorised: that happens inside `KeyStore.sign`, because the
 *    platform must bind the prompt to the key operation (see keystore.ts).
 *    A `confirm()` that returns `true` is a UI fact, never a trust fact.
 *
 *  - `FaceCapture` — the enrolment-only capture of an actual face image with
 *    liveness/PAD, which is *sent to the broker* to be matched 1:1 against
 *    NIDA's reference (03 §2 steps 3–6b, T8). This is the one and only moment
 *    the app handles biometric bytes.
 *
 * BIOMETRIC BYTE DISCIPLINE (07 §1, 08 §3) — binding on any implementation:
 *  - the sample exists only for the duration of one enrolment request;
 *  - it is never written to disk, never put in a log, a crash report, an
 *    analytics event, or a redux/devtools-visible store;
 *  - the buffer is overwritten (`.fill(0)`) as soon as it has been encoded;
 *  - no camera frame is retained after the capture session ends.
 * The core enforces what it can: `EnrolmentSample.dispose()` exists and the
 * client calls it in a `finally`, and nothing in this package ever logs a
 * sample.
 */
import type { BiometricSampleDto } from './wire.js';

export type BiometryKind = 'face' | 'fingerprint' | 'iris' | 'none';

export interface BiometricCapabilities {
  /** Hardware present and usable. */
  available: boolean;
  /** The citizen has actually enrolled a biometric in the OS. */
  enrolled: boolean;
  /**
   * Class 3 / "strong" biometry (Android BIOMETRIC_STRONG, iOS Face ID or
   * Touch ID). Only strong biometry may gate the signing key (05 §3) — a
   * device offering only weak biometry must not be enrolled at AL2+.
   */
  strong: boolean;
  kinds: BiometryKind[];
}

export interface BiometricConfirmSpec {
  title: string;
  subtitle?: string;
  cancelLabel: string;
}

export interface BiometricPrompt {
  capabilities(): Promise<BiometricCapabilities>;
  /**
   * Presentation-only confirmation. Returns false when the citizen cancels.
   * NEVER use the return value as authorisation for anything cryptographic —
   * use `KeyStore.sign`, which the platform binds to the key.
   */
  confirm(spec: BiometricConfirmSpec): Promise<boolean>;
}

/**
 * One captured biometric sample, owned by the caller and disposed by it.
 * `toDto()` may be called once; after `dispose()` both throw.
 */
export interface EnrolmentSample {
  /** Encode for the wire (base64 + liveness metadata). */
  toDto(): BiometricSampleDto;
  /** Zero the underlying buffer. Idempotent. Always called in a `finally`. */
  dispose(): void;
}

export interface FaceCaptureOptions {
  /** Localised on-screen instruction, e.g. "look at the camera and blink". */
  instruction: string;
  cancelLabel: string;
}

export interface FaceCapture {
  /**
   * Run a capture session with active liveness (ISO/IEC 30107 L2 — T8, 03 §2).
   * Throws MobileError('biometric_cancelled') if the citizen backs out.
   */
  capture(options: FaceCaptureOptions): Promise<EnrolmentSample>;
}
