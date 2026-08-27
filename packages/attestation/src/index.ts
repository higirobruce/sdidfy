/**
 * @sdid/attestation — platform and hardware-key attestation for enrolment
 * (spec 03 §2 step 1, 05 §4, 06 T2/T3/T4, 10 #4).
 *
 * Public surface: build the verifier pair once at broker start-up, then call
 * `verify` per enrolment. The verifiers are pure with respect to time and
 * network (types.ts): the clock arrives on the request and Google's decode
 * call sits behind an injected seam.
 *
 * Configuration is validated eagerly here, because the failure modes of a
 * mis-set attestation config are silent and total: an empty
 * `certificateDigests` list would make the signing-certificate check vacuous
 * and accept any repackaged clone. Every such case throws at construction
 * rather than degrading at runtime.
 */

import { AppAttestVerifier } from './app-attest.js';
import { PlayIntegrityVerifier } from './play-integrity.js';
import { GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM } from './roots.js';
import { DEFAULT_MAX_TOKEN_AGE_MS, type AttestationVerifierConfig, type AttestationVerifiers } from './types.js';
import { parseTrustAnchors } from './x509.js';

export * from './types.js';
export { deriveAssuranceCap, type AssuranceInputs } from './assurance.js';
export {
  APP_ATTEST_FMT,
  APPLE_APP_ATTEST_NONCE_OID,
  AppAttestVerifier,
  type AppAttestVerifierOptions,
} from './app-attest.js';
export {
  APP_RECOGNITION_PLAY_RECOGNIZED,
  CLOCK_SKEW_TOLERANCE_MS,
  DEVICE_VERDICT_BASIC_INTEGRITY,
  DEVICE_VERDICT_DEVICE_INTEGRITY,
  DEVICE_VERDICT_STRONG_INTEGRITY,
  PlayIntegrityVerifier,
  type PlayIntegrityVerifierOptions,
} from './play-integrity.js';
export {
  ANDROID_KEY_ATTESTATION_OID,
  parseKeyDescription,
  verifyAndroidKeyAttestation,
  type AndroidKeyAttestationInput,
  type AndroidKeyAttestationOutcome,
  type KeyDescription,
} from './key-attestation.js';
export { APPLE_APP_ATTEST_ROOT_PEM, GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM } from './roots.js';
export { CborError, decodeCbor, type CborValue } from './cbor.js';
export { DerError, parseDer, type DerNode } from './der.js';

/** Thrown at construction when the deployment configuration cannot be trusted. */
export class AttestationConfigurationError extends Error {
  constructor(message: string) {
    super(`attestation configuration: ${message}`);
    this.name = 'AttestationConfigurationError';
  }
}

/**
 * Trust anchors that the contract in types.ts has no field for.
 *
 * iOS roots are configurable through `IosVerifierConfig.rootCertificatesPem`;
 * Android's are not, so they are supplied here instead of by widening the
 * frozen config type. Defaults to the pinned Google roots in roots.ts — read
 * that file's provenance header before production.
 */
export interface AttestationTrustAnchors {
  androidRootCertificatesPem?: readonly string[];
}

/**
 * Builds the per-platform verifiers.
 *
 * @throws AttestationConfigurationError when the configuration would weaken a
 * check rather than fail loudly.
 */
export function createAttestationVerifiers(
  config: AttestationVerifierConfig,
  trustAnchors: AttestationTrustAnchors = {},
): AttestationVerifiers {
  const { android, ios } = config;
  if (!android || typeof android !== 'object') {
    throw new AttestationConfigurationError('android config is missing');
  }
  if (!ios || typeof ios !== 'object') {
    throw new AttestationConfigurationError('ios config is missing');
  }

  if (typeof android.packageName !== 'string' || android.packageName.trim().length === 0) {
    throw new AttestationConfigurationError('android.packageName is required');
  }
  // The one that matters most: an empty digest list would make the
  // signing-certificate check pass for every app, including a repackaged
  // clone (T3). "Accept any" must never be reachable by omission.
  if (!Array.isArray(android.certificateDigests) || android.certificateDigests.length === 0) {
    throw new AttestationConfigurationError(
      'android.certificateDigests must list at least one signing-certificate digest',
    );
  }
  if (android.certificateDigests.some((digest) => typeof digest !== 'string' || digest.length === 0)) {
    throw new AttestationConfigurationError('android.certificateDigests contains an empty entry');
  }
  if (typeof android.decodeToken !== 'function') {
    throw new AttestationConfigurationError('android.decodeToken must be supplied');
  }

  if (typeof ios.appId !== 'string' || !/^[A-Za-z0-9]+\.[A-Za-z0-9.-]+$/.test(ios.appId)) {
    throw new AttestationConfigurationError('ios.appId must be "<teamId>.<bundleId>"');
  }
  if (typeof ios.production !== 'boolean') {
    // Defaulting this would mean guessing whether development builds are
    // acceptable — the wrong guess lets a dev-provisioned app enrol citizens.
    throw new AttestationConfigurationError('ios.production must be set explicitly');
  }

  const maxTokenAgeMs = config.maxTokenAgeMs ?? DEFAULT_MAX_TOKEN_AGE_MS;
  if (!Number.isFinite(maxTokenAgeMs) || maxTokenAgeMs <= 0) {
    throw new AttestationConfigurationError('maxTokenAgeMs must be a positive number of milliseconds');
  }

  const androidRootsPem = trustAnchors.androidRootCertificatesPem ?? GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM;
  let androidAnchors;
  try {
    androidAnchors = parseTrustAnchors(androidRootsPem);
  } catch (error) {
    throw new AttestationConfigurationError(
      `android trust anchors: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
  }

  let iosVerifier: AppAttestVerifier;
  try {
    iosVerifier = new AppAttestVerifier({ config: ios });
  } catch (error) {
    throw new AttestationConfigurationError(
      `ios trust anchors: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
  }

  return {
    android: new PlayIntegrityVerifier({ config: android, maxTokenAgeMs, trustAnchors: androidAnchors }),
    ios: iosVerifier,
  };
}
