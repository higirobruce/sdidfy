import type { Provider } from '@nestjs/common';
import {
  createAttestationVerifiers,
  type AttestationVerifierConfig,
  type AttestationVerifiers,
} from '@sdid/attestation';
import { androidCertificateDigests, loadConfig } from '../config.js';
import { createPlayIntegrityDecoder } from './play-integrity.decoder.js';

/**
 * DI token for the platform verifier set. Injecting the verifiers instead of
 * constructing them inside `AttestationService` gives tests one clean seam to
 * override — they stub `AttestationVerifier.verify` at the module boundary and
 * never reach into `@sdid/attestation` internals, exactly as a real Play
 * Integrity / App Attest outage or verdict would arrive.
 */
export const ATTESTATION_VERIFIERS = Symbol('ATTESTATION_VERIFIERS');

export interface AttestationVerifierSource {
  /** Built on first use — never at boot, so mock mode needs no real config. */
  get(): AttestationVerifiers;
}

export function buildVerifierConfig(): AttestationVerifierConfig {
  const config = loadConfig();
  return {
    android: {
      packageName: config.ANDROID_PACKAGE_NAME,
      certificateDigests: androidCertificateDigests(config),
      decodeToken: createPlayIntegrityDecoder({
        packageName: config.ANDROID_PACKAGE_NAME,
        credentialsJson: config.PLAY_INTEGRITY_CREDENTIALS_JSON,
      }),
    },
    ios: {
      appId: config.IOS_APP_ID,
      production: config.IOS_ATTESTATION_PRODUCTION,
    },
  };
}

/**
 * Config-driven verifiers, memoised after the first successful build. A
 * construction failure (e.g. no certificate digests configured) is NOT cached:
 * it surfaces on every attempt so the operator sees it until it is fixed, and
 * it can never be mistaken for an acceptance.
 */
export class ConfiguredAttestationVerifiers implements AttestationVerifierSource {
  private cached?: AttestationVerifiers;

  get(): AttestationVerifiers {
    if (!this.cached) this.cached = createAttestationVerifiers(buildVerifierConfig());
    return this.cached;
  }
}

export const attestationVerifiersProvider: Provider = {
  provide: ATTESTATION_VERIFIERS,
  useFactory: (): AttestationVerifierSource => new ConfiguredAttestationVerifiers(),
};
