import type { PlayIntegrityTokenDecoder } from '@sdid/attestation';

/**
 * Play Integrity token decode seam (05 §4).
 *
 * Google's supported path for reading an integrity verdict is a *server-side*
 * call — `POST playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken`
 * — authenticated with a GCP service account that has the Play Integrity API
 * enabled for our app. Local JWE decryption with the app-managed keys is the
 * unsupported alternative and is not what we will ship.
 *
 * ============================ UNIMPLEMENTED =============================
 * GoR service-account credentials for the Play console project do not exist
 * yet, so this decoder deliberately THROWS rather than pretending. The
 * `@sdid/attestation` Android verifier fails closed on a throwing decoder
 * (`verifier_unavailable` → retryable 503), so a misconfigured broker refuses
 * enrolments instead of accepting unverified tokens.
 *
 * Swapping in the real client is a one-function change: implement
 * `createPlayIntegrityDecoder` to return a function that POSTs the token and
 * resolves the raw `tokenPayloadExternal` object. Return the response
 * unvalidated — the verifier owns schema validation on purpose, so a changed
 * or compromised upstream shape cannot walk into a verdict.
 * ========================================================================
 */
export function createPlayIntegrityDecoder(options: {
  packageName: string;
  /** Path to, or inline blob of, the service-account JSON. */
  credentialsJson: string;
}): PlayIntegrityTokenDecoder {
  return async (_token: string): Promise<unknown> => {
    throw new Error(
      'Play Integrity decode is not implemented: no GoR service-account credentials are wired ' +
        `(package=${options.packageName || '<unset>'}, credentials=${
          options.credentialsJson ? 'configured' : 'unset'
        }). Implement createPlayIntegrityDecoder in ` +
        'apps/broker/src/trust/play-integrity.decoder.ts before enabling ATTESTATION_MODE=strict on Android.',
    );
  };
}
