/**
 * Play Integrity verification for Android (spec 05 §4, 06 T2/T3/T4, 10 #4).
 *
 * The token itself is decoded by Google (`decodeIntegrityToken`) behind the
 * injected `decodeToken` seam — see types.ts for why. What arrives back is an
 * `unknown` payload, and this file treats it as exactly that: every field is
 * shape-checked before it is read. A verdict payload is not a trusted object
 * merely because a Google API produced it; an upstream change, a stubbed
 * client, or a compromised credential must not be able to walk an unexpected
 * shape into an acceptance.
 *
 * Ordering is deliberate. Identity binding and nonce binding are checked
 * before the integrity verdicts, so a genuine token belonging to another app
 * or another enrolment session is rejected as what it is (`app_mismatch` /
 * `nonce_mismatch`), not mislabelled as a device problem.
 *
 * The rooted-device hole this file exists to close: `MEETS_BASIC_INTEGRITY`
 * alone is NOT sufficient. Basic integrity is satisfied by devices that are
 * rooted or fail Play certification; only `MEETS_DEVICE_INTEGRITY` (or the
 * stronger `MEETS_STRONG_INTEGRITY`) means an unmodified, Play-certified
 * device. Accepting basic integrity is the single most common Play Integrity
 * misconfiguration and it re-opens T2 completely.
 */

import type { X509Certificate } from 'node:crypto';

import { deriveAssuranceCap } from './assurance.js';
import { reject, stringsEqual } from './common.js';
import { verifyAndroidKeyAttestation } from './key-attestation.js';
import type {
  AndroidVerifierConfig,
  AttestationRequest,
  AttestationResult,
  AttestationVerifier,
  KeySecurityLevel,
} from './types.js';

/** The only app-recognition verdict that means "this is our Play build". */
export const APP_RECOGNITION_PLAY_RECOGNIZED = 'PLAY_RECOGNIZED';
/** Unmodified, Play-certified device. */
export const DEVICE_VERDICT_DEVICE_INTEGRITY = 'MEETS_DEVICE_INTEGRITY';
/** Hardware-backed, boot-verified device — strictly stronger than the above. */
export const DEVICE_VERDICT_STRONG_INTEGRITY = 'MEETS_STRONG_INTEGRITY';
/** Satisfied by rooted devices. Never sufficient on its own. */
export const DEVICE_VERDICT_BASIC_INTEGRITY = 'MEETS_BASIC_INTEGRITY';

/**
 * Tolerance for a device clock running ahead of ours. Small on purpose: it is
 * a grace window for skew, not a freshness extension (T4).
 */
export const CLOCK_SKEW_TOLERANCE_MS = 60 * 1000;

/** Longest token we will hand to the decoder; real tokens are a few KB. */
const MAX_TOKEN_CHARS = 64 * 1024;

export interface PlayIntegrityVerifierOptions {
  config: AndroidVerifierConfig;
  maxTokenAgeMs: number;
  /** Pinned Google hardware-attestation roots (roots.ts) for the key chain. */
  trustAnchors: readonly X509Certificate[];
}

/** Validated shape of the decoded Play Integrity payload. */
interface IntegrityPayload {
  requestPackageName: string;
  nonce: string;
  timestampMillis: number;
  appRecognitionVerdict: string;
  appPackageName?: string;
  certificateDigests: string[];
  versionCode?: string;
  deviceVerdicts: string[];
  appLicensingVerdict?: string;
}

export class PlayIntegrityVerifier implements AttestationVerifier {
  readonly platform = 'android' as const;

  constructor(private readonly options: PlayIntegrityVerifierOptions) {}

  async verify(request: AttestationRequest): Promise<AttestationResult> {
    try {
      return await this.verifyInner(request);
    } catch (error) {
      // Fail closed (types.ts): an unexpected fault in the verifier is a
      // retryable non-answer, never an acceptance. The detail is
      // operator-facing only (03 §7).
      return reject('verifier_unavailable', `android verifier fault: ${describe(error)}`);
    }
  }

  private async verifyInner(request: AttestationRequest): Promise<AttestationResult> {
    const { config, maxTokenAgeMs } = this.options;

    if (typeof request.token !== 'string' || request.token.length === 0) {
      return reject('malformed', 'play integrity token is missing');
    }
    if (request.token.length > MAX_TOKEN_CHARS) {
      return reject('malformed', 'play integrity token is implausibly large');
    }
    if (typeof request.expectedNonce !== 'string' || request.expectedNonce.length === 0) {
      // A caller bug, but the safe reading is "no nonce was bound", which is
      // the T4 hole itself. Refuse rather than compare against nothing.
      return reject('nonce_mismatch', 'no expected nonce was supplied');
    }

    // 1. Decode. Any failure of Google's service is `verifier_unavailable`:
    //    we would rather block an enrolment than guess a verdict.
    let decoded: unknown;
    try {
      decoded = await config.decodeToken(request.token);
    } catch (error) {
      return reject('verifier_unavailable', `play integrity decode failed: ${describe(error)}`);
    }

    // 2. Validate the shape ourselves before reading a single field.
    let payload: IntegrityPayload;
    try {
      payload = parseIntegrityPayload(decoded);
    } catch (error) {
      return reject('malformed', `play integrity payload: ${describe(error)}`);
    }

    // 3. Identity binding — is this token about OUR app at all?
    if (payload.requestPackageName !== config.packageName) {
      return reject(
        'app_mismatch',
        `token was issued for package ${payload.requestPackageName}, expected ${config.packageName}`,
      );
    }

    // 4. Nonce binding (T4). Constant-time: an early-exit compare leaks the
    //    nonce a byte at a time to an attacker who can retry.
    if (!stringsEqual(payload.nonce, request.expectedNonce)) {
      return reject('nonce_mismatch', 'token nonce is not the nonce we issued');
    }

    // 5. Freshness (T4). Both directions: a token from the future is either a
    //    broken clock or a forged timestamp, and neither should extend the
    //    replay window.
    const age = request.now - payload.timestampMillis;
    if (age < -CLOCK_SKEW_TOLERANCE_MS) {
      return reject('stale', `token timestamp is ${-age}ms in the future`);
    }
    if (age > maxTokenAgeMs) {
      return reject('stale', `token is ${age}ms old, limit ${maxTokenAgeMs}ms`);
    }

    // 6. App integrity — the recognised Play build, signed by our certificate.
    if (payload.appRecognitionVerdict !== APP_RECOGNITION_PLAY_RECOGNIZED) {
      return reject(
        'app_integrity',
        `app recognition verdict is ${payload.appRecognitionVerdict}, expected ${APP_RECOGNITION_PLAY_RECOGNIZED}`,
      );
    }
    if (payload.appPackageName !== undefined && payload.appPackageName !== config.packageName) {
      return reject(
        'app_mismatch',
        `appIntegrity names package ${payload.appPackageName}, expected ${config.packageName}`,
      );
    }
    if (!payload.certificateDigests.some((digest) => config.certificateDigests.includes(digest))) {
      // Same package name, different signing key = a repackaged clone (T3).
      return reject('app_mismatch', 'app signing certificate digest is not one of ours');
    }

    // 7. Device integrity. See the file header: basic integrity is not enough.
    const meetsDevice =
      payload.deviceVerdicts.includes(DEVICE_VERDICT_DEVICE_INTEGRITY) ||
      payload.deviceVerdicts.includes(DEVICE_VERDICT_STRONG_INTEGRITY);
    if (!meetsDevice) {
      return reject(
        'device_integrity',
        `device verdicts [${payload.deviceVerdicts.join(', ')}] do not include ${DEVICE_VERDICT_DEVICE_INTEGRITY}`,
      );
    }

    // 8. Hardware key attestation — the independent second question (05 §3).
    //    Absent evidence is a downgrade to AL1, contradictory evidence is a
    //    rejection (06 §6).
    let keySecurityLevel: KeySecurityLevel = 'software';
    let keyEvidence: Record<string, unknown> = { keyAttestationPresent: false };
    if (typeof request.keyAttestation === 'string' && request.keyAttestation.length > 0) {
      const outcome = verifyAndroidKeyAttestation({
        keyAttestation: request.keyAttestation,
        expectedNonce: request.expectedNonce,
        devicePublicKeyJwk: request.devicePublicKeyJwk,
        packageName: config.packageName,
        certificateDigests: config.certificateDigests,
        now: request.now,
        trustAnchors: this.options.trustAnchors,
      });
      if (!outcome.ok) return reject(outcome.code, outcome.detail);
      keySecurityLevel = outcome.keySecurityLevel;
      keyEvidence = { keyAttestationPresent: true, ...outcome.evidence };
    }

    return {
      ok: true,
      platform: 'android',
      appGenuine: true,
      keySecurityLevel,
      assuranceCap: deriveAssuranceCap({
        appGenuine: true,
        keySecurityLevel,
        requireStrongBox: config.requireStrongBox === true,
      }),
      evidence: {
        // Non-sensitive verdict facts only — never the token, the chain, or
        // any citizen identifier (07 §3).
        appRecognitionVerdict: payload.appRecognitionVerdict,
        deviceRecognitionVerdict: payload.deviceVerdicts,
        appLicensingVerdict: payload.appLicensingVerdict ?? null,
        packageName: payload.requestPackageName,
        appVersionCode: payload.versionCode ?? null,
        tokenAgeMs: age,
        keySecurityLevel,
        ...keyEvidence,
      },
    };
  }
}

/**
 * Hand-written schema check for the decoded payload.
 *
 * Notes on Google's actual shapes, each of which has bitten integrations:
 *   - the API response wraps the verdict in `tokenPayloadExternal`; some
 *     clients unwrap it and some do not, so both are accepted here;
 *   - `timestampMillis` is an int64 and therefore arrives as a *string* in
 *     JSON;
 *   - `deviceRecognitionVerdict` is ABSENT (not empty, not null) for a device
 *     that meets nothing — that is a failing device, not a malformed payload,
 *     so it must reach the device-integrity check rather than being rejected
 *     as garbage.
 */
function parseIntegrityPayload(decoded: unknown): IntegrityPayload {
  const root = asObject(decoded, 'payload');
  const body = 'tokenPayloadExternal' in root ? asObject(root.tokenPayloadExternal, 'tokenPayloadExternal') : root;

  const requestDetails = asObject(body.requestDetails, 'requestDetails');
  const appIntegrity = asObject(body.appIntegrity, 'appIntegrity');
  const deviceIntegrity = asObject(body.deviceIntegrity, 'deviceIntegrity');

  const digests = optionalStringArray(appIntegrity.certificateSha256Digest, 'certificateSha256Digest');
  const deviceVerdicts = optionalStringArray(deviceIntegrity.deviceRecognitionVerdict, 'deviceRecognitionVerdict');

  const payload: IntegrityPayload = {
    requestPackageName: asString(requestDetails.requestPackageName, 'requestPackageName'),
    nonce: asString(requestDetails.nonce, 'nonce'),
    timestampMillis: asEpochMillis(requestDetails.timestampMillis, 'timestampMillis'),
    appRecognitionVerdict: asString(appIntegrity.appRecognitionVerdict, 'appRecognitionVerdict'),
    certificateDigests: digests ?? [],
    deviceVerdicts: deviceVerdicts ?? [],
  };

  if (appIntegrity.packageName !== undefined) {
    payload.appPackageName = asString(appIntegrity.packageName, 'appIntegrity.packageName');
  }
  if (appIntegrity.versionCode !== undefined) {
    payload.versionCode = String(appIntegrity.versionCode);
  }
  if (body.accountDetails !== undefined) {
    const accountDetails = asObject(body.accountDetails, 'accountDetails');
    if (accountDetails.appLicensingVerdict !== undefined) {
      // Recorded for audit only. Licensing is a distribution signal, not a
      // security control, and must never gate a citizen's enrolment.
      payload.appLicensingVerdict = asString(accountDetails.appLicensingVerdict, 'appLicensingVerdict');
    }
  }
  return payload;
}

function asObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${what} is not a string`);
  return value;
}

function optionalStringArray(value: unknown, what: string): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) throw new Error(`${what} is not an array`);
  if (value.length > 64) throw new Error(`${what} has an implausible number of entries`);
  return value.map((entry, index) => asString(entry, `${what}[${index}]`));
}

/** int64 epoch milliseconds, arriving as a JSON string or (rarely) a number. */
function asEpochMillis(value: unknown, what: string): number {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${what} is not a valid timestamp`);
    return value;
  }
  if (typeof value === 'string' && /^[0-9]{1,15}$/.test(value)) {
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${what} is not a valid timestamp`);
    return parsed;
  }
  throw new Error(`${what} is not a valid timestamp`);
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
