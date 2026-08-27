import { Inject, Injectable, Logger } from '@nestjs/common';
import { BridgeError, type AssuranceLevel } from '@sdid/shared';
import type {
  AttestationRejectionCode,
  AttestationRequest,
  AttestationResult,
} from '@sdid/attestation';
import { loadConfig } from '../config.js';
import { MetricsService } from '../observability/metrics.service.js';
import { ChallengeService } from './challenge.service.js';
import {
  ATTESTATION_VERIFIERS,
  type AttestationVerifierSource,
} from './attestation-verifiers.provider.js';

export interface AttestationVerdict {
  acceptable: boolean;
  hardwareBacked: boolean;
  platform: string;
  /** Highest assurance this device can carry (06 §6 — degradation mapping). */
  assuranceCap: AssuranceLevel;
  detail: Record<string, unknown>;
  /**
   * Non-sensitive facts from the verifier, persisted on the binding's
   * `attestation` JSONB for later policy review (07). Never raw tokens or
   * certificates. Absent in mock mode.
   */
  evidence?: Record<string, unknown>;
}

/**
 * The ONE client-visible reason for any strict-mode attestation refusal.
 * 03 §7: a precise reason ("your device is rooted", "nonce replayed", "app
 * signature unknown") tells an attacker exactly which control to defeat next,
 * so every refusal looks identical from outside. The precise code + detail go
 * to the audit record and the server log — nowhere else.
 */
const GENERIC_REJECTION_MESSAGE = 'Device attestation could not be verified';

/** Public key shape the verifier binds the key attestation to. */
export type DevicePublicKeyJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };

export interface AttestationInput {
  platform: string;
  token: string;
  keyAttestation?: string;
  /** Id of the single-use nonce minted by /v1/enrol/attestation-challenge. */
  nonceId?: string;
}

/**
 * A strict-mode refusal. Client-visible fields are deliberately uniform; the
 * precise `rejectionCode`/`rejectionDetail` ride along for the audit trail and
 * are never serialised into the HTTP body (the error filter only reads
 * `code`/`message`).
 */
export class AttestationRejectionError extends BridgeError {
  constructor(
    readonly rejectionCode: AttestationRejectionCode,
    readonly rejectionDetail: string,
  ) {
    super('attestation_rejected', GENERIC_REJECTION_MESSAGE, 403);
  }
}

/**
 * Device/app attestation verification (03 §2 step 1, 05 §4, T2/T3/T4).
 *
 * ATTESTATION_MODE=mock accepts the simulator's structured mock tokens so the
 * trust chain is exercised end-to-end in Phases 0–2. ATTESTATION_MODE=strict
 * runs the real Play Integrity / App Attest verifiers from `@sdid/attestation`
 * and enforces all three bindings that make a verdict mean anything:
 *
 *   - **nonce** — a single-use, server-issued nonce consumed here (GETDEL)
 *     before the verifier is called, and matched *inside* the signed token by
 *     the verifier. Without it, a token harvested from one genuine device
 *     replays from an attacker's device forever (T4).
 *   - **key** — the hardware key attestation must cover the public key being
 *     enrolled, so an attacker cannot attest a hardware key and then enrol a
 *     software-held one. Hence `verify()` takes the JWK.
 *   - **identity** — the token must name our app (package + signing digest, or
 *     App ID); enforced inside the verifiers from broker config.
 */
@Injectable()
export class AttestationService {
  private readonly logger = new Logger(AttestationService.name);

  constructor(
    private readonly challenges: ChallengeService,
    private readonly metrics: MetricsService,
    @Inject(ATTESTATION_VERIFIERS) private readonly verifiers: AttestationVerifierSource,
  ) {}

  async verify(
    attestation: AttestationInput,
    devicePublicKeyJwk: DevicePublicKeyJwk,
  ): Promise<AttestationVerdict> {
    const mode = loadConfig().ATTESTATION_MODE;
    // Metrics are recorded on every path — accepted, rejected (with the
    // verifier's code, which is a bounded enum) and unavailable. Splitting
    // "we refused this device" from "we could not check" is the difference
    // between an attack and a platform outage, and an operator must be able
    // to tell them apart from the dashboard alone.
    try {
      const verdict =
        mode === 'strict'
          ? await this.verifyStrict(attestation, devicePublicKeyJwk)
          : await this.verifyMock(attestation);
      this.metrics.recordAttestationVerdict({
        platform: verdict.platform,
        mode,
        outcome: 'accepted',
      });
      return verdict;
    } catch (err) {
      const outcome =
        err instanceof BridgeError && err.code === 'attestation_unavailable'
          ? 'unavailable'
          : 'rejected';
      this.metrics.recordAttestationVerdict({
        platform: attestation.platform,
        mode,
        outcome,
        ...(err instanceof AttestationRejectionError ? { code: err.rejectionCode } : {}),
      });
      throw err;
    }
  }

  // --- strict -------------------------------------------------------------

  private async verifyStrict(
    attestation: AttestationInput,
    devicePublicKeyJwk: DevicePublicKeyJwk,
  ): Promise<AttestationVerdict> {
    if (attestation.platform !== 'android' && attestation.platform !== 'ios') {
      // 'sim' is a mock-mode-only platform; in strict it is not our app.
      throw this.reject('app_mismatch', `unsupported platform '${attestation.platform}' in strict mode`);
    }
    if (!attestation.nonceId) {
      throw this.reject('nonce_mismatch', 'attestation.nonceId is required in strict mode');
    }

    // Single-use: consumed atomically (GETDEL) BEFORE verification, so a
    // replayed nonceId is dead even if the token verifies perfectly, and even
    // under concurrent requests. A failed verification does not give the
    // nonce back — the client mints a fresh one.
    let expectedNonce: string;
    try {
      expectedNonce = await this.challenges.consumeAttestationNonce(attestation.nonceId);
    } catch {
      throw this.reject('nonce_mismatch', 'unknown, expired, or already-used attestation nonce');
    }

    const request: AttestationRequest = {
      token: attestation.token,
      ...(attestation.keyAttestation !== undefined
        ? { keyAttestation: attestation.keyAttestation }
        : {}),
      expectedNonce,
      devicePublicKeyJwk,
      now: Date.now(),
    };

    let result: AttestationResult;
    try {
      result = await this.verifiers.get()[attestation.platform].verify(request);
    } catch (err) {
      // Fail closed: an exception is never an acceptance. A throwing verifier
      // (unbuilt Play Integrity client, credential failure, config error) is
      // an availability problem, so it is retryable — not a refusal of this
      // citizen's device.
      this.logger.error(
        `attestation verifier threw (platform=${attestation.platform}): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      throw this.unavailable();
    }

    if (!result.ok) {
      if (result.code === 'verifier_unavailable') {
        this.logger.error(`attestation verifier unavailable: ${result.detail}`);
        throw this.unavailable();
      }
      throw this.reject(result.code, result.detail);
    }

    const hardwareBacked = result.keySecurityLevel !== 'software';
    return {
      acceptable: true,
      hardwareBacked,
      platform: result.platform,
      assuranceCap: result.assuranceCap,
      detail: {
        mode: 'strict',
        keySecurityLevel: result.keySecurityLevel,
        appGenuine: result.appGenuine,
        hardwareBacked,
      },
      evidence: result.evidence,
    };
  }

  private reject(code: AttestationRejectionCode, detail: string): AttestationRejectionError {
    // Operator-facing only. The HTTP body stays uniform (03 §7).
    this.logger.warn(`attestation rejected: code=${code} detail=${detail}`);
    return new AttestationRejectionError(code, detail);
  }

  /**
   * Retryable 503, never a refusal: treating "we could not check" as "the
   * device failed" would lock out genuine citizens during a platform outage,
   * and treating it as acceptance would be the bypass itself.
   */
  private unavailable(): BridgeError {
    return new BridgeError(
      'attestation_unavailable',
      'Attestation verification is temporarily unavailable; retry shortly',
      503,
    );
  }

  // --- mock (Phases 0–2: device-sim, e2e, ghost-login demo) ---------------

  private async verifyMock(attestation: AttestationInput): Promise<AttestationVerdict> {
    // A nonce is never required in mock mode, but when a client supplies one
    // we burn it so the simulator exercises the production shape end-to-end.
    // Failure to consume is ignored on purpose: mock mode's behaviour must be
    // byte-for-byte what it was before nonces existed.
    if (attestation.nonceId) {
      try {
        await this.challenges.consumeAttestationNonce(attestation.nonceId);
      } catch {
        this.logger.debug('mock attestation: supplied nonceId was not consumable (ignored)');
      }
    }

    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(Buffer.from(attestation.token, 'base64url').toString('utf8'));
    } catch {
      throw new BridgeError('attestation_rejected', 'Malformed attestation token', 400);
    }
    if (claims['mock'] !== true) {
      throw new BridgeError('attestation_rejected', 'Not a mock attestation token', 400);
    }
    const deviceIntegrity = claims['deviceIntegrity'] === true;
    const appIntegrity = claims['appIntegrity'] === true;
    const hardwareBacked = claims['hardwareBackedKey'] === true;
    // Enrolment policy (10 #4): rooted/emulated devices are refused outright.
    if (!deviceIntegrity || !appIntegrity) {
      throw new BridgeError('attestation_rejected', 'Device failed integrity checks', 403);
    }
    // Tiered assurance (03 §3): hardware-backed key + key attestation → AL2;
    // AL3 additionally requires SDID re-assertion at auth time, so the cap
    // from attestation alone is AL2 vs AL1.
    const assuranceCap: AssuranceLevel = hardwareBacked && attestation.keyAttestation ? 'AL2' : 'AL1';
    return {
      acceptable: true,
      hardwareBacked,
      platform: attestation.platform,
      assuranceCap,
      detail: { deviceIntegrity, appIntegrity, hardwareBacked, mode: 'mock' },
    };
  }
}
