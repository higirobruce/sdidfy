import { Injectable } from '@nestjs/common';
import { BridgeError, type AssuranceLevel } from '@sdid/shared';
import { loadConfig } from '../config.js';

export interface AttestationVerdict {
  acceptable: boolean;
  hardwareBacked: boolean;
  platform: string;
  /** Highest assurance this device can carry (06 §6 — degradation mapping). */
  assuranceCap: AssuranceLevel;
  detail: Record<string, unknown>;
}

/**
 * Device/app attestation verification (03 §2 step 1, 05 §4, T2/T3).
 *
 * ATTESTATION_MODE=mock accepts the simulator's structured mock tokens so the
 * trust chain is exercised end-to-end in Phases 0–2. Production
 * (ATTESTATION_MODE=strict) requires real Play Integrity / App Attest
 * verifiers — this seam is where they plug in (open decision #4 for the
 * exact tiering policy).
 */
@Injectable()
export class AttestationService {
  async verify(attestation: {
    platform: string;
    token: string;
    keyAttestation?: string;
  }): Promise<AttestationVerdict> {
    const mode = loadConfig().ATTESTATION_MODE;
    if (mode === 'strict') {
      // Phase 3: PlayIntegrityVerifier / AppAttestVerifier land here.
      throw new BridgeError('attestation_rejected', 'Strict attestation not yet available', 501);
    }
    return this.verifyMock(attestation);
  }

  private verifyMock(attestation: { platform: string; token: string; keyAttestation?: string }): AttestationVerdict {
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
