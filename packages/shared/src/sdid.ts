import type { AssuranceLevel } from './assurance.js';

/** Biometric modalities (Q5: face + fingerprint). */
export type BiometricModality = 'face' | 'fingerprint';

/**
 * A reference biometric fetched from NIDA (format TBD by SDID — A2).
 * CARDINAL RULE (07 §1): instances live in memory only, for the duration of a
 * single match, and MUST be zeroed via `zeroize()` immediately after use.
 * Never log, persist, cache, or serialise the `data` field.
 */
export interface BiometricReference {
  modality: BiometricModality;
  /** Opaque template/image bytes. Format pending SDID answer A2. */
  data: Uint8Array;
  format: 'iso-19794' | 'jpeg2000' | 'mock';
}

/** A captured sample submitted at enrolment. Same in-memory-only discipline. */
export interface BiometricSample {
  modality: BiometricModality;
  data: Uint8Array;
  /** Client-side liveness signal accompanying the capture (PAD input). */
  liveness: {
    method: string;
    score: number; // 0..1 client-reported; server-side PAD re-evaluates
  };
}

/** Overwrite biometric bytes in place. Call in a `finally` around every match. */
export function zeroize(...buffers: Array<Uint8Array | undefined>): void {
  for (const b of buffers) {
    if (b) b.fill(0);
  }
}

/** Minimal attribute set we are authorised to receive (Q9). Fetched on demand, not warehoused. */
export interface AttributeSet {
  name?: string;
  dateOfBirth?: string; // ISO date
  address?: string;
  /** Face reference presence indicator only — never the bytes at rest. */
  faceReferenceAvailable?: boolean;
}

export interface ReferenceBiometricResult {
  reference: BiometricReference;
  /** SDID-side stable subject identifier; mapped to our pseudonymised-NID key. */
  sdidSubject: string;
  /** SDID-side transaction reference, propagated into the audit trail. */
  txnRef: string;
}

export interface ReassertResult {
  valid: boolean;
  assurance: AssuranceLevel;
  txnRef: string;
}

/**
 * The stable internal interface the Broker depends on (spec 02 §1).
 * Strategies: MockSdidStrategy (Phases 0–2), OidcEsignetStrategy or
 * ProprietaryRestStrategy (Phase 3, pending A1). The Broker never imports
 * anything SDID-specific — only this contract.
 */
export interface SdidProvider {
  getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult>;

  getAttributes(nid: string, scopes: string[]): Promise<AttributeSet>;

  /** Periodic re-verification — also the revoked/deceased-identity signal (Q12). */
  reassert(nid: string): Promise<ReassertResult>;
}

export type SdidStrategyName = 'mock' | 'oidc' | 'proprietary';
