import { createHash } from 'node:crypto';

/**
 * DEV/MOCK ONLY (Phases 0–2, spec 02 §2): the canonical mock biometric bytes
 * for a test identity. MockSdidStrategy derives the "NIDA reference" from
 * this, and the device simulator derives the "captured sample" from it, so a
 * genuine enrolment matches deterministically and an impostor (different
 * NID) does not. Real strategies never touch this.
 */
export function mockBiometricBytes(nid: string, modality: 'face' | 'fingerprint'): Uint8Array {
  return new Uint8Array(createHash('sha256').update(`mock-biometric:${modality}:${nid}`).digest());
}

/** Seeded test identities the mock SDID knows (02 §2). Any other NID is unknown. */
export const MOCK_TEST_NIDS = [
  '1199012345678901',
  '1199012345678902',
  '1199012345678903',
  '1198567890123401',
  '1197033322211105',
] as const;
