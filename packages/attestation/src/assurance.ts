/**
 * Assurance derivation (spec 03 §3, 06 §6).
 *
 * One function, used by both platform verifiers, so the AL2 bar cannot drift
 * apart between Android and iOS. The cap is *derived* from proven facts and is
 * never something a caller — or a client — can assert (types.ts).
 *
 * AL2 needs both halves of the attestation story: a genuine app on a sound
 * device AND a key proven to live in secure hardware. A sound device holding a
 * software key is AL1: usable for low-risk services, not for the default
 * assurance tier. AL3 is out of reach from attestation alone — it additionally
 * requires SDID re-assertion at auth time (03 §6), so this never returns it.
 */

import type { KeySecurityLevel } from './types.js';

export interface AssuranceInputs {
  /** Platform attestation passed: genuine app, sound device. */
  appGenuine: boolean;
  /** Proven protection level of the key being enrolled. */
  keySecurityLevel: KeySecurityLevel;
  /**
   * Deployment policy: require a discrete secure element rather than any TEE.
   * Off by default — StrongBox is absent from much of the Android install base
   * and a blanket requirement would exclude many citizens (08 inclusion).
   */
  requireStrongBox?: boolean;
}

export function deriveAssuranceCap(inputs: AssuranceInputs): 'AL1' | 'AL2' {
  if (!inputs.appGenuine) return 'AL1';
  if (inputs.requireStrongBox) {
    return inputs.keySecurityLevel === 'strongbox' ? 'AL2' : 'AL1';
  }
  return inputs.keySecurityLevel === 'software' ? 'AL1' : 'AL2';
}
