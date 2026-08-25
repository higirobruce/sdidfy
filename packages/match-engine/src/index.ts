import type {
  BiometricReference,
  BiometricSample,
  MatchEngine,
  MatchResult,
  MatchScoreBand,
} from '@sdid/shared';
import { zeroize } from '@sdid/shared';

/**
 * Server-side PAD acceptance threshold (ISO/IEC 30107 L2 stand-in — spec 06 §2
 * T8, 10 Q7). A capture whose liveness score falls below this is treated as a
 * presentation attack and is never compared against the reference.
 */
export const PAD_THRESHOLD = 0.8;

/** Score-band thresholds for the mock comparator (audited coarse bands — 07 §4). */
const BAND_HIGH = 1;
const BAND_MEDIUM = 0.9;
const BAND_LOW = 0.75;

/**
 * MockMatchEngine — the Phase 0–2 stand-in for a vetted 1:1 matching SDK +
 * PAD evaluation (spec 03 §2 step 6b; replaced in Phase 3 per 06 §2 T18).
 *
 * Biometric discipline (07 §1 / T17 — non-negotiable):
 * - sample and reference bytes exist in memory only, for this one call;
 * - they are NEVER logged, persisted, or included in results/errors;
 * - both buffers are zeroized in a `finally`, on every path, including errors.
 */
export class MockMatchEngine implements MatchEngine {
  async match(sample: BiometricSample, reference: BiometricReference): Promise<MatchResult> {
    try {
      // 1. PAD first (T8): a spoofed capture must learn nothing about the
      //    match — the bytes are not compared at all when PAD fails.
      const padPassed =
        sample.liveness.method.length > 0 && sample.liveness.score >= PAD_THRESHOLD;
      if (!padPassed) {
        return { matched: false, scoreBand: 'no-match', padPassed: false };
      }

      // 2. 1:1 compare (mock format only). Anything malformed degrades to
      //    'no-match' — never a thrown error that could carry biometric content.
      const scoreBand = compareMockTemplates(sample, reference);
      const matched = scoreBand === 'high' || scoreBand === 'medium';
      return { matched, scoreBand, padPassed: true };
    } catch {
      // Defensive: no error object (which could reference biometric state)
      // ever propagates — rethrow a content-free failure.
      throw new Error('match-engine: internal matching error');
    } finally {
      // 3. Zeroize discipline (07 §1): always, on every path.
      zeroize(sample.data, reference.data);
    }
  }
}

/**
 * Mock 1:1 comparator: fraction of equal bytes over equal-length buffers.
 * Constant-time-style — the loop always walks the full length, no early exit,
 * so timing does not leak how far a template diverges (T18 hygiene, even in a
 * mock).
 */
function compareMockTemplates(
  sample: BiometricSample,
  reference: BiometricReference,
): MatchScoreBand {
  if (reference.format !== 'mock') return 'no-match';

  const a = sample.data;
  const b = reference.data;
  if (a.length !== b.length || a.length === 0) return 'no-match';

  let equal = 0;
  for (let i = 0; i < a.length; i++) {
    // Branch-free accumulate: 1 when bytes are equal, 0 otherwise.
    equal += (a[i]! ^ b[i]!) === 0 ? 1 : 0;
  }

  const f = equal / a.length;
  if (f === BAND_HIGH) return 'high';
  if (f >= BAND_MEDIUM) return 'medium'; // tolerates template noise
  if (f >= BAND_LOW) return 'low';
  return 'no-match';
}

/** Factory consumed by the broker's SdidModule (injection seam, 02 §4). */
export function createMatchEngine(): MatchEngine {
  return new MockMatchEngine();
}
