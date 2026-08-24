import type { BiometricReference, BiometricSample } from './sdid.js';

/** Coarse score band logged to audit (07 §4) — never a raw score tied to a biometric. */
export type MatchScoreBand = 'high' | 'medium' | 'low' | 'no-match';

export interface MatchResult {
  matched: boolean;
  scoreBand: MatchScoreBand;
  /** Presentation-attack detection outcome (ISO/IEC 30107 L2 target — Q7). */
  padPassed: boolean;
}

/**
 * 1:1 biometric match + PAD (spec: we match ourselves — Q2).
 * Implementations MUST treat sample and reference as in-memory-only and
 * zeroize both before resolving (07 §1 / T17). The engine never logs,
 * persists, or re-emits biometric bytes — only the MatchResult survives.
 */
export interface MatchEngine {
  match(sample: BiometricSample, reference: BiometricReference): Promise<MatchResult>;
}
