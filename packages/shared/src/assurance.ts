/** Assurance levels (spec 03 §3). Carried on bindings and into tokens as `acr`. */
export const ASSURANCE_LEVELS = ['AL1', 'AL2', 'AL3'] as const;
export type AssuranceLevel = (typeof ASSURANCE_LEVELS)[number];

const AL_RANK: Record<AssuranceLevel, number> = { AL1: 1, AL2: 2, AL3: 3 };

/** True when `actual` satisfies a required minimum assurance level. */
export function alMeets(actual: AssuranceLevel, min: AssuranceLevel): boolean {
  return AL_RANK[actual] >= AL_RANK[min];
}

export function alRank(level: AssuranceLevel): number {
  return AL_RANK[level];
}
