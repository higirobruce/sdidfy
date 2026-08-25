# @sdid/match-engine

The 1:1 biometric match + PAD engine for the SDID Authentication Bridge
(spec `03` §2 step 6b): at enrolment, the broker hands it the captured
sample and the NIDA reference template, and it returns a `MatchResult`
(`matched`, coarse `scoreBand`, `padPassed`) — nothing else.

## What this mock stands in for

`MockMatchEngine` is the **Phase 0–2 stand-in** (no SDID sandbox exists, so
everything upstream of the adapter is built against mocks):

- **PAD**: a threshold check on the client-reported liveness score
  (`PAD_THRESHOLD = 0.8`) stands in for real ISO/IEC 30107 Level 2
  presentation-attack detection. PAD is evaluated **before** any byte
  comparison, so a spoofed capture learns nothing about the match (T8).
- **Matching**: mock templates (`format: 'mock'`, from `mockBiometricBytes`)
  are compared as fraction-of-equal-bytes over a full-length, no-early-exit
  loop, mapped to the audited score bands: `high` (identical), `medium`
  (≥ 0.9 — tolerates template noise, still a match), `low` (≥ 0.75), else
  `no-match`. Length mismatches, empty buffers, and non-`mock` formats
  degrade to `no-match` — never a thrown error carrying biometric content.

## Phase 3 plan

Per spec `06` §2 T18 and `09` Phase 3, this mock is replaced behind the same
`MatchEngine` contract by:

- a **vetted commercial/certified matching SDK** operating on NIDA's real
  reference format (ISO 19794 template or image — pending SDID answer A2),
  with score-band thresholds tuned and audited;
- **real PAD at ISO/IEC 30107 Level 2**, evaluated server-side, with a
  formal PAD/liveness evaluation as part of the pre-prod security gate.

The broker consumes only `createMatchEngine(): MatchEngine`, so the swap
changes nothing outside this package.

## Zeroize / in-memory contract (spec `07` §1 — non-negotiable)

Sample and reference bytes exist **in memory only, for the duration of one
`match()` call**:

- both buffers are zeroized (`zeroize()` from `@sdid/shared`) in a `finally`
  block — on success, on PAD failure, and on error;
- bytes are **never** logged, persisted, cached, or included in any result
  or thrown error; only the coarse `MatchResult` survives the call;
- callers must treat their buffers as consumed (zeroed) after `match()`
  resolves.

The test suite asserts the zeroize discipline on every path, including the
PAD-fail and malformed-input paths.
