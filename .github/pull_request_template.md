<!--
Keep this short. The checklist exists because this service authenticates
citizens against the national identity register; the boxes are the things a
reviewer cannot infer from the diff. Delete the sections that don't apply.
Full guidance: docs/CONTRIBUTING.md.
-->

## What and why

<!-- One paragraph. Cite the spec section this implements — e.g. (04 §3) — or
     the threat it mitigates — e.g. T4. -->

## How it was verified

<!-- Which layer: unit / protocol / e2e / the ghost-login demo. Say what you
     actually ran, not what should pass. -->

- [ ] `pnpm verify` passes locally (typecheck, build, test, ghost-login demo)

---

## Non-negotiables

Tick only what applies. If none apply, say so and delete the rest.

**Touches biometrics** (enrolment, match engine, the capture path)

- [ ] No sample or reference template is written to Postgres, Redis, a file, a
      cache, a metric, an HTTP response, or a log (07 §1)
- [ ] Every buffer is zeroized on **every** path, including the error path
- [ ] Only the match *outcome* — pass/fail plus a score band — is audited (07 §4)

**Touches the audit trail**

- [ ] Insert-only: no UPDATE, no DELETE, no TRUNCATE, and the guard triggers
      are intact (07 §4)
- [ ] The new event chains: `prev_hash`/`hash` are computed the same way as
      every other event, and `/admin/audit/verify` still reports `intact: true`
- [ ] No raw NID and no biometric value in `subject_ref`, `context`, or
      `match_result` — the pseudonymised NID is the identity reference (Q8)

**Touches tokens, keys or sessions**

- [ ] Subjects are pairwise per RP; nothing leaks a cross-RP identifier (04 §4)
- [ ] Lifetimes are unchanged, or the change is recorded in docs/DECISIONS.md
- [ ] Fail-closed: a missing or unparseable input is a rejection, never a
      default-allow
- [ ] Nothing new is signed with, or derived from, a key outside the keystore

**Touches the schema**

- [ ] Forward-only migration, additive, safe to apply to a live database
- [ ] No column that stores a biometric artefact or a raw NID
- [ ] Applied and re-applied cleanly against an empty database
      (the `db-integrity` CI job proves this)

**Touches SDID**

- [ ] SDID is reached through `packages/sdid-adapter` only — nothing else in
      the repo speaks its protocol (02 §4)
- [ ] Both strategies still satisfy the shared contract tests

---

- [ ] Config/env changes are reflected in `.env.example` **and**
      `docs/runbook.md` §2
- [ ] New boundaries validate their input with zod
- [ ] Comments cite the spec section or threat id they implement

<!--
The CI guard (.github/scripts/guard-non-negotiables.mjs) checks a lexical
subset of the above and nothing more. A green CI run is not a substitute for
ticking these boxes honestly — see the "WHAT THIS DOES NOT CATCH" section at
the bottom of that script.
-->
