# Engineering Decisions — Phases 0–2 Implementation

Decisions taken while building this repo, in the format: context → decision → rationale → revisit trigger. These are implementation decisions layered on top of the spec's own decisions log (SPEC 10); where one resolves or deviates from a spec item, that is called out explicitly.

---

## a. Drizzle ORM everywhere (resolves spec open decision #12)

**Context.** Spec 01 §4 names "PostgreSQL 16 + Prisma" with "consider Drizzle for the audit/ledger context"; open decision #12 left the split (Drizzle for audit/txn + Prisma elsewhere vs one ORM) unresolved.

**Decision.** One ORM: Drizzle (`drizzle-orm`) for all broker data access (`apps/broker/src/db/schema.ts`), with plain SQL migrations (`apps/broker/migrations/*.sql`) run by a minimal forward-only runner (`apps/broker/src/db/migrate.ts`). The audit path uses the raw `pg` pool directly where it needs transaction + advisory-lock control.

**Rationale.** Prisma 7's engine binaries were unavailable in the build environment, and the spec had already sanctioned Drizzle for the ledger context (the Ikigea pattern). Splitting ORMs to keep Prisma would have bought two toolchains for no functional gain; Drizzle's SQL-first model also suits a schema in which the most sensitive table (audit) is deliberately hand-written SQL with triggers.

**Revisit trigger.** Only if a team-standard mandate forces Prisma back in; nothing in the code depends on Drizzle beyond `schema.ts` and per-module queries.

## b. OIDC endpoints implemented directly on NestJS + jose — DEVIATION from spec 04 §2

**Context.** Spec 04 §2 says "Build on a vetted OIDC provider (`node-oidc-provider` or equivalent) extended for CIBA — do **not** hand-roll OIDC."

**Decision.** The v1 broker implements the OIDC surface directly as NestJS controllers (`apps/broker/src/modules/oidc`, `modules/ciba`) with `jose` for all JWT/JWKS work. This is a **deliberate, tracked deviation**, not an oversight.

**Rationale.** The subset we need — code+PKCE with a phone-approval page instead of a browser login session, poll-mode CIBA, pairwise-only subjects, ES256, two client-auth methods — is small, and extending `node-oidc-provider` for CIBA plus a non-standard authorize interaction was judged more code (and more configuration surface to audit) than implementing the subset with zod-validated DTOs and protocol tests. Hand-rolling was made survivable by keeping the surface minimal: no refresh tokens, no dynamic registration, no request objects, `S256`-only PKCE.

**Revisit trigger.** **Before Phase 3 / production.** Re-evaluate migrating onto a vetted provider once the real flows are pinned down. The migration contract is (1) the endpoint surface documented in `docs/rp-integration-guide.md` and the discovery document, and (2) the protocol test suites in `apps/broker/src/modules/oidc/testkit.ts` and the module specs — a replacement provider must pass the same tests unchanged.

## c. jose@4 (last CJS-compatible line)

**Context.** The monorepo builds to CommonJS (NestJS + ts-node-free `tsc` output); `jose` v5+ is ESM-only and cannot be `require()`d.

**Decision.** Pin `jose@^4.15.9` (the last CJS-compatible major) in broker and test-rp.

**Rationale.** Module-system compatibility without dual-build complexity. jose@4 covers everything used: ES256 sign/verify, JWK import/export, local and remote JWK sets.

**Revisit trigger.** When the monorepo moves to ESM (or NestJS tooling makes ESM the default), lift to current jose in the same change.

## d. Face-only 1:1 matching at enrolment v1 (parked decision D1, self-service option)

**Context.** Spec appendix D1: phone fingerprint sensors cannot produce a print matchable against NIDA's reference. Options were assisted enrolment with an external reader, or face-match self-service.

**Decision.** v1 enrolment matches **face only**. `EnrolmentService.start` rejects `modality: 'fingerprint'` samples outright (`invalid_request`). Fingerprint remains a **device-unlock** mechanism only — it gates the private key on the phone and is never transmitted or matched against NIDA.

**Rationale.** Self-service enrolment on the citizen's own phone is the only path that scales without physical enrolment points, and it is what D1's self-service option prescribes. The DTO and `SdidProvider` contract keep the `fingerprint` modality so an assisted-enrolment channel can be added without interface changes.

**Revisit trigger.** D1 being formally decided the other way (assisted enrolment), or NIDA/SDID providing a phone-compatible fingerprint matching path (A2).

## e. Device simulator stands in for the React Native authenticator

**Context.** Spec Phase 2 delivers a React Native mobile authenticator; its security properties (non-exportable keys, biometric-gated signing, attestation) are what the trust chain rests on.

**Decision.** `apps/device-sim` (`SimDevice`) implements the citizen-device side of every protocol — enrolment, activation proof-of-possession, direct login, backchannel pull, signed CIBA approve/deny — using a WebCrypto P-256 keypair generated with `extractable: false` and a simulated biometric gate.

**Rationale.** It proves the full trust chain (spec 09 §6 ghost login) now, without waiting on native crypto modules. Crucially, the RN app is not a rewrite: it consumes the **identical HTTP + challenge-signing contract** (`packages/shared/src/protocol.ts` — `sdid-bridge:v1:<purpose>:<challengeId>:<nonce>` payloads, ECDSA P-256/SHA-256, base64url raw r||s). **SimDevice is the reference client** for the Phase 2 app team; behavioural overrides (impostor NID, spoofed liveness, rooted-device attestation) double as the negative-path test fixture.

**Revisit trigger.** None — the simulator stays permanently as the e2e test harness even after the RN app ships.

## f. Dev key store in Postgres; KeysService is the KMS/HSM seam (spec open decision #5)

**Context.** Broker signing keys must live in a GoR-approved KMS or on-prem HSM (in-country residency, spec 06 §3, decision #5) — but that choice is not yet made and dev needs signing today.

**Decision.** Development keys are ES256 JWKs generated at first boot and stored (public **and private**) in the `signing_keys` Postgres table. All signing/verification goes through `KeysService` (`apps/broker/src/keys/keys.service.ts`) — no other module touches key material. The production swap replaces KeysService's storage/signing internals with KMS/HSM calls; `signJwt`/`verifyJwt`/`jwks` are the seam.

**Rationale.** Postgres keeps dev multi-process-consistent (unlike per-process in-memory keys) with zero extra infrastructure. Confining key handling to one injectable service makes the KMS swap a one-module change, exactly as the adapter confines SDID.

**Revisit trigger.** Phase 3 hardening / key-custody decision #5 landing. A private key in the database is a **dev-only posture** — it must not survive into any environment with real citizens. (Note: `KEYSTORE_DIR` exists in config as a reserved knob but the dev store is the DB table.)

## g. Conservative token lifetimes; no refresh tokens in v1 (spec open decision #2)

**Context.** Spec 04 §4 leaves lifetimes open with the instruction "start conservative".

**Decision.** From `apps/broker/src/config.ts` (env-overridable, authoritative): ID token **300 s**, access token **600 s**, first-party device session **900 s**. **No refresh tokens** — the token endpoint supports only `authorization_code` and the CIBA grant. Supporting knobs: challenge TTL 120 s, CIBA request TTL 180 s (cap 600), auth code TTL 60 s.

**Rationale.** Every token an RP holds is short enough that revocation windows stay small, and re-authentication is cheap for the citizen (a biometric tap). Refresh tokens would create a long-lived bearer credential precisely where the spec's model says a fresh signature should be, and AL3 requires fresh step-up anyway (04 §7).

**Revisit trigger.** Pilot RP feedback showing genuine need for longer sessions — extend lifetimes or add refresh **only where justified**, per decision #2's own wording.

## h. Multi-device cap N = 5 (spec open decision #3)

**Context.** Decision #3 recommends "N capped (3–5), each via full biometric flow".

**Decision.** `MAX_ACTIVE_BINDINGS = 5` (`apps/broker/src/modules/enrolment/enrolment.service.ts`), counting non-revoked (pending + active) bindings; the sixth enrolment fails with `invalid_request` / HTTP 409 and is audited (`device_limit_reached`). Every new device runs the full biometric + SDID flow — there is no cloning path, by construction (keys are non-exportable).

**Rationale.** Top of the recommended band: households sharing devices and phone-replacement churn make 3 tight, while a hard cap still bounds the attack surface a compromised identity can accumulate.

**Revisit trigger.** Abuse telemetry (many-device enrolment patterns) or product feedback; it is a one-constant change.

## i. Pseudo-NID pepper and admin token via env in dev; production guard rails refuse dev defaults

**Context.** The pseudo-NID keyed hash (Q8) needs a pepper; the admin API needs a credential. In production both belong in KMS/managed secrets (T12, T13), which don't exist in dev.

**Decision.** Dev takes `NID_PEPPER` and `ADMIN_API_TOKEN` from env with recognisable dev defaults. `loadConfig()` (`apps/broker/src/config.ts`) enforces guard rails: with `NODE_ENV=production` the broker **refuses to boot** if `NID_PEPPER` starts with `dev-only`, if `ADMIN_API_TOKEN` equals `dev-admin-token`, or if `ATTESTATION_MODE` is not `strict`.

**Rationale.** The failure mode this kills is silent: a production deploy that "works" on dev secrets would pseudonymise every citizen's NID under a public pepper and expose the admin API on a known token. Failing at boot is the cheapest possible control.

**Revisit trigger.** Phase 3 key-custody work moves both values into the GoR KMS; the guard rails stay (they then assert the env plumbing delivered real values).

## j. Audit chain: hash-chained, advisory-lock serialised, trigger-enforced append-only — and awaited

**Context.** Spec 07 §4 requires an insert-only, tamper-evident audit trail; 06 §7 requires every security event to land in it.

**Decision.** `AuditService.append` (`apps/broker/src/audit/audit.service.ts`) writes each event with `hash = SHA-256(prev_hash || canonical(row))` over a key-sorted canonical JSON form, inside a transaction that takes a Postgres advisory lock (`pg_advisory_xact_lock`) so the chain is strictly linear even across broker replicas. Migration `0001_init.sql` installs triggers rejecting UPDATE/DELETE/TRUNCATE on `audit_events`. `GET /admin/audit/verify` re-walks the whole chain. And critically: **every caller `await`s `append()` — a failed audit write fails the operation.** There is no fire-and-forget audit anywhere in the broker.

**Rationale.** For national-ID auth, an unaudited state change is worse than a failed request: the trail is the accountability substrate for NIDA reporting, citizen access rights (08 §5) and forensics (08 §8). The advisory lock trades write concurrency for a chain that can never fork; audit volume is low enough that this is a sound trade. Canonicalisation is key-sorted because jsonb round-trips reorder object keys — without it, verification would false-alarm.

**Revisit trigger.** If audit write volume ever makes the single-lock serialisation a measured bottleneck, shard the chain per epoch/partition with anchored checkpoints — never relax awaited-ness or append-only.

## k. Re-verification cadence: staleness-gated at auth + a proactive sweep (resolves spec open decision #9)

**Context.** Spec 03 §6 and open decision #9 fix the identity-freshness policy at "~90 days + AL3 step-up". Routine auth only verifies a device signature and SDID does not push us identity changes (Q12), so periodic SDID re-assertion is our *only* signal for a revoked/deceased/changed identity behind an existing device. The first cut implemented the AL3 step-up half only (re-assert on every AL3 request); an AL1/AL2 device whose citizen had died or been revoked at NIDA would never have been caught.

**Decision.** The re-assertion logic lives in one place — `ReverificationService` (`apps/broker/src/trust/reverification.service.ts`), extracted from the CIBA controller's former private `stepUpReassert`. A binding is "due" when `now − (lastReassertedAt ?? activatedAt ?? enrolledAt) ≥ REVERIFY_INTERVAL_SECONDS` (default 90 days), or when forced. It is driven from two triggers:
- **Lazy** — direct login and CIBA **approval** (any assurance level) call `reassertIfDue`; AL3 additionally forces. A CIBA **denial** never re-asserts (it mints nothing).
- **Proactive** — `POST /admin/reverify/sweep` re-asserts every active binding past the cadence, one SDID call per citizen, batched (`limit`, default 200 / max 1000), for an external scheduler to drive (realising "on a schedule" for devices that are never used again).

A valid re-assertion refreshes `lastReassertedAt` for **all** of the citizen's active bindings (the check is identity-level, not device-level). An invalid identity suspends the citizen and revokes every active binding (`revoke_reason='sdid-reassert-invalid'`), audited as `sdid.reassert`/`failure`; the lazy path then fails the auth with 403, the sweep tallies it as `revoked`. No SDID subject ⇒ fail closed.

**Rationale.** Lazy staleness checks put the revoked/deceased catch exactly where it costs nothing until it is needed — the next time the identity is actually used — while the sweep bounds how long an unused-but-invalidated identity can linger. Gating on `approve` keeps a citizen's *denial* of a fraudulent request from spending SDID quota or, worse, tripping a suspension. Confining every SDID re-assertion to `ReverificationService` mirrors how the adapter confines SDID calls: cadence tuning (decision #9's Phase 3 half) and the eventual real `SdidProvider.reassert` are a one-service change.

**Revisit trigger.** Phase 3 cadence tuning against real SDID call-volume/cost (A5) — `REVERIFY_INTERVAL_SECONDS` is the single knob. If sweeps at national scale strain the SDID quota, move from a full-table scan to a due-index (`WHERE status='active' ORDER BY coalesce(last_reasserted_at, activated_at, enrolled_at)`) and/or a step-up-only posture for low-assurance bindings.
