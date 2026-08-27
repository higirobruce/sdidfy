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

**Revisit trigger.** ~~Phase 3 hardening / key-custody decision #5 landing.~~ **Superseded by decision (l)**, which replaced the "swap KeysService's internals" plan with an explicit `KeyCustody` interface and moved the Postgres store behind it as one provider among three. The dev-only posture is unchanged and is now enforced rather than documented: `PostgresDevKeyCustody` refuses to construct under `NODE_ENV=production`, and `loadConfig()` refuses to boot on `KEY_CUSTODY=postgres-dev` there. (`KEYSTORE_DIR`, the reserved knob nothing read, was removed in (l) — `KEY_CUSTODY` is the real setting.)

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

## l. Attestation nonce is server-issued, single-use, and bound to the enrolled key — and the verifiers are hand-rolled with no new dependencies

**Context.** Until now `POST /v1/enrol/start` accepted an attestation token with no server challenge, and `AttestationService.verify` took only the attestation blob. Both platform mechanisms are designed around a server nonce: Play Integrity binds a caller-supplied `requestHash`/nonce inside the signed verdict, App Attest binds a client-data hash inside the CBOR attestation object. Without one, a token captured from a single genuine, unrooted device could be replayed from any number of attacker devices forever — and without passing the public key being enrolled into the verifier, an attacker could attest a real hardware key and then bind a software-held one (06 T2/T3/T4, spec 03 §2 step 1).

**Decision.** Three parts.

1. **A nonce endpoint in front of enrolment.** `POST /v1/enrol/attestation-challenge` mints `{nonceId, nonce, expiresAt}` — 32 CSPRNG bytes, base64url — stored at `attnonce:<nonceId>` with `ATTESTATION_NONCE_TTL_SECONDS` (default 300 s, boot-checked `<=` the verifiers' 300 s token-age window) and consumed with **GETDEL**, the same atomic single-use pattern as the signing challenges. Unauthenticated by necessity, therefore rate-limited per IP (60/h) and audited on issuance. `attestation` joins `ChallengePurpose` in `packages/shared/src/protocol.ts` even though it is not a signing payload: the nonce travels *inside* the platform token, under the platform's signature, never in a `sdid-bridge:` string.
2. **Enforced in strict mode only, in the service, not the schema.** `attestationSchema.nonceId` is `optional()`; `AttestationService` requires it when `ATTESTATION_MODE=strict`. `verify()` now takes the `devicePublicKeyJwk` and hands it to the verifier so the key binding is checked against the key actually being bound. Every strict-mode refusal — missing nonce, replay, rooted device, wrong app, key mismatch, stale token — returns one identical `403 attestation_rejected` body; the precise code and detail go to the `enrolment.failed` audit row and the log. `verifier_unavailable` (including a throwing verifier) is a retryable `503 attestation_unavailable`, never a refusal and never an acceptance.
3. **Verifiers hand-rolled in `@sdid/attestation`, no new runtime dependencies**, behind a pure `AttestationRequest → AttestationResult` contract, injected into the broker through the `ATTESTATION_VERIFIERS` seam. The Play Integrity decode call — the one part that genuinely needs Google credentials — is an injected `decodeToken` function whose broker implementation (`apps/broker/src/trust/play-integrity.decoder.ts`) currently throws with a descriptive error.

**Rationale.** Making the nonce optional in the zod schema and required in the service is what lets one change close the replay gap *and* leave the entire Phase 0–2 path (device-sim, e2e, the ghost-login demo) byte-identically working: a missing nonce in strict mode then fails as a uniform attestation rejection rather than a validation error that tells an attacker precisely which field to add (03 §7). Consuming the nonce *before* verification, and not refunding it on failure, means a replay loses atomically rather than being noticed afterwards. Passing the JWK through is the cheapest possible fix for the attest-one-key-enrol-another substitution, and it is why `verify()`'s signature changed rather than growing a second method. On dependencies: a Play Integrity / App Attest verifier is CBOR + X.509 + ECDSA over well-specified formats, all reachable from `node:crypto`; pulling in `google-auth-library`, an attestation SDK and a CBOR package would have added a large, transitive, unaudited supply-chain surface to *the* component whose entire job is to be trustworthy — for a national identity system that trade is the wrong way round. Google's server-side decode API is the one thing that cannot be hand-rolled, so it is the one thing behind an injected seam, and it fails closed.

**Revisit trigger.** (a) When GoR service-account credentials for the Play console project exist — implement `createPlayIntegrityDecoder` and nothing else changes. (b) If the hand-rolled chain validation ever needs a capability `node:crypto` cannot express (a new Apple/Google attestation format, RSA-PSS chains, OCSP), re-evaluate a vetted library for *that piece* against the same supply-chain bar; the `AttestationVerifier` contract is the swap point. (c) If Play Integrity's classic verdict ever loses the nonce/`requestHash` binding, the whole T4 defence must be redesigned, not patched. (d) `ATTESTATION_NONCE_TTL_SECONDS` is the one tuning knob if real-world attestation latency (slow devices, poor connectivity — 08 inclusion) makes 300 s tight; it can never exceed the verifiers' token-age window.

## l. Signing-key custody is a sign-as-a-service interface (resolves spec open decision #5 *in structure*, vendor still open)

**Context.** Spec 06 §3 / T13 require broker signing keys in a KMS or HSM, "never in app memory as plaintext", "never leave the boundary in plaintext", with rotation over JWKS overlap and a key-usage audit; 07 §5 forbids secrets in the DB. Open decision #5 (owner Pacifique, needed by Phase 1) has *not* chosen between a GoR-approved KMS and an on-prem HSM, and residency (Q17) has already ruled out any foreign cloud KMS. Meanwhile decision (f) had the dev key in Postgres with `KeysService` as a notional "seam" — but the seam was only a promise: `signJwt` held a `jose.KeyLike` and there was no interface a KMS could have implemented.

**Decision.** Introduce an explicit custody boundary, `KeyCustody` (`apps/broker/src/keys/key-custody.ts`), and make it **sign-as-a-service**: `activeKid()`, `listPublicJwks()`, `sign(kid, data) -> raw r||s`, `healthCheck()`, `rotate()`, `capabilities`. It exposes **no private key material by any route** — there is deliberately no `getPrivateKey(kid)`, because that method is unimplementable against a real KMS or HSM and would let the codebase keep doing exactly what T13 forbids while looking solved.

Three providers implement it:

- **`postgres-dev`** — the existing behaviour, unchanged for dev/test/demo, and the only one that holds key material. It **refuses to construct under `NODE_ENV=production`**, and `loadConfig()` refuses to boot there on `KEY_CUSTODY=postgres-dev`, naming decision #5.
- **`kms`** and **`hsm-pkcs11`** — declared seams in the `trust/play-integrity.decoder.ts` idiom: real structure, typed configuration, injectable adapter functions the deployment supplies (`listKeys` / `getPublicKey` / `sign` / optional `rotate` + `health`), and a descriptive `KeyCustodyNotConfiguredError` from every operation until one is registered. **No vendor SDK or API shape is invented**, exactly as `packages/sdid-adapter` declines to guess SDID's interface (A1/A2).

Consequences that fell out of the sign-as-a-service constraint:

- `jose.SignJWT().sign()` is gone from the signing path — it needs a local key and cannot call a remote signer. `KeysService` assembles the compact JWS itself and hands only the signing input across the boundary. `jose` still does all verification (public keys only).
- ES256 JWS needs raw 64-byte `r||s`, but most KMS and many PKCS#11 stacks return DER. Conversion is the provider's job and lives in one tested helper (`derEcdsaToJoseSignature` / `normalizeEcdsaSignature`), with a shape assertion before any signature becomes a token.
- `rotate()` is capability-flagged. A provider that cannot rotate programmatically (the normal case for an HSM under dual control) **throws** rather than no-opping — a rotation job that reports success while rotating nothing is the failure mode worth engineering against.
- `probeSigning()` now exercises custody for real — health check, real signature, verification against the published JWKS — which is precisely the divergence its old comment predicted.
- Key usage is audited as a **periodic per-kid summary** (`key.usage_summary`, plus immediate rows for generate/promote/retire/rotate/signing-failure/health-transition) rather than a row per token, because at national scale a row per token would swamp a chain whose every append takes a global advisory lock (07 §4). The shared audit vocabulary gained the `key.*` actions, closing the gap that forced anomaly detection onto `admin.action`.

**Rationale.** The vendor decision is not ours to make and is months out, but the *shape* of the answer is already fully determined by the spec: whatever wins must sign on our behalf without surrendering the key. Building that shape now means the eventual choice is a bounded piece of work — implement four adapter functions — instead of a refactor of the token path under Phase 1 pressure. Declining to invent a vendor API is the same discipline the SDID adapter applies to A1/A2: a plausible-looking client for an API nobody has agreed to is code that must be deleted, and worse, it makes a seam *look* closed.

**Revisit trigger.** **When GoR names the KMS or the HSM** (decision #5, owner Pacifique). At that point: implement one `RemoteCustodyAdapter`, register it at bootstrap, set `KEY_CUSTODY`, and verify against the checklist in `docs/runbook.md` §4.3/§4.4 — in particular whether the backend wants a digest or a message, and whether it returns DER. Revisit sooner if the chosen backend cannot express something the interface assumes: a non-ES256 algorithm (only ES256 is modelled), a key set the backend will not enumerate, or per-signature authorisation/quorum, which the current interface has no way to represent.
