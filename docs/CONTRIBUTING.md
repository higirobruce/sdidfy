# Contributing to the SDID Auth Bridge

This service authenticates Rwandan citizens against the national identity
register. A defect here is not a broken feature — it is a citizen who cannot
log in to a government service, or a biometric that should never have existed
on disk. The conventions below exist for that reason and are not stylistic
preferences.

Read [`docs/SPEC.md`](SPEC.md) before your first change. It is the source of
truth for design intent; this document is only how we work on the code.

---

## 1. Local setup, from a clean machine

You need four things: Node 22, pnpm, PostgreSQL 16, Redis. Nothing else.

```bash
# 1. Node 22 (nvm, asdf, or your distribution's package — the repo enforces
#    >=22 via engines, and CI runs 22).
node --version           # v22.x

# 2. pnpm. The repo pins the version in `packageManager`; corepack honours it.
corepack enable
pnpm --version           # 10.33.0

# 3. Postgres 16 and Redis, with the credentials .env.example expects.
#    Docker is the least painful route:
docker run -d --name sdid-pg    -p 5432:5432 \
  -e POSTGRES_USER=sdid -e POSTGRES_PASSWORD=sdid_dev -e POSTGRES_DB=sdid_bridge \
  postgres:16
docker run -d --name sdid-redis -p 6379:6379 redis:7

#    Or use a local install — the only requirement is a `sdid` / `sdid_dev`
#    role owning a `sdid_bridge` database, and Redis on 6379.

# 4. The repo.
cp .env.example .env
pnpm install
pnpm build
pnpm db:migrate          # optional: the broker also migrates at boot
pnpm demo:ghost-login    # the whole trust chain, narrated
```

If `pnpm demo:ghost-login` prints a green run and exits 0, your machine is
correctly set up. That single command exercises enrolment, the 1:1 biometric
match, hardware-key binding, CIBA approval and token verification.

`.env` is only read by your shell/tooling — the broker reads process
environment variables directly (`apps/broker/src/config.ts`), so export them
or use a loader. Every knob and its default is tabulated in
[`docs/runbook.md`](runbook.md) §2; `.env.example` is the short version.

**Redis snapshots.** Starting `redis-server` from the repo root writes
`dump.rdb` into the working directory. It is gitignored. Don't commit it.

### Common setup failures

| Symptom | Cause |
|---|---|
| `ECONNREFUSED 127.0.0.1:5432` in tests | Postgres isn't up, or isn't on 5432 |
| `relation "citizens" does not exist` | Run `pnpm db:migrate` |
| Enrolment fails with `rate_limited` after a few runs | 5 enrolments per NID per hour (runbook §7). Clear `rl:enrol:*` in Redis, or wait |
| `something is already listening on http://localhost:3199` | A previous e2e harness broker survived. Kill it |
| `ERR_PNPM_OUTDATED_LOCKFILE` in CI | A workspace package was added without regenerating `pnpm-lock.yaml`. Run `pnpm install` and commit the lockfile |

---

## 2. Repository layout

A pnpm workspace driven by turborepo. Three services, deliberately not one app
(00 §1): the adapter is the only thing that speaks SDID, the broker is the only
thing that speaks OIDC to relying parties, the authenticator is the citizen's
device.

| Path | Package | What it is |
|------|---------|------------|
| `packages/shared` | `@sdid/shared` | Contracts everything else depends on: zod DTO schemas, the `SdidProvider` and `MatchEngine` interfaces, challenge-signing protocol, error codes, assurance levels, audit event types, mock test NIDs |
| `packages/sdid-adapter` | `@sdid/sdid-adapter` | The **only** module that speaks SDID's protocol (02 §4). Mock strategy plus the resilience wrapper — timeout, retry with jitter, circuit breaker, boundary validation |
| `packages/match-engine` | `@sdid/match-engine` | 1:1 sample-vs-reference comparison and PAD threshold. In memory only, zeroized on every path (07 §1) |
| `packages/attestation` | `@sdid/attestation` | Play Integrity / App Attest verification primitives (05 §4) |
| `apps/broker` | `@sdid/broker` | The Identity Broker: OIDC + CIBA, enrolment, device binding, device backchannel, RP admin API, hash-chained audit, migrations |
| `apps/device-sim` | `@sdid/device-sim` | Simulated citizen phone: non-exportable P-256 key, biometric-gated signing, full protocols, CLI |
| `apps/mobile` | `@sdid/mobile` | The citizen authenticator (05). `src/core` is plain TypeScript under vitest; the UI and native bridges need a React Native toolchain |
| `apps/test-rp` | `@sdid/test-rp` | Pilot relying-party client: CIBA initiation, token polling, ID-token verification, CLI |
| `e2e` | `@sdid/e2e` | The ghost-login demo and end-to-end suite (09 §6) |
| `docs` | — | Spec, decisions, runbook, RP integration guide, this file |
| `.github` | — | CI, security workflows, and the CI guard scripts |

Inside `apps/broker/src`, `modules/` holds protocol surfaces (`oidc`, `ciba`,
`enrolment`, `devices`, `consent`, `rp`) and the siblings hold infrastructure
(`db`, `redis`, `keys`, `audit`, `trust`, `sdid`, `push`, `logging`,
`observability`, `anomaly`). `trust/` is where signature verification,
challenges, attestation, pairwise subjects and rate limits live — most
security-relevant review happens there.

### Turborepo

`pnpm build`, `pnpm typecheck`, `pnpm test` and `pnpm lint` all run through
turbo. Two things worth knowing:

- **Task graph.** `typecheck` and `test` depend on `^build`, so a package's
  dependencies are built before it is checked. `build` outputs `dist/**`.
- **Environment variables are declared, not ambient.** Turbo 2 runs tasks in
  strict environment mode, so a variable a task actually reads must appear in
  `globalEnv` in `turbo.json` — otherwise it neither reaches the task nor
  affects the cache key, and you get a cache hit that should have been a miss.
  If you add a config knob the broker reads at test time, add it there too.

---

## 3. Running the tests

There are four layers. Run the cheapest one that can fail on your change, then
`pnpm verify` before you open the PR.

| Layer | Command | Needs Postgres/Redis | What it covers |
|---|---|---|---|
| One package | `pnpm --filter @sdid/match-engine test` | Only if that package touches the DB | The fastest loop |
| Everything | `pnpm test` | **Yes** | All packages. The broker's suite runs against a real Postgres and Redis — it is an integration suite that happens to use vitest |
| End-to-end | `pnpm test:e2e` | **Yes** | Spawns the real broker (`apps/broker/dist/main.js`) on port 3199 and drives it through the full ghost-login flow |
| Demo / smoke | `pnpm demo:ghost-login` | **Yes** | The narrated version of the same flow. Must exit 0 |
| Everything, in order | `pnpm verify` | **Yes** | typecheck → build → test → demo. This is what CI runs |

Notes that will save you an hour:

- **The broker's tests are not unit tests.** `apps/broker/src/modules/*/testkit.ts`
  builds a Nest application over the real Postgres, Redis, keys, audit and
  trust modules; only the SDID provider is stubbed. If they fail with a
  connection error, that's your infrastructure, not the code.
- **The e2e harness builds if it must.** `e2e/src/harness.ts` runs `pnpm build`
  when `apps/broker/dist/main.js` is missing, so a stale `dist` becomes a slow
  first test rather than a confusing failure.
- **Rate limits are real in tests.** Enrolment is capped at 5 per NID per hour
  and bindings at 5 per citizen. The suites clear their own `rl:enrol:*` and
  `lockout:enrol:*` keys; the e2e harness shells out to `redis-cli` to do it,
  and degrades silently if `redis-cli` isn't installed. Install it.
- **Don't point any of this at a shared database.** The suites truncate
  application tables and the CI audit check appends a chain-breaking probe row.

### The guard scripts

Three checks run in CI and are runnable locally:

```bash
pnpm ci:guard               # the non-negotiables scan (no dependencies)
pnpm ci:secret-scan         # grep for committed credentials
pnpm ci:audit-append-only   # prove the audit triggers reject UPDATE/DELETE
```

The last one needs a **disposable** database — it appends a probe row with a
bogus hash, which breaks the tamper-evident chain from that row onward. It
refuses to run against a non-local `DATABASE_URL` for that reason.

---

## 4. House conventions

### Cite the spec, in the code

Every non-obvious decision carries the reason it exists, as a spec section or a
threat id, in the comment next to it:

```ts
/** Enrolment failure lockout: 5 failures / 15 min window (03 §7). */
const ENROL_MAX_FAILURES = 5;
```

```ts
// Must be <= the verifiers' token-age window — a nonce that outlives the
// freshness check widens the very replay window it exists to close (T4).
```

The form is `(NN §M)` for a spec section and `T4` for a threat from the
catalogue in 06 §2. `decision #9` refers to `docs/DECISIONS.md`. This is not
decoration: half the constants in this codebase look arbitrary and are not, and
the next person to "simplify" one needs to find out why before they do.

Comments explain **why**. TypeScript already says what.

### Fail closed, always

A missing configuration value, an unparseable token, an unreachable SDID, an
empty trust anchor — every one of these is a rejection, never a default-allow.
The pattern is everywhere in `config.ts`: an empty `ANDROID_CERT_SHA256_DIGESTS`
in strict mode is a boot failure, not "accept any certificate". An
unimplemented verifier throws, so the path returns 503 rather than passing.

When you add a branch, ask what happens when the input is absent, malformed, or
hostile. If the answer is "it proceeds", it is wrong.

### Validate at the boundary with zod

Anything crossing into our process — an HTTP body, an SDID response, an
environment variable — is parsed by a zod schema before any other code sees it.
Request DTO schemas live in `packages/shared`; the SDID adapter validates
responses at its own boundary so a malformed upstream payload never reaches
broker logic; `loadConfig()` parses `process.env`.

Do not hand-roll validation, and do not trust a type assertion at a boundary —
`as SomeDto` is a lie the compiler cannot check.

Beware `z.coerce.boolean()`, which applies JS truthiness so the string
`"false"` parses as `true`. `config.ts` has the correct helper; use it.

### Other conventions

- **TypeScript strict, CommonJS output, `.js` extensions in relative imports.**
  The compiler settings are in `tsconfig.base.json`; match the import style of
  the file you are editing.
- **Errors are `BridgeError` with a stable error code** from `@sdid/shared`,
  not ad-hoc `Error` subclasses. RPs and the mobile app switch on those codes.
- **Failures are indistinguishable on purpose.** Unknown NID, failed match and
  failed PAD all return the same thing (03 §7) — do not "improve" the error
  message into an oracle for probing the register (T14).
- **New env var → three places.** `apps/broker/src/config.ts` (with a comment
  and a fail-closed default), `.env.example`, and `docs/runbook.md` §2. Add it
  to `turbo.json` `globalEnv` if a task reads it.
- **Decisions go in `docs/DECISIONS.md`.** If you changed a token lifetime, a
  threshold or a cadence, the number is not the record — the reasoning is.

---

## 5. Non-negotiables a reviewer must check

These come from `docs/SPEC.md` (10 — Decisions Log, "Non-negotiables"; detail
in 07 §1/§3/§4). They are not negotiable in review either: a change that
violates one does not get merged with a follow-up ticket.

CI runs a lexical guard for a subset of them
(`.github/scripts/guard-non-negotiables.mjs`). **A green CI run is not
evidence.** The script's own header lists what it cannot see; the list below is
what a human has to check.

### Any change touching biometrics

The cardinal rule (07 §1): the captured sample and NIDA's reference template
exist in memory, for the duration of one match, and are then gone.

- [ ] No sample or template is written to Postgres, Redis, a file, a cache,
      an object store, a metric label, an HTTP response body, or a log line —
      including inside an error object that later gets logged.
- [ ] Buffers are zeroized on **every** path out of the function, error paths
      included. A `try` that zeroizes only on success is a defect.
- [ ] What survives the request is a binding, a proof, and a verdict: device
      public key, attestation, assurance level, audit record. Nothing else.
- [ ] Only the match **outcome** is audited — pass/fail and a score band, never
      the biometric and never a raw score that could reconstruct one (07 §4, T18).
- [ ] No new schema column that could hold a biometric artefact.
- [ ] PAD (liveness) is still evaluated and still fails closed (T8).

### Any change touching the audit trail

`audit_events` is insert-only and hash-chained (07 §4).

- [ ] No UPDATE, no DELETE, no TRUNCATE — in SQL, in Drizzle, in a migration,
      in a test helper, anywhere.
- [ ] The DB guard triggers are untouched. If a migration alters
      `audit_events`, the `db-integrity` CI job must still pass.
- [ ] A new event chains correctly: `prev_hash`/`hash` computed the same way as
      every other event, written under the same serialisation, and
      `/admin/audit/verify` still reports `intact: true` afterwards.
- [ ] **No raw 16-digit NID and no biometric value anywhere in the row** —
      not in `subject_ref`, not in `context`, not in `match_result`. The
      pseudonymised NID (keyed hash, Q8) is the identity reference.
- [ ] The event is actually written for the security-relevant action. An
      un-audited enrolment or revocation is as much a defect as a wrong one.

### Any change touching tokens, keys or sessions

- [ ] Subjects stay pairwise per RP (04 §4). Nothing may return an identifier
      that lets two RPs correlate the same citizen.
- [ ] Token lifetimes unchanged, or changed deliberately and recorded in
      `docs/DECISIONS.md`. Short-only, no refresh, in v1 (decision #2).
- [ ] Signing keys come from the keystore and nowhere else. No key material in
      a log, an error, a response, or the repository (T13).
- [ ] Revocation still propagates on the paths runbook §6 documents — a live
      check against Postgres/Redis, not a cached decision.
- [ ] Every signature verification is bound to a single-use, short-TTL,
      server-issued nonce, and reuse is rejected (T4).
- [ ] Nothing added a headless path. Interactive citizen approval is always
      required — that is a hard non-goal (00), not a feature gap.

### Any change touching SDID

- [ ] SDID is reached through `packages/sdid-adapter` only (02 §4). If any
      other package imports an SDID URL, protocol detail or credential, that is
      the defect, whatever else the change does.
- [ ] Mock and real strategies still satisfy the same contract tests — that
      shared suite is what makes the Phase 3 cutover survivable.

### Everywhere

- [ ] Fail-closed on absent, malformed or hostile input.
- [ ] zod validation at the boundary.
- [ ] Rate limits and lockouts still apply to the path you touched (T14).
- [ ] Comments cite the spec section or threat id.

---

## 6. CI

| Workflow | Job | What it does |
|---|---|---|
| `ci.yml` | `guards` | The non-negotiables scan and the secret scan. No install, under a minute |
| `ci.yml` | `verify` | Postgres 16 + Redis service containers, then typecheck → build → migrate → test → `pnpm demo:ghost-login` as a smoke test. Mirrors the README quickstart exactly |
| `ci.yml` | `db-integrity` | A pristine database: migrations apply, re-apply as a no-op, and the audit append-only triggers are proved to reject UPDATE, DELETE and TRUNCATE |
| `security.yml` | `dependencies` | `pnpm audit`, **advisory not blocking** — see the comment in the file before changing that |
| `security.yml` | `secrets` | The secret scan again, on a weekly schedule |
| `security.yml` | `sast` | **A declared gap.** No SAST tool is configured. The step names the candidates and warns; it does not pretend to be coverage |

Two of these are deliberately honest about not doing their job:
history-aware secret scanning and SAST. SPEC 09 §3 asks for both. If you are
the person who enables one, delete the placeholder rather than leaving it next
to the real thing.

Everything CI runs, you can run locally. `pnpm verify` is the whole of the
`verify` job.
