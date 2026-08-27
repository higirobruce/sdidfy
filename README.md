# SDID Auth Bridge

A national-scale authentication service for Rwanda, built by RISA Engineering: citizens authenticate with SDID using biometrics, and any other GoR system can delegate that authentication over standard OIDC instead of integrating with SDID directly. It is deliberately three services, not one app (spec 00 §1): an **SDID Adapter** (the only code that speaks SDID's native protocol), an **Identity Broker** (exposes OIDC + CIBA to relying parties, orchestrates citizen auth, mints tokens), and a **Mobile Authenticator** (the citizen's device: enrol once with a server-side biometric match, then approve logins with the device biometric unlocking a hardware-backed key). This repo implements spec Phases 0–2 end-to-end against a **mock SDID** — there is no SDID sandbox, so the mock is the build enabler until the SDID team answers the integration questionnaire.

The full specification lives in [`docs/SPEC.md`](docs/SPEC.md).

## Architecture

```
 Relying parties            +--------------------------------------------+
 (test-rp in this repo)     |                 Broker (NestJS)            |
      |                     |                                            |
      |  OIDC + CIBA        |  /oidc/*  /admin/*        +--------------+ |
      +---------------------+-> OIDC/CIBA modules ----->| SDID Adapter |-+--> SDID / NIDA
                            |        |                  | (mock in     | |    (Phase 3)
 Citizen phone              |        v                  |  Phases 0-2) | |
 (device-sim in this repo)  |  /v1/enrol/*  /v1/device/*+--------------+ |
      |  signed             |  Enrolment / Devices /         |           |
      |  challenges         |  CIBA device backchannel   Match Engine    |
      +---------------------+->      |                  (1:1 + PAD,      |
                            |        v                   in-memory only) |
                            |  Postgres 16 (+ hash-chained audit)        |
                            |  Redis (challenges, rate limits, denylist) |
                            +--------------------------------------------+
```

## Repo layout

| Path | Package | What it is |
|------|---------|------------|
| `packages/shared` | `@sdid/shared` | Contracts: DTO schemas (zod), the `SdidProvider` and `MatchEngine` interfaces, challenge-signing protocol, error codes, assurance levels, audit event types, mock test NIDs |
| `packages/sdid-adapter` | `@sdid/sdid-adapter` | The only module that will ever speak SDID's protocol. `MockSdidStrategy` plus resilience wrapper (timeout, retry with jitter, circuit breaker, boundary validation) and audit hook |
| `packages/match-engine` | `@sdid/match-engine` | `MockMatchEngine`: 1:1 sample-vs-reference comparison + PAD threshold, in-memory only, zeroized on every path (spec 07 §1) |
| `apps/broker` | `@sdid/broker` | The Identity Broker: OIDC/CIBA endpoints, enrolment + device binding, device backchannel, RP admin API, hash-chained audit, migrations |
| `apps/device-sim` | `@sdid/device-sim` | `SimDevice` — simulated citizen phone: non-exportable P-256 key, biometric-gated signing, mock attestation, full enrolment/login/CIBA protocols + CLI |
| `apps/test-rp` | `@sdid/test-rp` | `RpClient` — pilot relying-party client: CIBA initiation, token polling, ID-token verification against the broker JWKS + CLI |
| `e2e` | `@sdid/e2e` | The "ghost login" end-to-end demo (spec 09 §6) |

## Quickstart

Prerequisites:

- Node.js >= 22
- pnpm (repo pins `pnpm@10.33.0`)
- PostgreSQL 16 with user `sdid` / password `sdid_dev` and database `sdid_bridge`
- Redis

```bash
cp .env.example .env
pnpm install
pnpm build
pnpm db:migrate          # optional: the broker also runs migrations at startup
pnpm demo:ghost-login    # the full trust-chain demo (see below)
pnpm test                # unit + protocol tests across all packages
```

To run the broker on its own: `pnpm broker:dev` (listens on `BROKER_PORT`, default 3100). The `device-sim` and `test-rp` CLIs default to `http://localhost:3100`, matching the broker; override with `--broker` / `BROKER_URL` if you moved it.

## What the ghost-login demo proves

"Ghost login" is the spec's first milestone (09 §6): a test RP completes a full CIBA login of a simulated device against mock SDID, end to end, with a genuine signature from a non-exportable key and a minted, verifiable token — no real SDID, no UI. One run exercises the entire trust chain:

1. **Enrolment** — the device attests itself, submits a face capture, the broker fetches the mock-NIDA reference and runs the 1:1 match + PAD in memory (biometric bytes zeroized after), then stores a device binding.
2. **Hardware-key binding** — the device proves possession by signing the activation challenge with its non-exportable P-256 key.
3. **CIBA approval** — the RP calls `/oidc/bc-authorize`; the device pulls the pending request over the authenticated backchannel and signs the approval challenge.
4. **Verified pairwise ID token** — the RP polls `/oidc/token`, receives an ES256 ID token with a pairwise `sub`, `acr`, `amr`, and verifies it against the broker's JWKS.

Everything downstream of enrolment is "verify a signature" — which is exactly what the spec says the trust chain should reduce to (03 §1).

## Status

| Area | Status |
|------|--------|
| SDID adapter contract + mock strategy, resilience, contract tests (spec 02) | Implemented (Phase 0) |
| Postgres schema, migrations, hash-chained append-only audit (spec 07) | Implemented (Phase 0) |
| OIDC broker: discovery, JWKS, token, userinfo, introspect, revoke (spec 04 §2) | Implemented (Phase 1) |
| CIBA backchannel + poll delivery, pairwise subjects, consent (spec 04 §3–§5) | Implemented (Phase 1) |
| Auth code + PKCE flow (phone-approval page, no broker browser session in v1) | Implemented (Phase 1) |
| Enrolment, device binding, activation, direct login, revocation (spec 03) | Implemented (Phase 2, device simulator in place of the RN app) |
| Re-verification cadence: ~90d staleness + AL3 step-up, proactive admin sweep (spec 03 §6, decision #9) | Implemented (Phase 1 defs; cadence tuning in Phase 3) |
| RP onboarding admin API (spec 04 §6) | Implemented |
| Real SDID strategies (`oidc` / `proprietary`) | Gated on SDID answers A1–A7 (Phase 3) |
| Real attestation (Play Integrity / App Attest), `ATTESTATION_MODE=strict` | Gated on Phase 3 |
| Vetted matching SDK + ISO 30107 L2 PAD evaluation | Gated on Phase 3 |
| Production traffic | Gated on DPIA + external pentest (spec 09 §2/§5, 06 §8) |

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — the consolidated spec kit (source of truth for design intent)
- [`docs/rp-integration-guide.md`](docs/rp-integration-guide.md) — how relying-party teams integrate
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — engineering decisions taken during this implementation
- [`docs/runbook.md`](docs/runbook.md) — ops notes: env vars, key rotation, audit verification, revocation, SDID cutover
