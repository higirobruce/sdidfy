# Runbook — SDID Auth Bridge (broker)

Ops notes for the Phases 0–2 build. Everything here is verified against `apps/broker/src` as of this commit; `apps/broker/src/config.ts` is the authoritative source for configuration.

## 1. Services

| Service | What | Notes |
|---------|------|-------|
| Broker | NestJS app, `apps/broker` (`pnpm broker:dev` / `node dist/main.js`) | Listens on `BROKER_PORT` (default 3100). Stateless; safe to run multiple replicas (audit chain is advisory-lock serialised, challenges/limits live in Redis) |
| PostgreSQL 16 | Primary store + append-only audit + dev signing keys | Dev credentials: `sdid`/`sdid_dev`, database `sdid_bridge` |
| Redis | Challenges, rate limits, lockouts, token denylist, code-flow stash | Single logical instance; all state is short-TTL and reconstructible except active lockouts |
| device-sim / test-rp | CLIs (`apps/device-sim`, `apps/test-rp`) | Dev/test only. Both default to `http://localhost:3000` — set `BROKER_URL` (or `--broker`) to the real broker address |

Push in this build is wake-only **and log-only**: `PushService.wake` writes a log line. Simulated devices discover pending CIBA requests by polling `GET /v1/device/ciba/pending`; FCM/APNs transports plug in behind `PushService` in Phase 2 without touching callers.

## 2. Environment variables (from `apps/broker/src/config.ts`)

| Variable | Default | Meaning |
|----------|---------|---------|
| `NODE_ENV` | `development` | `development` \| `test` \| `production`. Production activates the guard rails (§8) |
| `BROKER_PORT` | `3100` | HTTP listen port |
| `BROKER_ISSUER` | `http://localhost:3100` | OIDC issuer: `iss` in every token, base of all endpoint URLs in discovery. Must be the externally reachable URL |
| `DATABASE_URL` | `postgresql://sdid:sdid_dev@localhost:5432/sdid_bridge` | Postgres connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `SDID_STRATEGY` | `mock` | `mock` \| `oidc` \| `proprietary` — adapter strategy flag (§7) |
| `NID_PEPPER` | `dev-only-nid-pepper-change-me` | HMAC key for the pseudonymised NID (Q8). Changing it orphans every existing citizen row — treat as immutable once citizens exist. Prod: KMS-held |
| `KEYSTORE_DIR` | `./data/keys` | Reserved. The dev key store is actually the `signing_keys` Postgres table (§4); this knob is currently unused |
| `ATTESTATION_MODE` | `mock` | `mock` accepts the simulator's structured attestation tokens; `strict` is the Phase 3 seam for Play Integrity / App Attest and currently rejects all enrolment with HTTP 501 |
| `ADMIN_API_TOKEN` | `dev-admin-token` | Bearer token for `/admin/*` (RP onboarding, audit verify). Prod: never the default (§8) |
| `ID_TOKEN_TTL_SECONDS` | `300` | ID token lifetime |
| `ACCESS_TOKEN_TTL_SECONDS` | `600` | Access token lifetime (also the `expires_in` in token responses) |
| `SESSION_TTL_SECONDS` | `900` | First-party device-session JWT lifetime |
| `CHALLENGE_TTL_SECONDS` | `120` | Single-use signing-challenge TTL (activation, login, CIBA approve/deny) |
| `CIBA_REQUEST_TTL_SECONDS` | `180` | Default CIBA auth-request lifetime (RPs may request up to 600); also the code-flow transaction/stash TTL |
| `CIBA_POLL_INTERVAL_SECONDS` | `2` | `interval` returned from `/oidc/bc-authorize` |
| `AUTH_CODE_TTL_SECONDS` | `60` | Authorization-code lifetime (single-use) |
| `REVERIFY_INTERVAL_SECONDS` | `7776000` (90 d) | SDID re-verification cadence (§6.1). A binding older than this since its last SDID contact is re-asserted at its next auth; also the trigger the proactive sweep uses |

Mock-adapter test knobs (read by `MockSdidStrategy`, dev only): `SDID_MOCK_LATENCY_MS` (simulated per-call latency), `SDID_MOCK_FAILURE_RATE` (0..1 probability of an injected `SdidUnavailableError`) — used for resilience/circuit-breaker testing.

CLI-side env (not broker config): `BROKER_URL`, and for `test-rp`: `CLIENT_ID`, `CLIENT_SECRET`, `ADMIN_API_TOKEN`.

## 3. Boot behaviour

1. `loadConfig()` parses env (zod) and applies production guard rails (§8) — a bad production config fails here, before anything listens.
2. **Migrations auto-run at startup** (`main.ts` → `runMigrations()`): files in `apps/broker/migrations/*.sql`, lexicographic order, each in its own transaction, tracked in the `_migrations` table. Forward-only; there are no down migrations. `pnpm db:migrate` runs the same runner standalone. Concurrent replicas racing the same migration will conflict loudly rather than corrupt — prefer migrating once before a rolling deploy.
3. `KeysService.onModuleInit` ensures an active ES256 signing key exists in `signing_keys`, generating one on first boot, and loads the JWKS into memory.
4. The app listens on `BROKER_PORT`.

## 4. Key rotation (spec 06 §3)

Keys live in the `signing_keys` table: `kid, alg, public_jwk, private_jwk, status ('active'|'retired'), created_at`. The broker signs with the single `active` key and **publishes every row — active and retired — in `/oidc/jwks`**, so tokens signed by a retired key keep verifying (JWKS overlap).

Rotation procedure (dev store; the KMS/HSM version keeps the same shape):

1. Generate a new ES256 keypair and swap it in **in one transaction**: set the current active row to `status='retired'` and insert the new row with `status='active'`. Exactly one row must be `active` at any time (the broker signs with the first active row it finds).
2. Restart (or rolling-restart) the broker: keys are loaded at module init, so the new active key takes effect on boot. All replicas must restart before the old key's tokens age out matters — until then both keys are in the published JWKS, so mixed replicas stay verifiable.
3. **Retired keys stay published** until no token signed by them can still be live: the longest broker-issued lifetime is `SESSION_TTL_SECONDS` (900 s by default). After that window a retired row may be deleted from `signing_keys`, which removes it from the JWKS.

RPs must select verification keys by `kid` and re-fetch the JWKS on an unknown `kid` — the integration guide says so.

## 5. Audit verification

```bash
curl -s http://localhost:3100/admin/audit/verify -H "Authorization: Bearer $ADMIN_API_TOKEN"
# → {"intact": true, "brokenAtSeq": null, "count": 1234}
```

This re-walks the entire hash chain: each row's `prev_hash` must equal the previous row's `hash`, and each `hash` must recompute from the row's canonical content. It is O(all rows) — fine at current volumes, schedule it (e.g. daily) rather than per-request.

**If `intact: false`:** a row at `brokenAtSeq` no longer matches the chain — the audit trail has been altered, deleted from, or corrupted at or before that row. The DB triggers block UPDATE/DELETE/TRUNCATE for every normal role, so a broken chain implies superuser/storage-level interference or storage corruption. Treat as a security incident (spec 08 §8):

1. Do **not** attempt to "fix" the table; new appends still chain off the last row, preserving evidence.
2. Snapshot the database (and WAL) immediately for forensics.
3. Pull the row(s) at and around `brokenAtSeq` and compare against the most recent backup to characterise the change.
4. Review DB superuser/host access for the window since the last known-intact verification.
5. Escalate per the breach-readiness process (infra/security lead; DPO notification path if citizen data is implicated).

## 6. Revocation paths and propagation windows (spec 06 §4)

| Path | How | Propagation |
|------|-----|-------------|
| **Device binding** | Citizen: `POST /v1/device/bindings/revoke` (own bindings only); system: an SDID re-assertion failure (AL3 step-up or the §6.1 cadence) revokes all of a citizen's bindings | **Immediate.** `DeviceSessionGuard` re-checks the binding's live status in Postgres on **every** backchannel request, and login/approval paths re-check `status='active'` — a revoked device is rejected on its next request even with an unexpired session JWT |
| **RP client** | `POST /admin/rps/{rpId}/suspend` | **Immediate** at the broker: client authentication and `/oidc/authorize` both reject non-active RPs on the next call. Tokens the RP already holds remain valid until expiry (≤ 600 s) unless individually revoked |
| **Token** | `POST /oidc/revoke` (RP, own-audience tokens only) → Redis denylist `revoked:<jti>` with TTL until the token's `exp` | **Immediate** on broker-checked paths (`/oidc/userinfo`, `/oidc/introspect`). **Not visible** to an RP validating JWT signatures offline — that residual window is bounded by the token TTL (access 600 s / ID 300 s). RPs needing hard revocation must introspect |
| **Consent** | Citizen: `POST /v1/device/consents/revoke` | **Immediate** for attribute release: `/oidc/userinfo` re-checks for a live covering grant on every call, even for a live token |

The overall design conclusion for decision #11: broker-mediated checks propagate in one request round-trip; the only eventual windows are the short token TTLs themselves.

### 6.1 Re-verification cadence (spec 03 §6, decision #9)

Routine auth only proves a device signature — it does **not** call SDID. SDID does not push us identity changes (Q12), so periodically re-asserting the identity is our **only** signal for a revoked, deceased, or otherwise invalidated citizen behind an already-bound device. Two triggers drive it, both through `ReverificationService`:

- **Lazy, at next use.** Every direct login and every CIBA **approval** (any assurance level) re-asserts the identity if the binding is past `REVERIFY_INTERVAL_SECONDS` since its last SDID contact (a prior reassert, else enrolment/activation). An AL3 request additionally forces a re-assertion every time (step-up). A CIBA **denial** never calls SDID.
- **Proactive, on a schedule.** `POST /admin/reverify/sweep` re-asserts every active binding that is past the cadence — one SDID call per citizen — so a device that is never used again is still caught. Drive it from an external scheduler (cron / Kubernetes CronJob), e.g. hourly:

  ```bash
  curl -s -X POST http://localhost:3100/admin/reverify/sweep \
    -H "Authorization: Bearer $ADMIN_API_TOKEN" \
    -H 'Content-Type: application/json' -d '{"limit": 500}'
  # → {"scanned": 4210, "due": 37, "reasserted": 36, "revoked": 1}
  ```

  `limit` caps citizens re-asserted per call (default 200, max 1000) — size it to your SDID verification quota (A5). Re-run until `due` reaches 0 to drain a backlog.

**When SDID declares an identity invalid** (either trigger): the citizen is set `status='suspended'`, **all** their active bindings are revoked (`revoke_reason='sdid-reassert-invalid'`), and the event is audited (`sdid.reassert`, `result='failure'`). The lazy path fails that auth with HTTP 403 `access_denied`; the sweep counts it under `revoked` and continues. Recovery is a fresh enrolment with a live biometric re-match (§ spec 03 §5) — there is no un-suspend path by design.

## 7. Rate limits, lockouts, and Redis keys

Fixed-window counters (`RateLimitService.hit`, error `rate_limited`/429) and failure lockouts (`recordFailure`/`assertNotLockedOut`, error `locked_out`/429 with exponential window extension ×2^min(n−max,4)):

| Limit | Key | Policy |
|-------|-----|--------|
| Enrolment per NID | `rl:enrol:nid:<pseudoNid>` | 5 / hour |
| Enrolment per IP | `rl:enrol:ip:<ip>` | 20 / hour |
| CIBA initiation per RP | `rl:ciba:rp:<rpId>` | 60 / minute |
| Enrolment failure lockout | `lockout:enrol:nid:<pseudoNid>` | 5 failures / 15 min (covers failed match, failed PAD, unknown NID — indistinguishable by design) |
| Login failure lockout | `lockout:login:<bindingId>` | 5 failures / 15 min; cleared on successful login |

Full Redis key prefix map:

| Prefix | Contents | TTL |
|--------|----------|-----|
| `rl:` | Fixed-window rate-limit counters | Window length |
| `lockout:` | Failure counters (lockout when count ≥ max) | Window, extended exponentially at/after the threshold |
| `challenge:` | Single-use signing challenges `{purpose, nonce, bindingId}`, consumed atomically with GETDEL | `CHALLENGE_TTL_SECONDS` (120 s) |
| `revoked:` | Token denylist by `jti` | Until token `exp` |
| `codeflow:` | Auth-code-flow stash `{codeChallenge, nonce, redirectUri, state}` keyed by transaction | `CIBA_REQUEST_TTL_SECONDS` (180 s) |

To lift a lockout manually (e.g. verified support case): `DEL lockout:enrol:nid:<pseudoNid>` / `DEL lockout:login:<bindingId>`. Never bulk-delete `challenge:` keys — that only invalidates in-flight authentications.

Redis loss is safe but lossy: in-flight challenges and code-flow stashes fail (users retry), rate/lockout counters reset, and **token denylist entries are lost** — revoked-but-unexpired tokens become acceptable again until `exp`. After an unplanned Redis flush, consider the outstanding-token window (≤ 600 s) exposed.

## 8. Dev vs production guard rails

`loadConfig()` refuses to boot with `NODE_ENV=production` unless:

- `NID_PEPPER` does not start with `dev-only`;
- `ADMIN_API_TOKEN` is not `dev-admin-token`;
- `ATTESTATION_MODE=strict`.

Additional production notes:

- `ATTESTATION_MODE=strict` currently returns HTTP 501 for all enrolments — deliberate: production enrolment is impossible until real Play Integrity / App Attest verifiers land (Phase 3). Existing bindings and RP flows are unaffected by attestation mode.
- The dev key store keeps private JWKs in Postgres (`signing_keys`) — a dev-only posture; production swaps `KeysService` internals for the GoR KMS/HSM (see `docs/DECISIONS.md` f).
- Production is additionally gated on DPIA + external pentest (spec 06 §8, 09 §5) — guard rails are necessary, not sufficient.

## 9. Mock → real SDID cutover (spec 02 §4)

The adapter strategy is feature-flagged: `SDID_STRATEGY=mock|oidc|proprietary`, consumed by `createSdidProvider` (`packages/sdid-adapter/src/index.ts`) via the broker's `SdidModule`.

- **`mock`** (current): `MockSdidStrategy` — knows exactly the seeded `MOCK_TEST_NIDS`, returns deterministic reference biometrics/attributes, supports latency/failure injection. This is the only working strategy in Phases 0–2 (there is no SDID sandbox).
- **`oidc` / `proprietary`** (today): `createSdidProvider` **throws at broker startup** — "SDID strategy pending integration answers A1/A2". Setting either flag now is a controlled way to verify the flag plumbing, not a cutover.

When Phase 3 lands the real strategy (per SDID answers A1/A2), cutover is: implement `OidcEsignetStrategy` or `ProprietaryRestStrategy` behind the same `SdidProvider` contract, pass the shared contract-test suite (`packages/sdid-adapter/src/contract-tests.ts` — mock and real must pass identically), then flip `SDID_STRATEGY` and restart. No broker code changes: every strategy is automatically wrapped with the resilience layer (5 s timeout, 2 retries with jitter, circuit breaker at 5 consecutive failures / 30 s reset, zod boundary validation) and the audit hook.
