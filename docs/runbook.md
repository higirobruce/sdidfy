# Runbook — SDID Auth Bridge (broker)

Ops notes for the Phases 0–2 build plus the Phase 3 hardening that needed no SDID answers (observability §11–§12, anomaly detection §14, real push §13). Everything here is verified against `apps/broker/src` as of this commit; `apps/broker/src/config.ts` is the authoritative source for configuration.

## 1. Services

| Service | What | Notes |
|---------|------|-------|
| Broker | NestJS app, `apps/broker` (`pnpm broker:dev` / `node dist/main.js`) | Listens on `BROKER_PORT` (default 3100). Stateless; safe to run multiple replicas (audit chain is advisory-lock serialised, challenges/limits live in Redis) |
| PostgreSQL 16 | Primary store + append-only audit + dev signing keys | Dev credentials: `sdid`/`sdid_dev`, database `sdid_bridge` |
| Redis | Challenges, rate limits, lockouts, token denylist, code-flow stash, anomaly-detector windows | Single logical instance; all state is short-TTL and reconstructible except active lockouts |
| Prometheus (or equivalent) | Scrapes `GET /metrics` with `METRICS_TOKEN` | §11. Orchestrator probes `GET /healthz` (liveness) and `GET /readyz` (readiness) — §12 |
| device-sim / test-rp | CLIs (`apps/device-sim`, `apps/test-rp`) | Dev/test only. Both default to `http://localhost:3000` — set `BROKER_URL` (or `--broker`) to the real broker address |

Push is wake-only and, today, **undeliverable**: the FCM and APNs transports are fully implemented but no GoR credentials exist, so both are declared seams that throw descriptively and the delivery is recorded as `outcome="not_configured"` (§13). Devices discover pending CIBA requests by polling `GET /v1/device/ciba/pending`, which is why an unconfigured transport degrades wake latency and nothing else.

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
| `ATTESTATION_MODE` | `mock` | `mock` accepts the simulator's structured attestation tokens; `strict` runs the real Play Integrity / App Attest verifiers from `@sdid/attestation` (§10) |
| `ATTESTATION_NONCE_TTL_SECONDS` | `300` | Lifetime of a server-issued attestation nonce (§10). Enforced `<=` the verifiers' max token age (300 s) — the broker refuses to boot in strict mode if it is larger |
| `ANDROID_PACKAGE_NAME` | *(empty)* | Our Android package name. Strict mode only; empty is a configuration error, not "accept any" |
| `ANDROID_CERT_SHA256_DIGESTS` | *(empty)* | Comma-separated base64 SHA-256 digests of accepted app-signing certificates |
| `PLAY_INTEGRITY_CREDENTIALS_JSON` | *(empty)* | Service-account credentials (path or inline JSON) for the Play Integrity decode call. **The decoder is an unimplemented seam** (§10) |
| `IOS_APP_ID` | *(empty)* | Apple App ID `<teamId>.<bundleId>`; production boot validates the shape, not just presence |
| `IOS_ATTESTATION_PRODUCTION` | `false` | `false` accepts Apple's development aaguid. Production must be `true` |
| `ADMIN_API_TOKEN` | `dev-admin-token` | Bearer token for `/admin/*` (RP onboarding, audit verify). Prod: never the default (§8) |
| `ID_TOKEN_TTL_SECONDS` | `300` | ID token lifetime |
| `ACCESS_TOKEN_TTL_SECONDS` | `600` | Access token lifetime (also the `expires_in` in token responses) |
| `SESSION_TTL_SECONDS` | `900` | First-party device-session JWT lifetime |
| `CHALLENGE_TTL_SECONDS` | `120` | Single-use signing-challenge TTL (activation, login, CIBA approve/deny) |
| `CIBA_REQUEST_TTL_SECONDS` | `180` | Default CIBA auth-request lifetime (RPs may request up to 600); also the code-flow transaction/stash TTL |
| `CIBA_POLL_INTERVAL_SECONDS` | `2` | `interval` returned from `/oidc/bc-authorize` |
| `AUTH_CODE_TTL_SECONDS` | `60` | Authorization-code lifetime (single-use) |
| `REVERIFY_INTERVAL_SECONDS` | `7776000` (90 d) | SDID re-verification cadence (§6.1). A binding older than this since its last SDID contact is re-asserted at its next auth; also the trigger the proactive sweep uses |
| `METRICS_ENABLED` | `true` | Serve `GET /metrics`. `false` makes the route 404 — it is never served unprotected (§11) |
| `METRICS_TOKEN` | *(empty)* | Bearer token for `/metrics`. Empty falls back to `ADMIN_API_TOKEN`, which **production refuses** (§11) |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` \| `silent` — JSON structured logs (§12.3) |
| `ANOMALY_ENABLED` | `true` | Abuse-pattern detection on the audit stream (§14). Detection only — never auto-bans |
| `ANOMALY_SOURCE_PEPPER` | `dev-only-…` | HMAC key for the truncated source handle on a detection. Production refuses the dev value |
| `ANOMALY_ENROL_PROBE_DISTINCT_NIDS` / `…_WINDOW_SECONDS` | `10` / `900` | T14 enrolment probing: distinct pseudo-NIDs from one source IP |
| `ANOMALY_ATTESTATION_REJECTION_THRESHOLD` / `…_WINDOW_SECONDS` | `10` / `900` | T2/T3 attestation rejections from one source IP |
| `ANOMALY_CIBA_INITIATION_THRESHOLD` / `…_WINDOW_SECONDS` | `200` / `300` | T9 CIBA initiations from one RP — set below the 60/min hard limit so it leads it |
| `ANOMALY_SIGNATURE_FAILURE_THRESHOLD` / `…_WINDOW_SECONDS` | `5` / `900` | T1/T4 signature failures against one binding (matches the login lockout) |
| `ANOMALY_SUSPICIOUS_DENIAL_THRESHOLD` / `…_WINDOW_SECONDS` | `3` / `3600` | T7 citizen-flagged denials against one RP — deliberately low |
| `PUSH_TIMEOUT_MS` | `5000` | Per-provider push request timeout (§13) |
| `FCM_PROJECT_ID` / `FCM_CREDENTIALS_JSON` | *(empty)* | Firebase project + service-account key (path or inline JSON). **Unconfigured seam today** |
| `APNS_TEAM_ID` / `APNS_KEY_ID` / `APNS_PRIVATE_KEY_P8` / `APNS_TOPIC` | *(empty)* | Apple token auth: team id, key id, `.p8` (path or inline PEM), bundle id. **Unconfigured seam today** |
| `APNS_PRODUCTION` | `false` | `false` targets `api.sandbox.push.apple.com`; production must be `true` |
| `APNS_PUSH_TYPE` | `alert` | `alert` (content-free loc-key, delivered promptly) \| `background` (silent, iOS-throttled) |

The repo-root `.env.example` documents every variable above with the same annotations, Phase 0–2 and Phase 3 together — it is the single file the README quickstart copies, so a new environment cannot silently miss the Phase 3 block.

Mock-adapter test knobs (read by `MockSdidStrategy`, dev only): `SDID_MOCK_LATENCY_MS` (simulated per-call latency), `SDID_MOCK_FAILURE_RATE` (0..1 probability of an injected `SdidUnavailableError`) — used for resilience/circuit-breaker testing.

CLI-side env (not broker config): `BROKER_URL`, and for `test-rp`: `CLIENT_ID`, `CLIENT_SECRET`, `ADMIN_API_TOKEN`.

## 3. Boot behaviour

1. `loadConfig()` parses env (zod) and applies production guard rails (§8) — a bad production config fails here, before anything listens.
2. **Migrations auto-run at startup** (`main.ts` → `runMigrations()`): files in `apps/broker/migrations/*.sql`, lexicographic order, each in its own transaction, tracked in the `_migrations` table. Forward-only; there are no down migrations. `pnpm db:migrate` runs the same runner standalone. Concurrent replicas racing the same migration will conflict loudly rather than corrupt — prefer migrating once before a rolling deploy.
3. `KeysService.onModuleInit` ensures an active ES256 signing key exists in `signing_keys`, generating one on first boot, and loads the JWKS into memory.
4. The app listens on `BROKER_PORT` and logs a `broker_listening` JSON line naming the port, issuer, SDID strategy, attestation mode, and whether metrics and anomaly detection are on.

The JSON logger is constructed **before** Nest, so migration and module-init output is structured and redacted too — the lines you most need during a bad boot are the earliest ones. The correlation middleware is registered before the router, so every line emitted while handling a request (including from the global exception filter) carries the same `requestId` (§12.3).

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
| Attestation-nonce mint per IP | `rl:enrol:attest:ip:<ip>` | 60 / hour (unauthenticated free-work endpoint) |
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
| `attnonce:` | Single-use attestation nonces `{purpose, nonce}`, consumed atomically with GETDEL (§10) | `ATTESTATION_NONCE_TTL_SECONDS` (300 s) |
| `revoked:` | Token denylist by `jti` | Until token `exp` |
| `codeflow:` | Auth-code-flow stash `{codeChallenge, nonce, redirectUri, state}` keyed by transaction | `CIBA_REQUEST_TTL_SECONDS` (180 s) |
| `anom:` | Anomaly-detector windows: counters, the distinct-pseudo-NID set per source, and `anom:alerted:*` one-alert-per-window suppression keys (§14) | The pattern's window |

To lift a lockout manually (e.g. verified support case): `DEL lockout:enrol:nid:<pseudoNid>` / `DEL lockout:login:<bindingId>`. Never bulk-delete `challenge:` keys — that only invalidates in-flight authentications.

Redis loss is safe but lossy: in-flight challenges and code-flow stashes fail (users retry), rate/lockout counters reset, and **token denylist entries are lost** — revoked-but-unexpired tokens become acceptable again until `exp`. After an unplanned Redis flush, consider the outstanding-token window (≤ 600 s) exposed.

## 8. Dev vs production guard rails

`loadConfig()` refuses to boot with `NODE_ENV=production` unless:

- `NID_PEPPER` does not start with `dev-only`;
- `ADMIN_API_TOKEN` is not `dev-admin-token`;
- `ATTESTATION_MODE=strict`.

With `ATTESTATION_MODE=strict` (which production also requires), boot additionally refuses unless **all** of these carry real values — an empty app identifier or trust anchor makes a verdict meaningless rather than permissive:

- `ANDROID_PACKAGE_NAME` non-empty;
- `ANDROID_CERT_SHA256_DIGESTS` contains at least one digest;
- `PLAY_INTEGRITY_CREDENTIALS_JSON` non-empty;
- `IOS_APP_ID` shaped `<teamId>.<bundleId>`;
- `IOS_ATTESTATION_PRODUCTION=true`;
- `ATTESTATION_NONCE_TTL_SECONDS <= 300` (checked in every environment, not just production).

Phase 3 adds four more production rails (all in `loadConfig()`; see `src/config.spec.ts`):

- `METRICS_TOKEN` must be set and **must differ from `ADMIN_API_TOKEN`** whenever `METRICS_ENABLED=true` — or set `METRICS_ENABLED=false`. A scrape credential lives in monitoring config that a much wider group can read; if it also onboards relying parties, every monitoring operator holds a privilege escalation (T12).
- `ANOMALY_SOURCE_PEPPER` must not be the dev value, or the source handles in the audit trail are recomputable by anyone with the repository.
- Push must be either fully configured or fully absent per provider. **Half-configured fails the boot**: a deployment that believes it has push and silently does not is worse than one that knows it has none.
- `APNS_PRODUCTION=true` whenever APNs is configured — the sandbox gateway accepts sends that reach no real device.

Additional production notes:

- Strict mode is wired end-to-end but **not deployable yet** — see §10 for exactly what is missing. Existing bindings and RP flows are unaffected by attestation mode.
- The dev key store keeps private JWKs in Postgres (`signing_keys`) — a dev-only posture; production swaps `KeysService` internals for the GoR KMS/HSM (see `docs/DECISIONS.md` f).
- Production is additionally gated on DPIA + external pentest (spec 06 §8, 09 §5) — guard rails are necessary, not sufficient.

## 9. Mock → real SDID cutover (spec 02 §4)

The adapter strategy is feature-flagged: `SDID_STRATEGY=mock|oidc|proprietary`, consumed by `createSdidProvider` (`packages/sdid-adapter/src/index.ts`) via the broker's `SdidModule`.

- **`mock`** (current): `MockSdidStrategy` — knows exactly the seeded `MOCK_TEST_NIDS`, returns deterministic reference biometrics/attributes, supports latency/failure injection. This is the only working strategy in Phases 0–2 (there is no SDID sandbox).
- **`oidc` / `proprietary`** (today): `createSdidProvider` **throws at broker startup** — "SDID strategy pending integration answers A1/A2". Setting either flag now is a controlled way to verify the flag plumbing, not a cutover.

When Phase 3 lands the real strategy (per SDID answers A1/A2), cutover is: implement `OidcEsignetStrategy` or `ProprietaryRestStrategy` behind the same `SdidProvider` contract, pass the shared contract-test suite (`packages/sdid-adapter/src/contract-tests.ts` — mock and real must pass identically), then flip `SDID_STRATEGY` and restart. No broker code changes: every strategy is automatically wrapped with the resilience layer (5 s timeout, 2 retries with jitter, circuit breaker at 5 consecutive failures / 30 s reset, zod boundary validation) and the audit hook.

## 10. Attestation: nonces and strict mode (spec 03 §2 step 1, 05 §4, 06 T2/T3/T4)

### The nonce round-trip

Enrolment now begins one call earlier:

```
POST /v1/enrol/attestation-challenge      (unauthenticated, rate-limited per IP)
  → { nonceId, nonce, expiresAt }
# app feeds `nonce` to Play Integrity / App Attest, which binds it UNDER the
# platform signature, then:
POST /v1/enrol/start   { ..., attestation: { platform, token, keyAttestation, nonceId } }
```

- `nonce` is 32 CSPRNG bytes, base64url. `nonceId` is the opaque handle the client echoes back.
- Stored at `attnonce:<nonceId>` for `ATTESTATION_NONCE_TTL_SECONDS` and **consumed with GETDEL** — one use, atomically, so a replay loses the race rather than being detected after the fact.
- The nonce is consumed **before** the verifier runs, and is not returned on failure: a client whose attestation is rejected mints a fresh nonce.
- Every mint writes an `auth.challenge_issued` audit row (`context.purpose = "attestation"`, nonce **value** never audited).
- Never bulk-delete `attnonce:` keys; that only fails in-flight enrolments.

`attestation.nonceId` is optional in the wire schema on purpose. Strict mode enforces its presence in `AttestationService`, so a missing nonce fails as a normal uniform attestation rejection instead of a shape-revealing validation error, and mock-mode clients (device-sim, e2e, the ghost-login demo) keep working untouched. Mock mode *consumes* a supplied nonce (so the simulator rehearses the production sequence) but never requires one and never fails on a stale one.

### What strict mode enforces

`AttestationService.verify(attestation, devicePublicKeyJwk)` in strict mode:

1. rejects any platform other than `android`/`ios` (`sim` is mock-only);
2. requires and consumes `nonceId`;
3. calls the platform verifier with `{ token, keyAttestation, expectedNonce, devicePublicKeyJwk, now }` — the **key binding** matters as much as the nonce: without it an attacker attests a genuine hardware key and enrols a software-held one;
4. maps the verdict onto the binding: `assuranceCap` (AL1 software-held / AL2 hardware-backed), `hardwareBacked`, and the verifier's `evidence` (verdict strings, key security level, app version) into the `device_bindings.attestation` JSONB. **No raw tokens or certificates are ever persisted.**

Failure behaviour, deliberately:

| Situation | Client sees | Where the truth goes |
|-----------|-------------|----------------------|
| Any rejection (bad nonce, replay, rooted device, wrong app, key mismatch, stale token) | `403 attestation_rejected` — *always the same body*: `"Device attestation could not be verified"` | Precise `code` + `detail` in the `enrolment.failed` audit row and the broker log (03 §7 — a precise reason tells an attacker which control to defeat) |
| Verifier unreachable, or the verifier throws | `503 attestation_unavailable` (retryable) | `logger.error` with the verifier detail |

"Could not check" is never "device failed" (that would lock out genuine citizens during a platform outage) and never an acceptance (that would be the bypass itself).

### Client contract — exact encodings the app MUST match

These are byte-level contracts between the authenticator app and the verifiers.
They are not negotiable at runtime and there is no fallback: get one wrong and
*every* enrolment fails with a uniform `attestation_rejected`, whose audit rows
will read `nonce_mismatch` with nothing else to go on. Verified against
`packages/attestation/src/key-attestation.ts` and `app-attest.ts`.

| What | Exact requirement |
|------|-------------------|
| Android attestation challenge | The **UTF-8 bytes of the `nonce` string** as returned by `/v1/enrol/attestation-challenge` — not the base64url-*decoded* 32 bytes, and not a re-encoding. Passed to `setAttestationChallenge()` at keypair generation. |
| iOS `clientDataHash` | `SHA256(utf8(nonce))`. Apple then binds `SHA256(authData ‖ clientDataHash)` into the credCert extension `1.2.840.113635.100.8.2`; the verifier recomputes both. |
| Android `keyAttestation` container | The X.509 chain, **leaf first**. Accepted as a JSON array of base64 DER strings, a PEM bundle, or a comma/whitespace-separated list of base64 DER. Liberal about the container, strict about the base64 inside it. |
| iOS `token` | base64 of the CBOR App Attest object (`fmt`/`attStmt`/`authData`) exactly as `DCAppAttestService` returns it. No `keyAttestation` field — on iOS the key attestation *is* the object. |
| Key identity | The attested key must be the **same** keypair whose public JWK is sent as `devicePublicKeyJwk`. Generating an attestation key separately from the signing key fails `key_mismatch`. |

The nonce is single-use and consumed before verification, so **the app must mint
a fresh nonce for every enrolment attempt**, including retries after a failure.

### What still blocks a real strict-mode deployment

Strict mode is wired, tested against stubbed verdicts, and guard-railed — but it cannot serve real citizens until:

1. **Play Integrity credentials.** `apps/broker/src/trust/play-integrity.decoder.ts` is a declared, throwing seam: no GoR service account exists for the Play console project, so `decodeIntegrityToken` cannot be called. Until it is implemented, Android strict enrolment fails closed with 503. Implementing it is a one-function swap.
2. **App identifiers.** `ANDROID_PACKAGE_NAME`, `ANDROID_CERT_SHA256_DIGESTS` and `IOS_APP_ID` need the real published app's values — they arrive with the Phase 2 React Native build, not before.
3. **iOS trust anchors and production flag.** App Attest chains verify to Apple's App Attest root; `IOS_ATTESTATION_PRODUCTION=true` is required or a dev-provisioned build attests successfully against production.
4. **A real client.** `device-sim` emits mock tokens; only the native app can produce tokens a real verifier accepts. Strict mode and the simulator are mutually exclusive by design (`sim` is refused in strict).

## 11. Metrics — `/metrics` (spec 09 §2 Phase 3)

### Endpoint and how it is protected

```bash
curl -s http://localhost:3100/metrics -H "Authorization: Bearer ${METRICS_TOKEN:-$ADMIN_API_TOKEN}"
```

Prometheus text exposition (`Content-Type: text/plain; version=0.0.4`), **hand-rolled with no third-party client library** — the broker sits on the citizen-authentication path, where every dependency is supply-chain surface for the pre-prod security gate (06 §8).

**Deployment choice: bearer token on the main port, not a second listener.** A second port is only a control if the network actually enforces it, and the GoR deployment target and its ingress rules are not settled (01 §3); a token is a control we can guarantee today and it composes with a network policy later. Use `METRICS_TOKEN` — a dedicated credential, never `ADMIN_API_TOKEN` (§8). Add a network policy restricting the port to the Prometheus scrapers when the topology is fixed; that is defence in depth, not a replacement.

`/metrics` carries **no citizen data at all**. Every label vocabulary is a bounded enum, and the registry actively refuses values shaped like identifiers — a 16-digit NID run, a uuid, a long hex hash, a high-entropy blob — as well as capping each family at 200 series. In `NODE_ENV=test` a violation throws (CI fails); everywhere else it is replaced with `__rejected__` and counted in `sdid_broker_metrics_dropped_series`, because a metrics bug must never break an authentication.

### Metric families

| Family | Type | Labels | What it answers |
|--------|------|--------|-----------------|
| `sdid_broker_enrolment_attempts_total` | counter | `outcome` | Enrolment funnel and where it fails (03 §2) |
| `sdid_broker_attestation_verdicts_total` | counter | `platform`, `mode`, `outcome`, `code` | Device/app attestation: accepted vs rejected (with the verifier's rejection code) vs *unavailable* (05 §4) |
| `sdid_broker_biometric_match_total` | counter | `band`, `matched`, `pad` | Match outcomes by **coarse score band only** — never a score, never tied to an identity (07 §4, T18) |
| `sdid_broker_ciba_requests_total` | counter | `flow` | Backchannel requests created (`ciba` / `code`) |
| `sdid_broker_ciba_decisions_total` | counter | `decision`, `flow`, `suspicious` | Citizen approve/deny, and whether they flagged it suspicious (T7) |
| `sdid_broker_ciba_expiries_total` | counter | `flow` | Requests that expired with no decision |
| `sdid_broker_tokens_issued_total` | counter | `grant_type` | Token responses minted |
| `sdid_broker_signature_verification_failures_total` | counter | `context` | Device-signature failures by flow leg (`activation` / `login` / `ciba-decision`) |
| `sdid_broker_rate_limit_hits_total`, `sdid_broker_lockout_hits_total` | counter | `scope` | Anti-automation refusals (06 §5) |
| `sdid_broker_anomaly_detections_total` | counter | `pattern` | Abuse patterns detected (§14) |
| `sdid_broker_sdid_call_duration_seconds` | histogram | `operation`, `outcome` | SDID adapter latency, as the broker experiences it (retries and backoff included) |
| `sdid_broker_sdid_circuit_open` / `_rejections_total` | gauge / counter | — | Circuit-breaker state, **inferred** from adapter errors (see caveat below) |
| `sdid_broker_audit_appends_total`, `sdid_broker_audit_append_failures_total` | counter | — | Append-only audit health (07 §4) |
| `sdid_broker_push_deliveries_total` | counter | `platform`, `outcome` | Wake-only push delivery (§13) |
| `sdid_broker_http_requests_total`, `sdid_broker_http_request_duration_seconds` | counter / histogram | `handler`, `status` | Traffic by **controller handler**, never URL — a URL carries `login_hint` (a pairwise subject) and authorization codes |
| `sdid_broker_readiness` | gauge | `component` | Last `/readyz` verdict per dependency |
| `sdid_broker_metrics_dropped_series` | gauge | — | Label combinations dropped at the cardinality ceiling |
| `sdid_broker_build_info` | gauge | `node`, `env` | Always 1; runtime identification |

**Circuit-breaker caveat.** The adapter's `SdidProvider` contract deliberately exposes no breaker state (02 §4), so the broker infers it: `sdid_broker_sdid_circuit_open` goes to 1 when a call is rejected with `SdidCircuitOpenError` and back to 0 on the next success. It is a faithful view of *outcomes*, not of internal state — a half-open probe is invisible, and the gauge is stale while no SDID calls are being made. Alert on `sdid_broker_sdid_circuit_rejections_total` rather than the gauge.

## 12. Health, readiness and alerting

### 12.1 Probes

| Endpoint | Auth | Meaning | Codes |
|----------|------|---------|-------|
| `GET /healthz` | none | **Is the process alive?** Touches no dependency, so a Postgres blip cannot get every replica killed and restarted — which would turn a recoverable dependency outage into a total one | `200 {"status":"ok"}` |
| `GET /readyz` | none | **Can this replica serve?** Checks Postgres (`SELECT 1`), Redis (`PING`) and the signing key (**a real ES256 signature**, not a row lookup) | `200 {"status":"ready", …}` / `503 {"status":"not_ready", …}` |

Both are unauthenticated because a kubelet or load-balancer health check cannot hold a credential, and gating a probe behind one turns a config mistake into a crash-loop. What makes that safe is that the bodies carry only `ok` / `fail` per component — no connection strings, no error text, nothing an attacker could not learn by watching the service fail. Failure detail goes to the structured log.

```json
{"status":"not_ready","checks":{"postgres":"ok","redis":"fail","signing_key":"ok"}}
```

Orchestrator wiring: liveness → `/healthz`; readiness → `/readyz`. Each check has a 2 s timeout, so a hung dependency reads as "not ready" rather than hanging the probe.

The signing-key probe signs a throwaway token rather than asserting a row exists. Today those coincide; once key custody moves to KMS/HSM (decision #5) they diverge exactly when it matters — an expired credential, a revoked grant, an unreachable HSM — and this probe is what takes the replica out of rotation instead of failing citizens' logins.

### 12.2 Alert-worthy conditions

Suggested starting thresholds. Tune against real traffic in the pilot cohort — these are chosen to be actionable rather than statistically calibrated (there is no production baseline yet).

| Condition | Suggested rule | Severity | Why |
|-----------|----------------|----------|-----|
| Audit append failing | `increase(sdid_broker_audit_append_failures_total[5m]) > 0` | **page** | Audit is not best-effort: a failed append fails the operation it was recording (07 §4). Any non-zero value means the broker is refusing security-relevant work |
| Not ready | `min_over_time(sdid_broker_readiness[5m]) == 0` for any component | **page** | Postgres/Redis/signing key down on a replica |
| Signing key unusable | `sdid_broker_readiness{component="signing_key"} == 0` | **page** | No tokens can be minted; distinct from a DB outage in remediation |
| SDID circuit rejecting | `increase(sdid_broker_sdid_circuit_rejections_total[5m]) > 0` | **page** | Enrolment and re-verification are both blocked while it is open |
| SDID latency | `histogram_quantile(0.95, rate(sdid_broker_sdid_call_duration_seconds_bucket[10m])) > 3` | ticket | Approaching the adapter's 5 s timeout; enrolments will start failing |
| Attestation verifier unavailable | `rate(sdid_broker_attestation_verdicts_total{outcome="unavailable"}[10m]) > 0.1/s` | **page** | "We could not check" — a platform or credential outage refusing genuine citizens with 503 |
| Attestation rejection spike | rejection share `> 20%` over 30 m | ticket | A bad app release, an expired signing certificate, or a rooted-device campaign. Break down by `code` first |
| Enrolment success rate | success share `< 60%` over 30 m | ticket | Compare `sdid_broker_biometric_match_total{matched="false"}` (match quality) against attestation rejections to tell which leg is failing |
| PAD failure share | `pad="fail"` share `> 10%` over 1 h | ticket | Presentation-attack attempts, or a PAD regression (T8). Both need a human |
| Match band drift | sustained shift in the `band` distribution week over week | ticket | Matching-engine regression or evasion (T18) — the reason bands are recorded at all |
| CIBA expiry share | expiries / requests `> 30%` over 15 m | ticket | Citizens are not seeing prompts — usually push (§13), possibly an app problem |
| Signature failures | `rate(sdid_broker_signature_verification_failures_total[10m]) > 0.2/s` | ticket | Replay attempts, a client crypto bug, or a bad app release |
| Any anomaly detection | `increase(sdid_broker_anomaly_detections_total[15m]) > 0` | ticket, **review same day** | Detection is deliberately never automatic action (§14) — the alert IS the response |
| Suspicious-denial spike | `increase(sdid_broker_anomaly_detections_total{pattern="suspicious_denial_spike"}[1h]) > 0` | **page** | Citizens are actively reporting prompts they did not request: the clearest signal of an approval-spraying campaign (T7) |
| Push delivery failing | `outcome!="delivered"` share `> 20%` over 15 m, once push is configured | ticket | Expected to be 100% `not_configured` today (§13) |
| Metric cardinality | `sdid_broker_metrics_dropped_series > 0` | ticket | A metric is being labelled with something unbounded — fix the call site |
| Rate-limit/lockout surge | `rate(sdid_broker_rate_limit_hits_total[15m])` well above baseline | ticket | Either an attack or a legitimate-traffic misconfiguration; correlate with anomaly detections |

Also keep the existing audit-chain verification on its daily schedule (§5) — `intact: false` is a security incident, not an alert threshold.

### 12.3 Structured logs

`LOG_LEVEL` selects `debug|info|warn|error|silent`. Output is one JSON object per line on stdout:

```json
{"ts":"2026-08-26T04:34:09.730Z","level":"info","msg":"http_request","requestId":"1bbdaa79-…","handler":"EnrolmentController.start","method":"POST","path":"/v1/enrol/start","status":200,"outcome":"ok","durationMs":41.2}
```

- **Correlation id.** Every line emitted while handling a request carries `requestId`. An inbound `x-request-id` is honoured (so a GoR ingress or an RP trace id ties systems together, the same reason SDID's `txnRef` rides in the audit trail) but only in a narrow shape — 8–64 chars of `[A-Za-z0-9_.:-]`; anything else, including log-injection newlines and oversized headers, is replaced with a fresh uuid. The id is echoed back in the `x-request-id` response header, so a citizen or RP can hand you the id from a failed request.
- **Redaction is unconditional and total.** Two independent passes run over everything the logger touches: a deny-list of field names (kills the whole subtree — `sample`, `nid`, `token`, `signature`, `nonce`, `pushToken`, `clientSecret`, …) and a value scrubber that replaces any run of 16+ digits with `[redacted-nid]` wherever it appears, including inside free text, error messages and stack traces. Binary is never rendered (`[binary N bytes]`), strings over 512 chars are truncated. Tested in `apps/broker/src/logging/redact.spec.ts`.
- **Never logged at all:** request/response bodies (an enrolment body holds a biometric sample), query strings (`login_hint` is a pairwise subject; the code-flow redirect carries an authorization code), and headers (`authorization` is a bearer token). Only `req.path` is recorded.
- Because `code` is a deny-listed field name (the OAuth authorization code), log error and rejection codes as `error_code` / `rejection_code`.
- Operational logs are a **separate stream from the audit trail** (06 §7) with their own, shorter retention. That separation is load-bearing: it is why a raw source IP may appear in a log line and never in an audit row (§14).

## 13. Push setup (spec 05 §5, T6)

### The wake-only contract

The payload is `{"type":"sdid.wake","v":1}` and nothing else. No auth data, no RP name or logo, no binding message, no scopes, no `auth_req_id`, no citizen/pseudo-NID/pairwise/binding identifier. The app is woken and then **pulls** the real pending request over the authenticated backchannel (`GET /v1/device/ciba/pending`, 04 §3 step 5).

This is enforced structurally, not by convention: `PushTransport.send(deviceToken)` takes only a device token, so there is no parameter through which request detail could be smuggled into a notification. A push payload is unauthenticated data delivered by a third party to a lock screen — if it carried the request, spoofing it would fabricate an approval prompt (T7) and a shoulder-surfer would learn which service a citizen is signing in to.

### Registration, rotation, removal

| Operation | Call | Notes |
|-----------|------|-------|
| Register / rotate | `POST /v1/device/push-token` `{platform:"fcm"\|"apns", token}` | Device-session authenticated; applies to the **session's own** binding — the body has no binding id, so one device can never redirect another citizen's wakes |
| Remove | `POST /v1/device/push-token/remove` | App logout / notifications disabled |
| Automatic removal | — | On binding revocation (citizen revoke **and** SDID re-assert failure), in the same statement as the revocation (06 §4); and whenever a provider reports the token dead (`410`, `UNREGISTERED`, `BadDeviceToken`) |

Storage: `device_bindings.push_platform`, `push_token`, `push_token_updated_at` (migration `0003_push_tokens.sql`). The token is stored in the clear because it *is* the address the provider requires — it cannot be hashed. It is a device handle, not a citizen identifier: it carries no identity, providers rotate it freely, it is deny-listed from logs, and it is cleared on revocation.

### Configuring FCM (Android)

1. Create the GoR Firebase project for the authenticator app; note the project id → `FCM_PROJECT_ID`.
2. Create a service account with the **Firebase Cloud Messaging API** enabled and download its JSON key → `FCM_CREDENTIALS_JSON` (a filesystem path, e.g. a Kubernetes secret mount, or the JSON inline).
3. Restart. The broker mints a service-account assertion, exchanges it at `oauth2.googleapis.com/token` (caching the access token until ~2 min before expiry) and posts **data-only** messages to `fcm.googleapis.com/v1/projects/{id}/messages:send`. Data-only means the OS renders nothing the broker supplied.

### Configuring APNs (iOS)

1. In the Apple developer account, create an **APNs auth key** (`.p8`) — token auth, not certificates: it does not expire annually and is one credential for every topic.
2. Set `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_PRIVATE_KEY_P8` (path or inline PEM), `APNS_TOPIC` (the app bundle id), and `APNS_PRODUCTION=true`.
3. Choose `APNS_PUSH_TYPE`:
   - `alert` (default) — the payload carries a **`loc-key` only**; the device renders a string from the app's own Kinyarwanda/English/French bundle (05 §7), so the broker never sends display text. Delivered promptly.
   - `background` — completely silent, but iOS throttles background pushes and may delay them for minutes, which can exceed the 180 s CIBA window. Use only with evidence it is fast enough on target devices.

The broker keeps one long-lived HTTP/2 session to Apple (APNs penalises connection churn) and refreshes the ES256 provider token every 40 minutes, inside Apple's 20–60 minute band.

### Current status and failure behaviour

**No GoR Firebase project and no GoR Apple team exist yet.** Both transports are therefore declared, clearly-marked seams — the same discipline as `trust/play-integrity.decoder.ts` — that throw a descriptive `PushNotConfiguredError` naming exactly which settings are missing. The protocol code is complete but has **never been exercised against the real endpoints**: treat the first configured send as an integration test against one device, not a rollout.

`PushService.wake()` never throws and never fails the caller. Push initiation happens inside `/oidc/bc-authorize` and `/oidc/authorize`; if a provider outage or a missing credential could fail those, an RP-facing authentication would fail for a reason unrelated to the citizen's identity. Every failure is a metric plus a log line:

| `sdid_broker_push_deliveries_total{outcome}` | Meaning |
|---|---|
| `delivered` | Provider accepted it |
| `unregistered` | Token is dead; the broker cleared the column |
| `failed` | Transient/unknown provider failure |
| `not_configured` | The seam — expected in every environment today |
| `no_token` / `lookup_failed` | Citizen has no registered device address / the DB lookup failed |

## 14. Anomaly detection (spec 06 §5)

### Detection only — never automatic action

Crossing a threshold writes **an audit row, a metric and a log line**. Nothing is banned, blocked, throttled, suspended or revoked. That is a design decision, not an unfinished feature.

Every detector works on a coarse signal, and every one of those signals has a benign explanation that occurs in normal operation: many distinct NIDs from one IP is an attacker probing the register — and also a district office, a university campus, or a whole mobile network behind carrier-grade NAT; an attestation-rejection burst is a rooted-device farm — and also a bad app release or a Play Integrity regression; a CIBA flood is a malicious RP — and also a pilot RP's load test. Auto-banning on any of these locks citizens out of a public service with no self-service path back (recovery is a full re-enrolment, 03 §5). **A false positive here denies a citizen a public service; a false negative is an alert a human reviews minutes later.** Rate limits and lockouts (§7) remain the automated controls — they are bounded, self-healing and per-actor.

So: an anomaly alert is a **same-day human review** item, not an automated response. Investigate with the audit trail and the metrics; if action is warranted, take it deliberately (suspend an RP via `/admin/rps/{id}/suspend`, tighten a rate limit, ship an app fix).

### Patterns, defaults, and where each signal comes from

| Pattern | Threshold / window (env) | Signal source | Threat |
|---------|--------------------------|---------------|--------|
| `enrolment_probing` | 10 distinct pseudo-NIDs / 15 min per source IP (`ANOMALY_ENROL_PROBE_*`) | Request path (`/v1/enrol/start`) | T14 — automated NID probing. Counts **distinct identities**, not attempts, so a single citizen retrying is not flagged (that is the per-NID rate limit's job) |
| `attestation_rejection_burst` | 10 rejections / 15 min per source IP (`ANOMALY_ATTESTATION_REJECTION_*`) | Request path | T2/T3. `verifier_unavailable` is excluded — that is our outage, not their attack |
| `ciba_initiation_flood` | 200 / 5 min per RP (`ANOMALY_CIBA_INITIATION_*`) | Audit stream (`ciba.request_created`) | T9. Set below the 60/min hard limit (300 per 5 min) so it leads the throttle rather than trailing it |
| `signature_failure_burst` | 5 / 15 min per binding (`ANOMALY_SIGNATURE_FAILURE_*`) | Audit stream (`auth.login_failed`, `reason=signature_invalid`) | T1/T4 — a stolen device under attack, or replay. The lockout is the control; this is the visibility |
| `suspicious_denial_spike` | 3 / 1 h per RP (`ANOMALY_SUSPICIOUS_DENIAL_*`) | Audit stream (`ciba.request_denied`, `reportedSuspicious`) | **T7** — citizens actively reporting "I didn't request this". Deliberately low: this is the highest-signal input the system has |

Each pattern raises **once per window** per scope (a `SET NX` suppression key), so a sustained attack produces one alert, not one audit row per event — otherwise the attacker becomes a write amplifier on an append-only table.

### Why source IPs are handled the way they are

The audit trail is append-only and retained for years (07 §4/§6), so a source IP must never be written into it. Two consequences:

- IP-keyed detectors (`enrolment_probing`, `attestation_rejection_burst`) are called **directly from the request path**, not from the audit stream, because the IP is not in the audit row and must not be put there.
- The IP is HMAC'd with `ANOMALY_SOURCE_PEPPER` and truncated to 16 hex characters; only that handle reaches the audit row's `context.sourceHandle`. The **raw IP goes to the operational log**, which has its own short retention — the practical meaning of 06 §7's "audit stream is separate from operational logs".

A detection audit row looks like:

```json
{"actor":{"type":"system"},"action":"admin.action","result":"failure",
 "context":{"op":"anomaly-detected","pattern":"enrolment_probing","observed":10,"threshold":10,
            "windowSeconds":900,"sourceHandle":"9f2c…","action":"none — detection only, human review required"}}
```

The shared `AUDIT_ACTIONS` vocabulary (`@sdid/shared`) has no `security.anomaly_detected` member, so detections are recorded under `admin.action` with a `system` actor and an `op` discriminator — the same pattern `admin.controller.ts` already uses for `reverify-sweep`. **Query anomalies by `context->>'op' = 'anomaly-detected'`**, e.g.:

```sql
SELECT ts, context->>'pattern' AS pattern, context->>'observed' AS observed, context->>'sourceHandle' AS source
  FROM audit_events
 WHERE context->>'op' = 'anomaly-detected'
 ORDER BY seq DESC LIMIT 50;
```

Adding a dedicated audit action to `@sdid/shared` is the obvious follow-up; `ANOMALY_AUDIT_ACTION` in `anomaly.service.ts` is the single line that changes.

Detector windows live in Redis under `anom:`, so counting aggregates correctly across replicas and survives a broker restart; a Redis flush resets every window (§7). The audit-stream subscription itself is in-process and post-commit — a subscriber only ever sees events that made it into the tamper-evident chain, and it cannot roll one back. There is no durable queue: an event appended while a replica is mid-restart is simply not counted by that replica.
