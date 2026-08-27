# `@sdid/sdid-adapter`

The **only** module in this monorepo that talks to SDID/NIDA or holds SDID credentials (`02` §4).
The broker depends on the `SdidProvider` contract from `@sdid/shared` and nothing else, so swapping
mock for real SDID is a configuration change, not a code change.

```
createSdidProvider(opts)
  └─ strategy            MockSdidStrategy | OidcEsignetStrategy | ProprietaryRestStrategy
     └─ ResilientSdidProvider   timeout · retry-with-jitter · circuit breaker · zod boundary validation
        └─ withAuditHook        one audit record per call, txnRef-linked, pseudonymous subject
```

Every strategy composes **identically**. A real strategy never bypasses resilience or audit.

---

## 1. `SDID_STRATEGY` — what the flag does

`SDID_STRATEGY` (read by the broker's config, passed to `createSdidProvider({ strategy })`) selects
the strategy at boot. Nothing else in the broker changes.

| Value | Strategy | Status |
|---|---|---|
| `mock` | `MockSdidStrategy` | 🟢 Complete. Seeded test identities (`MOCK_TEST_NIDS`), latency/failure injection. The only usable value today — there is no SDID sandbox (Q4). |
| `oidc` | `OidcEsignetStrategy` | 🟡 Scaffolded. Transport, discovery, client auth, token handling, validation and error mapping are real. The SDID-specific request/response shapes are **unfilled holes blocked on A1/A2**. |
| `proprietary` | `ProprietaryRestStrategy` | 🟡 Scaffolded. Same: base URL, auth schemes, call layer, validation and error mapping are real; payload shaping is blocked on A1/A2. |

**Fail-closed:** with `strategy: 'oidc'` or `'proprietary'`, `createSdidProvider` throws
`SdidConfigurationError` at construction unless every A1/A2-dependent adapter function is supplied.
It will not boot into a state where an SDID answer has been guessed. Pass
`requireFullyConfigured: false` only for deliberate partial-cutover testing — the unfilled methods
still throw at call time; they never return fabricated data.

---

## 2. What is REAL today (works without A1/A2)

Both real strategies already implement, and are tested for:

- **HTTP transport seam** (`SdidHttpTransport`) — Node `fetch` by default, injectable for tests.
  Byte-oriented, so a JSON, multipart, binary or SOAP-over-HTTP answer to A1 all fit.
- **Socket-level deadline** mapped to `SdidTimeoutError` regardless of transport implementation.
- **Client authentication (Q3, detail A3)**
  - OIDC: `client_secret_basic`, `client_secret_post`, `private_key_jwt` (RFC 7523, RS256/ES256,
    signed with `node:crypto` — no third-party JOSE library).
  - Proprietary: `api-key` header, static bearer, OAuth2 client-credentials, or a `custom` signer
    (HMAC / WS-Security / nonce schemes). mTLS is a transport concern (C1/C2), not a config value.
- **Client-credentials token cache** with pre-expiry refresh, concurrent-request de-duplication
  (no token-endpoint stampede against an unknown quota — A5), and invalidation on 401/403 so a
  rotated credential (A3) recovers on the next attempt rather than after a redeploy.
- **OIDC discovery** — fetch, zod-validate, cache with TTL, de-duplicate concurrent fetches, and
  **reject a document whose `issuer` does not match the configured issuer** (mix-up defence).
- **Boundary validation (02 §4)** — every response zod-validated before it reaches the broker;
  error messages carry zod issue paths and codes only, never received values.
- **Error taxonomy mapping** — `404` (or a configured status) → `SdidUnknownIdentityError`;
  `401`/`403` → `SdidUnavailableError` (never mislabelled as an unknown citizen); `429` → unavailable
  with quota context; `5xx`/transport failure → unavailable; abort → `SdidTimeoutError`;
  schema failure → `SdidMalformedResponseError`.
- **Pseudonymous subject (Q8)** — `sdidSubject` is always **our** peppered HMAC of the NID.
  SDID's own subject identifier is never persisted.
- **Scope policy (Q9)** — applied by the strategy, not by the deployment's adapter function, so a
  mapping mistake cannot widen what the broker receives.
- **Q12 semantics** — a `reassert` checker that raises `SdidUnknownIdentityError` is reported as
  `{ valid: false }`: an identity SDID no longer knows is our revoked/deceased signal.

### Biometric discipline (`07` §1, `10` non-negotiables)

Reference-template bytes returned by a real strategy go straight into the in-memory
`BiometricReference` and are matched and discarded within the same request. They are **never**
logged, cached, written to disk, or placed in an error or audit record. Raw 16-digit NIDs never
appear at rest or in audit — only the peppered HMAC pseudonym. Tests assert both properties on
success and failure paths.

---

## 3. What is BLOCKED — and on which question

Each hole is an explicit, typed, injectable configuration point. Unconfigured, it throws
`SdidConfigurationError` (which names the option path and the open question, is never retried, and
never trips the circuit breaker) — it does not fall back to a guess.

| Option | Blocked on | What we need answered |
|---|---|---|
| `oidc.referenceBiometric` / `proprietary.referenceBiometric` | **A2 (critical)** | Does NIDA return the enrolled reference template per request? Endpoint, request shape, response encoding (ISO/IEC 19794 template? JPEG2000? base64 in JSON? raw bytes?), and whether **fingerprint** is served at all. |
| `oidc.attributes` (`buildRequest` + `claimNames`) | **A1** | How an identity is named to the attribute/userinfo endpoint — in a standard OIDC flow the subject is bound to the token, but we authenticate as a service (client-credentials) — and the **claim names** SDID returns. |
| `proprietary.attributes` | **A1** | The attribute endpoint, its request payload, and its response field names. |
| `oidc.reassert` / `proprietary.reassert` | **A1** (+ Q12) | The re-verification call shape and how SDID signals a revoked/deceased identity. |
| `oidc.subjectResolver` / `proprietary.subjectResolver` | **A1/A3** | See below — this one also needs a data-protection decision. |
| `tokenScopes` / `auth` credentials | **A3** | Token endpoint, scope names, credential issuance, rotation policy + grace period. |
| `issuer` / `baseUrl` | **A4** | Production endpoint hosts (and the hosts/ports infra must allow-list — C1). |

### The `subjectResolver` hole is not just a config value

The v1 `/userinfo` path calls `getAttributes` with the **stored `sdidSubject`**, because raw NIDs
are deliberately not persisted (`07` §3). A real strategy therefore needs a way to name that
identity upstream, and we do not know what SDID accepts:

- **Expected answer:** SDID accepts its own stable subject identifier; the resolver maps our
  pseudonym → that identifier. Storing an SDID-side opaque subject is *probably* acceptable under
  `07` §3, **but it is a new stored identifier and needs DPO sign-off** — flag it in the DPIA.
- **Bad answer:** SDID only accepts a raw NID. That path is not implementable without storing raw
  NIDs, which `07` §3 forbids. That is an escalation, not a configuration choice.

The test fixture's resolver is backed by a raw-NID table; that is acceptable **only** because those
are fixture NIDs. Do not copy that shape into production.

`STANDARD_OIDC_CLAIM_NAMES` (`name` / `birthdate` / `address.formatted`) is exported as an
**opt-in convenience**, not a default. Pass it only after A1 confirms SDID uses OIDC Core §5.1
standard claims — reading the wrong claim would put the wrong data in a citizen's token.

---

## 4. Cutover checklist (Phase 3)

1. **Get A1 answered** → pick `SDID_STRATEGY=oidc` or `proprietary`. Decision `10` #1.
2. **Get A2 answered** → write the `referenceBiometric` fetcher. This is the critical path.
3. **Get A3/A4** → set `issuer`/`baseUrl`, the `clientAuth`/`auth` block, `tokenScopes`, and confirm
   the rotation policy + grace period against the token cache's behaviour.
4. **C1**: allow-list the SDID hosts/ports outbound from the broker tier.
5. **C2**: place SDID client credentials in the GoR KMS/HSM — never in the DB (`07` §5).
6. Write the deployment's adapter functions. `src/fake-sdid.fixture.ts` has a worked example of each
   (`fakeReferenceFetcher`, `fakeOidcAttributesConfig`, `fakeProprietaryAttributesFetcher`,
   `fakeReassertChecker`, `fakeSubjectResolver`). Each one zod-validates its response and logs
   nothing.
7. Resolve the `subjectResolver` question above, with the DPO.
8. Wire the config into the broker's `SdidModule` factory (`apps/broker/src/sdid/sdid.module.ts`) —
   add the `oidc` / `proprietary` block beside the existing `strategy` and `nidPepper`. Leave
   `requireFullyConfigured` at its default.
9. **A7**: obtain NIDA-provisioned test identities in production (there is no sandbox) before any
   real-endpoint run.
10. Run the contract suite against the real endpoint (§5), then the controlled prod cohort.
11. Confirm `A5` quotas against the re-verification cadence (`10` #9) before rollout.

---

## 5. Running the contract suite

The shared suite (`runSdidProviderContractTests`, `09` §3) is the cutover safety net: mock and both
real strategies pass **the same tests**.

```bash
pnpm --filter @sdid/sdid-adapter test
```

Today that runs the suite four times over the real strategies — bare and factory-composed — driven
against `FakeSdid` through the injected transport, plus the mock's two runs.

### Against a real SDID endpoint, when one exists

The suite takes a factory, so no test code needs to change — only the transport and configuration:

1. Leave the default transport in place (`createFetchTransport()`), or inject one carrying an mTLS
   client certificate if A3 requires it.
2. Point `issuer`/`baseUrl` at the real host and supply real credentials **from the environment**,
   never from a file in the repo.
3. Use **A7 test identities only** as `knownNid`. Never run the suite against a live citizen record
   — it performs reference-template fetches, which is real biometric processing.
4. Pick an `unknownNid` that is well-formed but provably unissued, agreed with NIDA.
5. Gate the run behind an env guard (e.g. `SDID_LIVE_CONTRACT=1`) so CI never reaches production;
   there is no sandbox and every call spends quota (A5).

```ts
runSdidProviderContractTests('OidcEsignetStrategy (LIVE)', () => ({
  provider: createSdidProvider({
    strategy: 'oidc',
    nidPepper: process.env.NID_PEPPER!,
    oidc: { issuer: process.env.SDID_ISSUER!, /* … A1/A2 adapters … */ },
  }),
  knownNid: process.env.SDID_TEST_NID!,   // A7-provisioned identity
  unknownNid: process.env.SDID_UNKNOWN_NID!,
}));
```

---

## 6. Files

| File | Role |
|---|---|
| `index.ts` | `createSdidProvider` factory + feature flag + fail-closed gap check |
| `mock-strategy.ts` | Phase 0–2 mock SDID (`02` §2) |
| `oidc-esignet-strategy.ts` | OIDC/eSignet strategy + its A1/A2 holes |
| `oidc-client-auth.ts` | Client-auth methods + client-credentials token cache |
| `proprietary-rest-strategy.ts` | Bespoke REST/SOAP strategy + its A1/A2 holes |
| `upstream.ts` | Shared gap types, call context, scope filter, identifier resolution |
| `http-transport.ts` | Transport seam, deadline, status→error mapping, JSON+zod parsing |
| `resilience.ts` | Timeout / retry / circuit breaker / boundary validation |
| `audit-hook.ts` | One audit event per call, pseudonymous, biometric-free |
| `pseudonym.ts` | Peppered HMAC subject derivation (Q8) |
| `contract-tests.ts` | The shared suite every strategy must pass (`09` §3) |
| `fake-sdid.fixture.ts` | In-memory fake SDID + worked adapter examples (tests only) |
