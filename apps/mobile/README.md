# `@sdid/mobile` — citizen authenticator (React Native)

The phone half of the SDID Auth Bridge (spec `docs/SPEC.md` 05). A citizen
enrols once — face matched 1:1 against NIDA, hardware key bound to the verified
identity (03 §2) — and thereafter approves every login by signing a broker
challenge with that key (04 §3).

`apps/device-sim` is the reference client for the same protocol. This package
speaks it byte-for-byte, minus the simulator's attack affordances.

---

## Read this first: what is real, and what is not

| Area | Status |
|------|--------|
| `src/core/**` — protocol client, keystore/biometric/attestation interfaces, error mapping, T7 pending logic | **Real and tested.** Plain TypeScript, zero React Native imports, 96 vitest tests |
| `src/i18n/**` — rw (default) / en / fr | **Real and tested.** Completeness, placeholder parity and fallback order are enforced by tests |
| `src/native/contract.ts` + `CONTRACT.md` | **Specification only.** TypeScript declarations typecheck; **no Swift and no Kotlin exists anywhere in this repo** |
| `src/native/*.rn.ts` | Written, **never compiled** — `react-native` is not installed here |
| `src/ui/**` | Written, **never rendered** — no Metro, no simulator, no device |
| Push (FCM/APNs) | **Not implemented here.** The app polls `GET /v1/device/ciba/pending`. As of the runbook this repo was built against, broker-side push was wake-only *and log-only* (runbook §1); if a device-token registration endpoint has since landed on the broker, add the registration call to `ProtocolClient` and keep the pull — the payload stays untrusted either way (T6) |
| Certificate pinning (T5) | **Not implemented.** Native work (CONTRACT.md §5). `assertPinnedTransport()` exists so a release build fails closed instead of shipping unpinned |
| Strict-mode attestation | **Blocked** on the broker's Play Integrity decoder seam and real app identifiers (runbook §10) |

> **No code in this package has ever run on a phone.** It has never been
> bundled by Metro, never launched in a simulator, never signed anything with a
> Secure Enclave or a StrongBox key. The Phase 2 exit criterion — "real phone
> enrols against mock SDID, then approves a CIBA login with a real
> hardware-backed signature" (09 §2) — is **not met** and cannot be met without
> the native work in `src/native/CONTRACT.md`.

What *is* established is that the protocol logic, the challenge-payload
discipline, the error mapping and the localisation are correct and provably so
under `vitest`, and that the native contract they sit on is written down
precisely enough to implement against.

---

## Layout

```
src/core/      pure TypeScript — runs and is tested under vitest
  client.ts        ProtocolClient: enrol, login, CIBA, devices, consents, activity
  keystore.ts      KeyStore interface + what the native side must guarantee
  biometrics.ts    BiometricPrompt (presentation) vs FaceCapture (enrolment bytes)
  attestation.ts   Attestation interface + the byte-level nonce encodings
  transport.ts     HTTP + retry policy + the pinning gate
  errors.ts        every broker error code → a citizen-facing message key
  pending.ts       T7: countdown, duplicate collapse, "multiple pending"
  wire.ts          endpoint paths + zod schemas for every parsed response
  testing/         ⚠ DEV/TEST ONLY doubles — must be excluded from release bundles
src/i18n/      rw (source of truth) / en / fr + a ~60-line type-safe lookup
src/native/    contract.ts (typechecked) · CONTRACT.md (Swift/Kotlin spec) · *.rn.ts glue
src/ui/        React Native screens
docs/          rn-dependencies.md — the RN packages needed, none installed
```

## ⚠ Before merging: the lockfile needs regenerating

This package was authored in an environment with no network access, so
`pnpm install` was never run and **`pnpm-lock.yaml` has no importer entry for
`apps/mobile`**. CI runs `pnpm install --frozen-lockfile`
(`.github/workflows/ci.yml`), which will fail until someone runs:

```bash
pnpm install        # at the repo root, then commit the updated pnpm-lock.yaml
```

Nothing new is being pulled from the registry — `zod@^3.24.1` is already in the
store via `@sdid/shared`, and `@sdid/shared` itself is a workspace link — the
lockfile just needs to learn that this workspace package exists.

`apps/mobile/node_modules` was hand-linked into the existing pnpm store so the
tests below could actually be run and verified. It is gitignored; a real
`pnpm install` replaces it.

## Commands

```bash
pnpm --filter @sdid/mobile test        # vitest — 96 tests
pnpm --filter @sdid/mobile typecheck   # tsc over src/core, src/i18n, src/native/contract.ts
pnpm --filter @sdid/mobile build       # same scope, emits dist/
```

### Why `tsconfig.json` excludes `src/ui` and `src/native/*.rn.ts`

Those files import `react` and `react-native`, which are **not installed** —
installing them here would break the workspace for every other package until a
full native toolchain exists. So:

- **`tsconfig.json`** (used by `typecheck`, `build`, and CI) covers `src/core`,
  `src/i18n` and `src/native/contract.ts`. That is every security-critical
  decision in the app, and it is green.
- **`tsconfig.app.json`** covers everything including the UI. It **fails today**
  by design; run it after installing `docs/rn-dependencies.md`:
  `pnpm --filter @sdid/mobile exec tsc -p tsconfig.app.json --noEmit`.

The trade-off is stated rather than hidden: the UI is unchecked TypeScript until
someone installs RN. Keeping the workspace green for the other agents working in
this repo was the higher priority.

### Metro and `.js` extensions

House style (and `module: NodeNext`) requires `.js` extensions on relative
imports. Metro does **not** apply TypeScript's `.js` → `.ts`/`.tsx` remapping.
Add a resolver shim in `metro.config.js`:

```js
config.resolver.resolveRequest = (context, moduleName, platform) => {
  const remapped = moduleName.startsWith('.') ? moduleName.replace(/\.js$/, '') : moduleName;
  return context.resolveRequest(context, remapped, platform);
};
```

Also exclude the test doubles from release bundles:

```js
config.resolver.blockList = [/src[\\/]core[\\/]testing[\\/].*/];
```

---

## Getting this onto a device (the honest list)

1. **Install the RN dependency set** — `docs/rn-dependencies.md`. Nothing below
   works until this is done.
2. **Write the four native modules** — `src/native/CONTRACT.md` §1–§4. This is
   the real work: Secure Enclave / StrongBox key generation with per-operation
   biometric auth, Play Integrity + App Attest, biometric capability checks, and
   a PAD-capable face capture. Budget for the DER → raw `r||s` signature
   conversion (§1.4) and the liveness SDK selection (§4, still **OPEN**).
3. **Wire certificate pinning** — CONTRACT.md §5, then pass a pinned transport
   into `createApp()`; `assertPinnedTransport` refuses an unpinned one in
   release.
4. **Implement `BindingStore`** on `expo-secure-store` / Keychain /
   EncryptedSharedPreferences, excluded from cloud backup. It holds
   `{bindingId, keyAlias, deviceLabel, assuranceLevel, enrolledAt}` — no NID, no
   session token, no key.
5. **Build a dev client**, point `brokerUrl` at a local broker
   (`pnpm broker:dev`, default `http://localhost:3100`) with
   `ATTESTATION_MODE=mock`, and use one of the seeded `MOCK_TEST_NIDS`. Mock
   mode accepts the simulator-shaped attestation token; a real Play Integrity
   token will NOT verify until step 6.
6. **Strict mode** (`ATTESTATION_MODE=strict`) additionally needs, per runbook
   §10: the Play Integrity decoder implemented in the broker, real
   `ANDROID_PACKAGE_NAME` / `ANDROID_CERT_SHA256_DIGESTS` / `IOS_APP_ID` from
   the published build, and `IOS_ATTESTATION_PRODUCTION=true`. `platform: 'sim'`
   is refused in strict mode by design.
7. **Only then** is the Phase 2 exit criterion testable: enrol a real phone
   against mock SDID and approve a CIBA login from `apps/test-rp` with a genuine
   hardware-backed signature (09 §2, §6).

---

## Security properties this package actually enforces (and tests)

- **Never signs a payload it did not reconstruct.** Every challenge is rebuilt
  with `buildChallengePayload(purpose, challengeId, nonce)` and compared for
  exact equality before the key is touched. A compromised or spoofed broker
  cannot steer the device into signing an arbitrary string, and specifically
  cannot swap in a `ciba-approve:<other authReqId>` payload behind a screen
  showing a different request (T4, T7). Tested.
- **Nonce-consuming calls are never retried.** The broker consumes challenges
  with GETDEL before verifying (T4), so a blind retry can only fail. Those calls
  surface `interrupted` — "start again" — instead. Tested.
- **A fresh attestation nonce, and a fresh key, per enrolment attempt.** The
  nonce is consumed before verification and not returned on failure; on Android
  the challenge is baked into the key at generation (runbook §10). Tested.
- **No raw server string ever reaches a citizen.** Broker `error_description`
  is discarded; only the machine `error` code is mapped to a localised message
  (03 §7). Unrecognised codes fail closed. Tested.
- **Nothing sensitive is persisted.** The stored binding carries no NID, no
  session token and no key. The session JWT is memory-only. Tested.
- **The biometric sample is disposed on every path**, including failure.
  Tested — with the honest caveat that the base64 copy is an immutable JS string
  that cannot be zeroed (CONTRACT.md §4 documents the fix, and flags it for the
  DPO).
- **Revocation is terminal.** A `binding_not_active` reply wipes local state and
  destroys the key; revoking this device does the same (06 §4, 03 §5). Tested.
- **Consent-fatigue defences.** Duplicate collapse never merges two different
  asks, and a burst of identical asks still requires one decision each (05 §9,
  T7). Tested.

## Known gaps

- No component tests for `src/ui` — the screens have never been rendered.
- No push; polling only.
- `SdidFaceCapture` has no PAD SDK chosen; the liveness score the client sends
  is whatever the native module reports, and nothing here validates it.
- The iOS App Attest key vs signing key relationship (CONTRACT.md §2.2) is
  **OPEN** and must be settled with `packages/attestation/src/app-attest.ts`
  before iOS work starts.
- Citizen-facing product name is still open decision #10; `common.appName` is a
  placeholder in all three locales.
- Offline authentication is out of scope for v1 (decision #7); every flow here
  requires the broker.
