# Native module contract — what a mobile engineer must implement

> **Status: SPECIFICATION ONLY. No Swift or Kotlin exists in this repository.**
>
> Everything below describes native code that must be written, compiled and
> tested on real hardware. It has never been built or run. It is written as a
> contract precisely so that the TypeScript above it (`src/core`, which *is*
> tested) can be reviewed and trusted independently of the native work.
>
> Where a decision is genuinely open, it is marked **OPEN** rather than guessed.

TypeScript declarations for these modules: [`contract.ts`](./contract.ts).
Spec references: `docs/SPEC.md` 05 §3–§5, 06 T1/T2/T3/T5, `docs/runbook.md` §10.

---

## 0. Ground rules for all four modules

| Rule | Why |
|------|-----|
| Arguments and results are JSON-safe primitives; binary crosses as base64 / base64url **strings**, with the encoding named per field | The RN bridge has no binary type; `number[]` is both slow and easy to leak into a log |
| Reject with a stable `code` from `NativeErrorCode`; free text is developer-only | A precise citizen-facing reason tells an attacker which control to defeat (03 §7) |
| Never log arguments or results — not in `NSLog`, `Log.d`, Crashlytics, or a debug build | Nonces, signatures, public keys and samples are all sensitive or fingerprintable (07 §1) |
| No key material, no biometric bytes, and no session token ever enters the JS heap | Anything in the JS heap is in the crash dump, the debugger, and any RN devtools attached |
| Every module compiles for both a real device and a simulator, but **must refuse to produce trust-bearing output on a simulator** | T3: a simulator has no secure element; a module that silently degrades hides that |

---

## 1. `SdidKeyStore` — the device key (05 §3, T1/T2/T3)

The trust chain reduces to this module. If it is wrong, nothing above it can
compensate.

### 1.1 Android (Kotlin) — generation

`KeyPairGenerator.getInstance("EC", "AndroidKeyStore")` with a
`KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)` carrying, all of them
required:

```
.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
.setDigests(KeyProperties.DIGEST_SHA256)
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)   // API 30+
.setInvalidatedByBiometricEnrollment(true)
.setAttestationChallenge(nonce.toByteArray(Charsets.UTF_8))
.setIsStrongBoxBacked(true)          // retry without it on StrongBoxUnavailableException
```

- **`setUserAuthenticationParameters(0, …)`** — a validity duration of `0`
  means one authentication authorises exactly one crypto operation. A non-zero
  duration would let one unlock cover a window of signatures; that is the
  property T1 forbids.
- **`AUTH_BIOMETRIC_STRONG`, not `AUTH_DEVICE_CREDENTIAL`** — a PIN or pattern
  must not substitute for the biometric on this key.
- **`setInvalidatedByBiometricEnrollment(true)`** — adding a fingerprint must
  destroy the key. Without it, someone who coerces the citizen into enrolling
  their own finger inherits the binding.
- **`setAttestationChallenge(utf8(nonce))`** — the UTF-8 bytes of the nonce
  *string* as received, **not** the base64url-decoded 32 bytes. This is the
  exact byte-level contract in `docs/runbook.md` §10; getting it wrong makes
  every enrolment fail with a uniform `attestation_rejected` whose audit row
  says `nonce_mismatch` and nothing more.
- **Below API 30**: `setUserAuthenticationValidityDurationSeconds(-1)` is the
  older spelling of "per-operation auth". **OPEN:** minimum supported API level
  (proposal: 30, which also gives StrongBox on most Rwanda-market devices).

Report `securityLevel` from `KeyInfo.getSecurityLevel()`
(`SECURITY_LEVEL_STRONGBOX` → `strongbox`, `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`
→ `tee`, anything else → `software`). Report honestly: the TS layer refuses to
enrol a `software` key by default, and that refusal is the control.

Return the attestation chain as a JSON array of base64 DER certificates,
**leaf first** (runbook §10 — the broker also accepts a PEM bundle or a
comma/whitespace-separated list, but pick one and stay with it).

### 1.2 iOS (Swift) — generation

`SecKeyCreateRandomKey` with:

```
kSecAttrKeyType            = kSecAttrKeyTypeECSECPrimeRandom
kSecAttrKeySizeInBits       = 256
kSecAttrTokenID             = kSecAttrTokenIDSecureEnclave
kSecPrivateKeyAttrs:
  kSecAttrIsPermanent       = true
  kSecAttrApplicationTag    = <alias>
  kSecAttrAccessControl     = SecAccessControlCreateWithFlags(
                                nil,
                                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                [.privateKeyUsage, .biometryCurrentSet],
                                &error)
```

- **`.biometryCurrentSet`** (not `.biometryAny`) — the key is invalidated when
  the enrolled biometric set changes: the iOS analogue of
  `setInvalidatedByBiometricEnrollment`.
- **`…ThisDeviceOnly`** — never syncs to iCloud Keychain, never restores onto
  another device.
- Secure Enclave keys are non-exportable by construction; there is no
  `SecKeyCopyExternalRepresentation` path for the private half.
- The attestation challenge is **not** used here — iOS binds it at App Attest
  time instead (§2.2).

### 1.3 The biometric prompt lives INSIDE `sign`

Both platforms must raise the prompt as part of the key operation:

- **Android**: `BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))`
  where `signature` is a `Signature.getInstance("SHA256withECDSA")` already
  `initSign(privateKey)`-ed. The signature object handed back in
  `onAuthenticationSucceeded` is the *only* one authorised — sign with that
  instance, never re-init afterwards.
- **iOS**: pass an `LAContext` with `localizedReason` via
  `kSecUseAuthenticationContext`, and let `SecKeyCreateSignature` trigger the
  evaluation. Do **not** call `LAContext.evaluatePolicy` separately and then
  sign; and never set `touchIDAuthenticationAllowableReuseDuration`.

There is deliberately **no `unlock()` method** on the interface. A separate
"authenticate, then sign" API is a time-of-check/time-of-use hole: malware that
wins the race between the two signs a payload the citizen never saw (T1, T7).
One prompt, one signature, one payload.

The prompt strings (`promptTitle`, `promptSubtitle`) arrive already localised;
the native side must render them verbatim and never substitute an English
default (05 §7). For a CIBA approval the subtitle carries the RP name and the
binding-message code, so the platform sheet is not a context-free "Confirm"
(T7).

### 1.4 Signature encoding — the classic trap

The broker verifies **raw `r||s`, 64 bytes, base64url** (`protocol.ts`, and
`SignatureService` on the broker side, which is WebCrypto-shaped).

Both platforms produce **ASN.1 DER** ECDSA signatures. The native module MUST
convert DER → raw `r||s`, left-padding each of `r` and `s` to exactly 32 bytes
and stripping DER's leading sign byte. A DER signature forwarded as-is fails
verification 100% of the time and looks exactly like a wrong key.

### 1.5 Deletion

Android: `KeyStore.deleteEntry(alias)`. iOS: `SecItemDelete` on the tag.
Must be irreversible and must succeed even when the key was already
invalidated by a biometric re-enrolment.

---

## 2. `SdidAttestation` — genuine app, sound device (05 §4, T2/T3/T4)

### 2.1 Android — Play Integrity

`IntegrityManagerFactory.createStandard(...)` →
`StandardIntegrityTokenProvider.request(StandardIntegrityTokenRequest.builder()
.setRequestHash(nonce).build())`.

- `requestHash` is the broker's nonce **string**, unmodified.
- The returned token is opaque and must be forwarded verbatim; the broker
  decodes it server-side.
- Alongside it, forward the key-attestation chain from §1.1 — the broker checks
  **both**, and specifically checks that the attested key is the same key whose
  public JWK is being enrolled. Attesting a separately generated key fails
  `key_mismatch` (runbook §10).
- ⚠ The broker cannot verify these tokens yet:
  `apps/broker/src/trust/play-integrity.decoder.ts` is a declared, throwing
  seam pending a GoR Play Console service account (runbook §10). Android strict
  mode fails closed with 503 until that lands.

### 2.2 iOS — App Attest

`DCAppAttestService.shared`:

1. `generateKey()` → `keyId`. **OPEN:** whether the App Attest key and the
   signing key of §1.2 are the same key. They cannot be — App Attest keys are
   its own — so the broker's "attested key == enrolled key" check must be
   satisfied by including the enrolled public key in the attested client data.
   Proposal: `clientDataHash = SHA256(utf8(nonce))` per runbook §10, and the
   enrolled public JWK carried in the assertion of the *first* subsequent
   `generateAssertion` call. **This needs to be settled with whoever implements
   `packages/attestation/src/app-attest.ts`'s verifier before any iOS work
   starts** — today the runbook states only the `clientDataHash` rule.
2. `attestKey(keyId, clientDataHash: SHA256(utf8(nonce)))` → CBOR object.
3. Forward it base64-encoded as `token`; no `keyAttestation` field.

Apple binds `SHA256(authData ‖ clientDataHash)` into the credCert extension
`1.2.840.113635.100.8.2`; the verifier recomputes both, so any deviation in the
hash input fails.

`IOS_ATTESTATION_PRODUCTION=true` on the broker means a development-provisioned
build will be rejected — expected, and the reason a dev build cannot be used to
smoke-test strict mode.

### 2.3 Fresh nonce, fresh key, every attempt

The broker consumes the nonce with GETDEL **before** verification and does not
return it on failure. So every enrolment attempt — including a retry after a
failure — needs a new nonce, and on Android a new key (the challenge is baked
in at generation). `ProtocolClient.enrol` already does this; the native side
must not cache either.

---

## 3. `SdidBiometrics` — capability checks and screen hygiene

- **Android**: `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)`.
  `BIOMETRIC_SUCCESS` → available+enrolled+strong;
  `BIOMETRIC_ERROR_NONE_ENROLLED` → available, not enrolled;
  `BIOMETRIC_ERROR_NO_HARDWARE` / `HW_UNAVAILABLE` → not available.
  Report `strong: false` when only `BIOMETRIC_WEAK` succeeds — the TS layer
  refuses enrolment in that case (05 §3).
- **iOS**: `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
  plus `biometryType`. `LAError.biometryNotEnrolled` distinguishes
  "no biometric set up" from "no hardware".
- **`isScreenCompromised`** (05 §9): iOS `UIScreen.main.isCaptured` plus the
  `capturedDidChangeNotification`; Android `FLAG_WINDOW_IS_OBSCURED` /
  `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` on touch events into the approval screen,
  and `WindowManager` overlay detection where available. Where the platform
  cannot tell, return `false` and document it — a fabricated `true` trains
  citizens to ignore the warning.
- The approval screen must also set `FLAG_SECURE` (Android) and blur the
  snapshot on `applicationWillResignActive` (iOS) so the request does not sit
  in the app switcher.

---

## 4. `SdidFaceCapture` — the only place biometric bytes exist (03 §2, 07 §1, T8)

**This module is the entire data-protection surface of the app.** Every DPIA
claim in `docs/SPEC.md` 08 §3 about in-memory-only handling has to be true here
or it is not true at all.

Requirements:

- Capture with **active liveness / PAD to ISO/IEC 30107 Level 2** (blink,
  head-turn, or an equivalent challenge–response). **OPEN:** which SDK. Whatever
  is chosen is on the security path and must be audited (05 §8), and its PAD
  performance is a pre-prod gate (06 §8, 09 §3).
- The image bytes exist in **one buffer**, in memory. Never a file, never the
  photo library, never a `NSTemporaryDirectory`/`cacheDir` scratch path, never
  a `UIImage` handed to a library that might cache it.
- `release()` **zeroes** the buffer (`memset_s` on iOS — not plain `memset`,
  which the optimiser may elide; `java.util.Arrays.fill` on a `ByteArray`, not
  a `String`) and frees the camera session. The TS layer calls it in a
  `finally`, on every path including failure.
- No frame is retained after the session ends: no preview snapshot, no debug
  overlay, no analytics thumbnail.
- Camera permission prompt text must be localised (05 §7).

**Known limitation, stated plainly:** once the sample crosses the bridge as
base64 it is a JS string, and JS strings are immutable — they cannot be zeroed
and are collected whenever the GC decides. The controls that remain are that
the string is short-lived, is never persisted, and is never logged; the
long-lived native buffer *is* zeroed. If that residual is unacceptable to the
DPIA, the fix is to move the enrolment POST into the native module so the bytes
never enter the JS heap. **OPEN — worth raising with the DPO.**

---

## 5. Certificate pinning (T5) — not a module, but native work

TLS pinning cannot be done from JS `fetch`. It must be installed in the
platform HTTP stack:

- **Android**: an OkHttp `CertificatePinner` on the RN networking client
  (`OkHttpClientProvider.setOkHttpClientFactory`), pinning the **SPKI SHA-256**
  of the broker's leaf *and* a backup key.
- **iOS**: an `URLSessionDelegate` doing `SecTrustEvaluateWithError` followed by
  an SPKI comparison, wired into RN's networking module.
- Pin the **public key (SPKI)**, never the certificate — certificate pinning
  breaks on every renewal.
- Ship **at least two pins** (current + next) and a documented rotation
  procedure, or a certificate renewal bricks every installed app.
- **OPEN:** pin rotation policy and who owns the broker's TLS material
  (relates to decision #5, key custody).

`assertPinnedTransport()` in `src/core/transport.ts` exists so a release build
fails closed if it is wired to the unpinned `FetchTransport`.

---

## 6. Push (05 §5, T6) — wake-only

FCM (Android) / APNs (iOS). The payload is **never trusted and never
displayed**: on receipt the app calls `ProtocolClient.pullPending()` and renders
only what came back over the authenticated backchannel. A notification may say
"you have a request waiting" and nothing more — no RP name, no scope, no code
from the push payload, because none of it is authenticated.

Registration token handling is **OPEN**: at the time of writing `PushService.wake`
only logs and there is no device-token registration endpoint (runbook §1), so the
app discovers pending requests by polling `GET /v1/device/ciba/pending`. Check
the broker before implementing — if a registration endpoint has since landed,
add the call to `ProtocolClient` and keep the pull; the payload remains
untrusted either way (T6).

---

## 7. Test plan for the native side (none of it done)

1. Unit: DER → raw `r||s` conversion against known vectors, including
   signatures where `r` or `s` has a leading zero byte (the case that breaks
   naive implementations).
2. On-device: generate → export JWK → sign → verify with the broker's
   `SignatureService`. This is the "ghost login" exit criterion for Phase 2
   (09 §2) and cannot be simulated.
3. On-device: StrongBox present vs TEE-only vs software fallback; assert the
   reported `securityLevel` matches reality on each.
4. On-device: adding a fingerprint invalidates the key (Android) / changing the
   biometric set invalidates it (iOS) — the anti-coercion property of §1.
5. On-device: a rooted / jailbroken / emulated device is refused (T2/T3).
6. Attestation round-trip against a broker in `ATTESTATION_MODE=strict` — blocked
   on the Play Integrity decoder seam and real app identifiers (runbook §10).
7. Pinning: connection fails against a MITM proxy with a trusted-store CA (T5).
