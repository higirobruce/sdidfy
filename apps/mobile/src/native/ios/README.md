# iOS — wiring `SdidKeyStore` into a real project

**Status: written, never compiled.** There is no `ios/` directory in this
repo — nobody has run `expo prebuild` (or `npx expo run:ios`) here, because
that needs a working Xcode + CocoaPods toolchain this environment doesn't
have and can't verify. The two files here (`SdidKeyStore.swift`,
`SdidKeyStore.m`) are real, complete Swift/Obj-C against
`SdidKeyStoreNativeModule` in `../contract.ts`, but nothing has compiled or
run them, and CONTRACT.md §1's own ground rule — every module must compile
for a real device and a simulator — is unmet until someone with a Mac and a
device does the following.

## 1. Generate the project

```bash
pnpm --filter @sdid/mobile exec expo prebuild --platform ios
```

This produces `apps/mobile/ios/`. Nothing below works before this step.

## 2. Add the files to the Xcode project

Drag both files into the generated `.xcodeproj` (or add them to
`ios/<AppName>/` and re-run `pod install` — either way they need to be a
member of the app target, not just present on disk). Since this is a mixed
Swift/Objective-C target, Xcode will prompt to create a bridging header the
first time a Swift file is added — accept that; `SdidKeyStore.m` needs
`#import <React/RCTBridgeModule.h>` to resolve, which comes from the Pods
already set up by `expo prebuild`, not from anything new.

## 3. What's still missing after that

- **`IOS_APP_ID`/team/bundle identifier** need real values before App Attest
  (a separate module, `SdidAttestation`) can work end-to-end, but
  `SdidKeyStore` on its own doesn't depend on them.
- **The `LAContext`/`kSecUseOperationPrompt` mechanism in `sign()` is flagged
  in the code as unverified.** CONTRACT.md §1.3 describes passing
  `localizedReason` via `kSecUseAuthenticationContext`; that property doesn't
  exist on `LAContext` the way the contract implies. What's implemented
  instead — binding `kSecUseAuthenticationContext` and
  `kSecUseOperationPrompt` to the `SecItemCopyMatching` query that fetches
  the key, so the returned `SecKey` carries that context into
  `SecKeyCreateSignature` — is the documented Apple pattern for prompting on
  a biometry-gated Keychain key, but it has never been exercised against
  Face ID or Touch ID on real hardware. **This is exactly the kind of
  byte-level trap `runbook.md` §10 warns about for the other two modules —
  test it first, before anything downstream of it.**
- **`mapSigningError`'s exact `LAError`/`OSStatus` code mapping is a
  best-effort guess**, not something observed from a real cancel/lockout/
  not-enrolled error on a device. Before trusting the citizen-facing error
  messages this maps to (via `NATIVE_ERROR_MAP` in `contract.ts`), deliberately
  trigger each case (cancel the prompt, lock out biometrics, remove all
  enrolled biometrics) and confirm the code that actually comes back matches.
- **No test has ever run against this file itself.** The DER→raw `r‖s`
  algorithm it implements (CONTRACT.md §7 item 1) has been verified — but as
  an independent TypeScript port, in `../der-signature.spec.ts`, against
  2000+ real P-256 ECDSA signatures including both the leading-zero-byte and
  short-coordinate traps. `derToRawRs` in this Swift file mirrors that logic
  exactly (and the Android Kotlin file mirrors it too — a bug found on one
  platform is worth checking for on the other); transcribe it faithfully, or
  port the same XCTest-able logic and cross-check against the same fixtures,
  before trusting it or attempting any of the on-device tests in §7 items 2–5.
