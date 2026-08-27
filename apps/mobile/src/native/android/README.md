# Android — wiring `SdidKeyStore` into a real project

**Status: written, never compiled.** There is no `android/` directory in
this repo — nobody has run `expo prebuild` (or `npx expo run:android`) here,
because that needs a working Android SDK/Gradle toolchain this environment
doesn't have and can't verify. The two files in this directory are real,
complete Kotlin against `SdidKeyStoreNativeModule` in `../contract.ts`, but
they have never been built, and CONTRACT.md §1's own ground rule — every
module must compile for a real device and a simulator — is unmet until
someone with a device does the following.

## 1. Generate the project

```bash
pnpm --filter @sdid/mobile exec expo prebuild --platform android
```

This produces `apps/mobile/android/`. Nothing below works before this step.

## 2. Place the module

Copy (or symlink) both files into the generated tree, e.g.:

```
android/app/src/main/java/com/sdid/authenticator/keystore/SdidKeyStoreModule.kt
android/app/src/main/java/com/sdid/authenticator/keystore/SdidKeyStorePackage.kt
```

The package name `com.sdid.authenticator.keystore` is a placeholder — rename
both the `package` declaration and the directory to match whatever
`android.package` ends up in `app.json` once that's decided, **and** keep it
identical to `ANDROID_PACKAGE_NAME` on the broker (`runbook.md` §10) — a
mismatch there fails every strict-mode attestation with a uniform rejection
and no other clue.

## 3. Register the package

In the generated `MainApplication.kt`, add `SdidKeyStorePackage()` to the
list returned by `getPackages()`:

```kotlin
override fun getPackages(): List<ReactPackage> =
    PackageList(this).packages.apply {
        add(SdidKeyStorePackage())
    }
```

## 4. Add the Gradle dependency

`SdidKeyStoreModule` uses `androidx.biometric.BiometricPrompt`, which is not
part of the React Native template. Add to `android/app/build.gradle`:

```gradle
dependencies {
    implementation "androidx.biometric:biometric:1.1.0"
}
```

Check that version against whatever's current when this actually gets built
— it's a starting point, not a pin (same caveat `../../docs/rn-dependencies.md`
gives every other package in this repo).

## 5. What's still missing after that

- **`minSdkVersion` must be raised to 30** in `android/build.gradle` — the
  floor CONTRACT.md §1.1 settles on. The Expo template usually defaults lower.
- **The calling `Activity` must be a `FragmentActivity`** — `sign()` casts
  `reactContext.currentActivity`, and rejects with `E_KEYSTORE` if that cast
  fails. React Native's default `MainActivity` already extends
  `ReactActivity`, which extends `AppCompatActivity`, which extends
  `FragmentActivity` — so this should hold without changes, but it's worth
  confirming against whatever Activity class ends up in the generated project.
- **No test has ever run against this file itself.** The DER→raw `r‖s`
  algorithm it implements (CONTRACT.md §7 item 1) has been verified — but as
  an independent TypeScript port, in `../der-signature.spec.ts`, against
  2000+ real P-256 ECDSA signatures including both the leading-zero-byte and
  short-coordinate traps. `derToRawRs` in this Kotlin file mirrors that logic
  exactly; transcribe it faithfully (or better, port the same JUnit-able
  logic and cross-check against the same fixtures) before trusting it, and
  before attempting any of the on-device tests in §7 items 2–5.
