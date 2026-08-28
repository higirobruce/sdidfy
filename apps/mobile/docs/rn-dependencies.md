# React Native dependency set — NOT installed

> None of the packages below are installed in this monorepo and none appear in
> `apps/mobile/package.json`. Adding them would break
> `pnpm --filter @sdid/mobile typecheck|test` for everyone until a full native
> toolchain (Xcode + Android SDK + CocoaPods) exists on the machine, and the
> environment this was built in has restricted network access, so nothing here
> has been resolved, installed, or version-verified.
>
> Treat every version as **a starting point to be checked against the current
> RN release train**, not as a lockfile.

## Why bare React Native, not managed Expo

Spec 05 §8 says it: Secure Enclave / StrongBox key generation, Play Integrity,
App Attest and certificate pinning all need native modules that managed Expo
does not expose. The options are Expo with a **dev client + config plugins**, or
bare RN. Either works; the four modules in `src/native/CONTRACT.md` have to be
written by hand regardless.

**Recommendation: Expo with a dev client**, because the team already uses Expo
(05 §8) and config plugins keep the `ios/`+`android/` directories generated
rather than hand-maintained — but with the four SDID modules as local native
modules in the repo, not as third-party packages.

## Runtime

| Package | Version (starting point) | Why |
|---------|--------------------------|-----|
| `react` | `19.x` | Peer of RN |
| `react-native` | `0.8x` | The framework |
| `expo` | `~5x` | Dev client + config plugins (if the Expo route is taken) |
| `expo-dev-client` | latest | Custom native code with the Expo workflow |
| `expo-localization` | latest | BCP-47 device locale → `resolveLocale()` |
| `react-native-safe-area-context` | latest | `SafeAreaProvider`/`SafeAreaView` in `App.tsx`. RN's own core `SafeAreaView` is iOS-only and unreliable even there — content spills into the status bar / notch on Android (and inconsistently on iOS) without this |
| `expo-font` + `@expo-google-fonts/plus-jakarta-sans` | latest | `theme.ts`'s `fonts.regular`/`semiBold`/`bold` — every text role in the app, not just titles. Loaded via `useFonts` at the app's entry point (not inside `App.tsx`/`theme.ts`, which stay agnostic about how a family name gets registered). Until something calls `useFonts` with all three weights, those family names silently fall back to the system font — nothing breaks, text just renders in the OS default until then |
| `react-native-mmkv` **or** `expo-secure-store` | latest | `BindingStore` implementation. Prefer `expo-secure-store` (Keychain / EncryptedSharedPreferences); it is identity-linked data (see below) |
| `@react-native-firebase/messaging` **or** `expo-notifications` | latest | FCM/APNs **wake-only** (05 §5, T6) |

Deliberately **absent** from this list:

- **No i18n library.** `src/i18n` is three string tables and one interpolator,
  ~60 lines. i18next is a dependency on the path to every security prompt for
  no gain (05 §8).
- **No HTTP client.** `fetch` plus `src/core/transport.ts`. Axios would not add
  pinning — that is native work (CONTRACT.md §5).
- **No crypto library.** Every signature happens in the secure element via
  `SdidKeyStore`. A JS crypto library on this path would be a way to
  accidentally hold a key in the JS heap.
- **No navigation library** initially — six screens, hand-switched in `App.tsx`.
  Add `@react-navigation/native` when the screen count justifies it, but keep
  the approval screen reachable without it.
- **No state library.** Component state plus one `ProtocolClient`. Redux
  devtools would expose pending requests and session tokens to anything
  attached to the debugger.

## Dev / build

| Package | Why |
|---------|-----|
| `@types/react` | Types for the UI |
| `typescript` | Already in the monorepo |
| `@react-native/babel-preset`, `@react-native/metro-config` | Bundler |
| `@testing-library/react-native`, `react-test-renderer` | Component tests for `src/ui` — **none exist yet**; `src/core` is tested, the screens are not |
| `detox` **or** `maestro` | On-device E2E for the enrolment and approval flows |

## Native (not npm packages — code to write)

The four modules in `src/native/CONTRACT.md`: `SdidKeyStore`,
`SdidAttestation`, `SdidBiometrics`, `SdidFaceCapture`, plus the pinning setup
in §5. Android needs the Play Integrity Play Services dependency; iOS needs
`DeviceCheck.framework`. **OPEN:** the PAD/liveness SDK for `SdidFaceCapture`
(ISO/IEC 30107 L2, spec 06 T8) — it sits on the security path, must be audited
(05 §8), and its PAD performance is a pre-prod gate (06 §8).

## Hermes and `Intl`

Dates in the activity and device screens use `toLocaleString()`. Hermes ships
without full ICU by default; enable the `intl` variant (or bundle
`@formatjs/intl-*` polyfills) or Kinyarwanda/French date formatting silently
degrades to a US-English-ish default — which would violate "full localisation,
not just labels" (05 §7).
