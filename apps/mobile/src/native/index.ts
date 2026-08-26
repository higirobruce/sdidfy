/**
 * Native surface. Only the pure-TypeScript contracts are exported here.
 *
 * The `*.rn.ts` adapters import `react-native` and are therefore excluded from
 * `tsconfig.json` (react-native is not installed in this monorepo). Import
 * them by path from UI code, which is likewise RN-only:
 *
 *   import { NativeKeyStore } from './native/keystore.rn.js';
 *
 * See ./CONTRACT.md for the Swift/Kotlin each module must implement. None of
 * it exists yet — that is stated there, loudly.
 */
export * from './contract.js';
