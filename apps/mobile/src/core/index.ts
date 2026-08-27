/**
 * Public surface of the authenticator's core (05). Everything here is plain
 * TypeScript with ZERO React Native imports — it runs, and is tested, under
 * the monorepo's vitest.
 *
 * `./testing/*` is deliberately NOT re-exported: those are dev/test doubles
 * and must not be reachable from a release bundle by an ordinary import.
 */
export * from './attestation.js';
export * from './biometrics.js';
export * from './client.js';
export * from './errors.js';
export * from './keystore.js';
export * from './pending.js';
export * from './transport.js';
export * from './types.js';
export * from './wire.js';
