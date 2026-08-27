import {
  AdapterBackedKeyCustody,
  createUnconfiguredCustody,
  type RemoteCustodyAdapter,
} from './adapter-custody.js';
import type { KeyCustody } from './key-custody.js';

/**
 * On-prem HSM signing-key custody over PKCS#11 (spec 06 §3, 07 §5, T13;
 * open decision #5).
 *
 * ============================ UNIMPLEMENTED =============================
 * No HSM exists to talk to, and decision #5 has not chosen between "GoR
 * KMS" and "on-prem HSM" (owner Pacifique, needed by Phase 1). Beyond that,
 * PKCS#11 is a **native C interface**: reaching it from Node needs an FFI
 * binding (`pkcs11js`, `graphene-pk11` or similar), which is a third-party
 * native dependency that has to clear the pre-production security assessment
 * (06 §8) and be chosen alongside the actual device. Guessing the vendor's
 * mechanism set, slot layout and login model now would be fiction.
 *
 * So `createHsmPkcs11Custody()` returns a custody boundary that throws
 * `KeyCustodyNotConfiguredError` from every operation until a deployment
 * registers an adapter — the declared-seam discipline of
 * `trust/play-integrity.decoder.ts`. `healthCheck()` alone reports rather than
 * throws, so `/readyz` can mark the replica not-ready with a reason.
 * ========================================================================
 *
 * ------------------------------------------------------------------------
 * WHAT A DEPLOYMENT MUST SUPPLY
 * ------------------------------------------------------------------------
 * 1. Configuration, from the environment (see `apps/broker/src/config.ts`):
 *      KEY_CUSTODY=hsm
 *      HSM_PKCS11_LIBRARY      absolute path to the vendor's PKCS#11 .so
 *      HSM_SLOT                slot id or token label to open a session on
 *      HSM_KEY_LABEL           label/CKA_ID prefix identifying the broker's
 *                              signing keys — a PREFIX, not one key, because
 *                              JWKS overlap needs the retired ones too
 *      HSM_PIN                 the token PIN / user password. Supply it from
 *                              the platform secret store, never a file in the
 *                              image: a PIN in the image is a key in the image
 *                              for every practical purpose.
 *
 * 2. One call to `registerHsmAdapterFactory()` during bootstrap, returning a
 *    `RemoteCustodyAdapter` (see `adapter-custody.ts`) backed by the FFI
 *    binding. Mapping notes that matter for PKCS#11 specifically:
 *
 *      listKeys()      → `C_FindObjects` over `CKO_PRIVATE_KEY` with the
 *                        configured label prefix. Return the ACTIVE and the
 *                        RETIRED keys; how a deployment marks which is which
 *                        (a label suffix, a CKA_ID convention, an attribute)
 *                        is its own choice — the adapter reports `status`.
 *      getPublicKey()  → the matching `CKO_PUBLIC_KEY`'s CKA_EC_POINT/SPKI.
 *                        Return SPKI DER and the engine converts it to a JWK.
 *      sign()          → `C_SignInit(CKM_ECDSA)` + `C_Sign`. Two traps:
 *                        (a) `CKM_ECDSA` signs a **pre-hashed** value, so the
 *                            adapter must SHA-256 the signing input itself
 *                            (or use `CKM_ECDSA_SHA256` where supported);
 *                        (b) PKCS#11 returns raw `r || s` for ECDSA, unlike
 *                            most KMS — the engine autodetects either form,
 *                            so return the bytes unmodified rather than
 *                            re-encoding them.
 *      rotate()        → USUALLY OMIT. On-prem HSM key creation is typically
 *                        a custodian ceremony under dual control, not
 *                        something a broker credential may do. Omitting it
 *                        makes `rotate()` throw
 *                        `KeyCustodyRotationUnsupportedError`, which is the
 *                        honest answer; the alternative — a rotation job that
 *                        reports success and rotated nothing — is the failure
 *                        mode this seam is written to prevent.
 *      health()        → session liveness. Sessions die (device reset, HA
 *                        failover, PIN lockout) and a dead session must fail
 *                        readiness, not the next citizen's login.
 *      close()         → `C_CloseSession` / `C_Finalize`.
 *
 * 3. Session handling inside the adapter. PKCS#11 sessions are stateful,
 *    not thread-safe in general, and the broker signs concurrently: pool them,
 *    re-login on `CKR_SESSION_HANDLE_INVALID`/`CKR_USER_NOT_LOGGED_IN`, and
 *    bound every call with a timeout so a wedged device fails the readiness
 *    probe instead of hanging the auth path.
 *
 * 4. The HSM's own audit log, reconciled against our `key.usage_summary` rows
 *    (07 §4). Ours records what the broker asked for; only the device's log
 *    can show a signature the broker never requested.
 */

export interface HsmPkcs11CustodyConfig {
  /** Absolute path to the vendor's PKCS#11 shared library. */
  libraryPath: string;
  /** Slot id or token label. */
  slot: string;
  /** Label / CKA_ID prefix identifying the broker's signing keys. */
  keyLabel: string;
  /** Token PIN. From the platform secret store; never logged, never echoed. */
  pin: string;
}

/** Supplied by the deployment; called lazily at `init()`. */
export type HsmAdapterFactory = (
  config: HsmPkcs11CustodyConfig,
) => RemoteCustodyAdapter | Promise<RemoteCustodyAdapter>;

let registeredFactory: HsmAdapterFactory | null = null;

/** Register the deployment's PKCS#11 adapter. Call before the broker boots. */
export function registerHsmAdapterFactory(factory: HsmAdapterFactory): void {
  registeredFactory = factory;
}

/** Test/bootstrap hook: forget the registered adapter. */
export function resetHsmAdapterFactory(): void {
  registeredFactory = null;
}

/** True when a deployment has registered an adapter. */
export function hasHsmAdapterFactory(): boolean {
  return registeredFactory !== null;
}

function unconfiguredReason(config: HsmPkcs11CustodyConfig): string | null {
  const missing: string[] = [];
  if (config.libraryPath.trim() === '') missing.push('HSM_PKCS11_LIBRARY');
  if (config.slot.trim() === '') missing.push('HSM_SLOT');
  if (config.keyLabel.trim() === '') missing.push('HSM_KEY_LABEL');
  // The PIN is checked for PRESENCE only, and never appears in any message.
  if (config.pin === '') missing.push('HSM_PIN');
  if (missing.length > 0) {
    return `HSM (PKCS#11) key custody is not configured: missing ${missing.join(', ')}.`;
  }
  if (registeredFactory === null) {
    return (
      'HSM key custody has configuration but no adapter: call registerHsmAdapterFactory() ' +
      'during bootstrap with a PKCS#11-backed client. None ships with the broker — PKCS#11 ' +
      'needs a native FFI binding chosen with the device and cleared by the pre-production ' +
      'security assessment (06 §8), and decision #5 has not chosen the device.'
    );
  }
  return null;
}

/** Build the HSM custody boundary, or the loudly-refusing stand-in for it. */
export function createHsmPkcs11Custody(config: HsmPkcs11CustodyConfig): KeyCustody {
  const reason = unconfiguredReason(config);
  if (reason !== null) {
    return createUnconfiguredCustody(
      'hsm',
      `${reason} The broker cannot mint tokens without a signing key (04 §4), so every ` +
        'signing operation fails and /readyz reports this replica not-ready. See the header of ' +
        'apps/broker/src/keys/hsm-pkcs11.custody.ts and docs/runbook.md §4 for what to supply.',
    );
  }
  const factory = registeredFactory as HsmAdapterFactory;
  return new AdapterBackedKeyCustody('hsm', () => factory(config));
}
