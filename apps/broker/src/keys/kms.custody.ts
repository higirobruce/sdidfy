import {
  AdapterBackedKeyCustody,
  createUnconfiguredCustody,
  type RemoteCustodyAdapter,
} from './adapter-custody.js';
import type { KeyCustody } from './key-custody.js';

/**
 * KMS signing-key custody (spec 06 §3, 07 §5, T13; open decision #5).
 *
 * ============================ UNIMPLEMENTED =============================
 * There is no KMS to talk to yet. Decision #5 is open — owner Pacifique,
 * needed by Phase 1 — and residency (Q17, 01 §3) has already narrowed it to a
 * **GoR-approved, in-country** KMS: no foreign cloud KMS is eligible, which
 * rules out simply writing an AWS/GCP/Azure client and calling it done. So
 * this file deliberately ships NO vendor SDK and NO vendor API shape. It would
 * be fiction, and the wrong fiction would be worse than none: it would make
 * the seam look closed.
 *
 * `createKmsCustody()` therefore returns a custody boundary that throws
 * `KeyCustodyNotConfiguredError` from every operation until a deployment
 * registers an adapter — the same declared-seam discipline as
 * `trust/play-integrity.decoder.ts` and the push transports. `healthCheck()`
 * is the single exception: it *reports* unhealthy so `/readyz` can take the
 * replica out of rotation with a reason rather than throwing on a probe.
 * Nothing here is ever reported as "there are no keys".
 * ========================================================================
 *
 * ------------------------------------------------------------------------
 * WHAT A DEPLOYMENT MUST SUPPLY
 * ------------------------------------------------------------------------
 * 1. Configuration, from the environment (see `apps/broker/src/config.ts`):
 *      KEY_CUSTODY=kms
 *      KMS_ENDPOINT            the in-country KMS API base URL
 *      KMS_KEY_GROUP           the logical group/ring/alias whose keys are the
 *                              broker's signing keys — NOT one key id, because
 *                              rotation with JWKS overlap needs the set
 *      KMS_CREDENTIALS         path to, or inline blob of, the client
 *                              credential (mTLS bundle, service account, token)
 *
 * 2. One call to `registerKmsAdapterFactory()` during bootstrap, returning an
 *    object implementing `RemoteCustodyAdapter` (see `adapter-custody.ts`):
 *
 *      listKeys()      → every ES256 signing key in the group, active AND
 *                        retired, each with a stable `kid` and the backend's
 *                        own `keyRef`. Retired keys MUST be included or JWKS
 *                        overlap breaks and tokens minted before the last
 *                        rotation stop verifying (06 §3).
 *      getPublicKey()  → the public key as a JWK or as SPKI DER. Most KMS
 *                        return SPKI DER; the engine converts it.
 *      sign()          → an ES256 signature over the SIGNING INPUT BYTES.
 *                        Two things routinely go wrong here:
 *                        (a) many KMS take a DIGEST, not the message — if so,
 *                            SHA-256 the bytes inside the adapter;
 *                        (b) most return DER-encoded ECDSA — the engine
 *                            normalises to the JWS r||s form, but only if you
 *                            return the bytes unmodified.
 *      rotate()        → OPTIONAL. Provide it only if the broker's own
 *                        credential is genuinely allowed to create and
 *                        promote a key. If rotation is an operator action,
 *                        omit it: `rotate()` then throws
 *                        `KeyCustodyRotationUnsupportedError` instead of
 *                        silently doing nothing.
 *      health()        → OPTIONAL cheap credential/reachability check.
 *
 * 3. Least privilege on that credential: `Sign`, `GetPublicKey`, `List` on the
 *    signing group and nothing else. The broker must NOT hold export/decrypt
 *    on these keys — the whole point of T13 is that a compromised broker
 *    cannot walk away with the key, only borrow the ability to sign, which
 *    revoking the credential ends.
 *
 * 4. KMS-side audit. Our `key.usage_summary` audit rows (07 §4) count what the
 *    broker ASKED for; they are not proof of what the KMS DID. Enable the
 *    backend's own signing audit log and reconcile the two — that pairing is
 *    what makes T13's "key-usage audit" control meaningful, because only the
 *    KMS log can reveal a signature the broker never requested.
 */

export interface KmsCustodyConfig {
  /** In-country KMS API base URL. Empty means the seam stays closed. */
  endpoint: string;
  /** Logical key group/ring/alias holding the broker's signing keys. */
  keyGroup: string;
  /** Client credential: filesystem path or inline blob. Never logged. */
  credentials: string;
}

/**
 * Supplied by the deployment during bootstrap. Called lazily at `init()` so a
 * KMS that is down at boot becomes a readiness failure on that replica rather
 * than a crash loop that takes the whole rollout with it.
 */
export type KmsAdapterFactory = (
  config: KmsCustodyConfig,
) => RemoteCustodyAdapter | Promise<RemoteCustodyAdapter>;

let registeredFactory: KmsAdapterFactory | null = null;

/**
 * Register the deployment's KMS adapter. Call before the broker boots.
 * Module-level (rather than a Nest provider) because it must be settable from
 * a bootstrap script or an integration test without rebuilding the DI graph —
 * the same reason `packages/sdid-adapter` takes its transport by injection.
 */
export function registerKmsAdapterFactory(factory: KmsAdapterFactory): void {
  registeredFactory = factory;
}

/** Test/bootstrap hook: forget the registered adapter. */
export function resetKmsAdapterFactory(): void {
  registeredFactory = null;
}

/** True when a deployment has registered an adapter. */
export function hasKmsAdapterFactory(): boolean {
  return registeredFactory !== null;
}

/**
 * Describes precisely what is missing, so an operator never has to open this
 * file to find out. Mirrors the FCM/APNs transport messages.
 */
function unconfiguredReason(config: KmsCustodyConfig): string | null {
  const missing: string[] = [];
  if (config.endpoint.trim() === '') missing.push('KMS_ENDPOINT');
  if (config.keyGroup.trim() === '') missing.push('KMS_KEY_GROUP');
  if (config.credentials.trim() === '') missing.push('KMS_CREDENTIALS');
  if (missing.length > 0) {
    return `KMS key custody is not configured: missing ${missing.join(', ')}.`;
  }
  if (registeredFactory === null) {
    return (
      'KMS key custody has configuration but no adapter: call registerKmsAdapterFactory() ' +
      'during bootstrap with a client for the GoR-approved in-country KMS. No adapter ships ' +
      'with the broker because decision #5 has not named a vendor (residency, Q17).'
    );
  }
  return null;
}

/**
 * Build the KMS custody boundary, or the loudly-refusing stand-in for it.
 */
export function createKmsCustody(config: KmsCustodyConfig): KeyCustody {
  const reason = unconfiguredReason(config);
  if (reason !== null) {
    return createUnconfiguredCustody(
      'kms',
      `${reason} The broker cannot mint tokens without a signing key (04 §4), so every ` +
        'signing operation fails and /readyz reports this replica not-ready. See the header of ' +
        'apps/broker/src/keys/kms.custody.ts and docs/runbook.md §4 for what to supply.',
    );
  }
  const factory = registeredFactory as KmsAdapterFactory;
  return new AdapterBackedKeyCustody('kms', () => factory(config));
}
