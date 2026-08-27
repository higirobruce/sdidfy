import { createPublicKey } from 'node:crypto';
import {
  KeyCustodyNotConfiguredError,
  KeyCustodyRotationUnsupportedError,
  KeyCustodySigningError,
  KeyCustodyUnavailableError,
  assertJwsSignatureShape,
  normalizeEcdsaSignature,
  type CustodyEvent,
  type CustodyEventListener,
  type CustodyHealth,
  type KeyCustody,
  type KeyCustodyCapabilities,
  type KeyCustodyProvider,
  type PublicJwk,
  type PublicJwks,
  type RotationResult,
  type SigningAlg,
  type SigningKeyDescriptor,
  type SigningKeyStatus,
} from './key-custody.js';

/**
 * The generic engine behind the two remote-custody seams (`kms.custody.ts`,
 * `hsm-pkcs11.custody.ts`) — decision #5, 06 §3, T13.
 *
 * WHY A GENERIC ENGINE AND NOT A VENDOR CLIENT. Residency (Q17) restricts us
 * to a GoR-approved in-country KMS or an on-prem HSM, and **nobody has chosen
 * which** (decision #5 is open, owner Pacifique, needed by Phase 1). Writing
 * against a specific cloud SDK today would be inventing an API we have no
 * reason to believe we will use, and would have to be deleted. So the backend
 * is expressed as four operations that every candidate supports —
 * `listKeys`, `getPublicKey`, `sign`, and optionally `rotate` — supplied by
 * the deployment as an adapter object, exactly as `packages/sdid-adapter`
 * handles the unresolved SDID interface (A1/A2) behind `SdidProvider`.
 *
 * The engine owns everything that is the same whoever wins: caching the key
 * set, publishing the JWKS with retired keys for overlap, converting whatever
 * public-key encoding the backend hands back into a JWK, normalising DER
 * signatures to the JWS `r || s` form, and refusing to pretend that an
 * unreachable backend is an empty one.
 */

/** One key as the backend knows it. No private material — there is no field for it. */
export interface RemoteKeyDescriptor {
  /**
   * The backend's own handle: a KMS key id/ARN/resource name, or a PKCS#11
   * object label or CKA_ID. Passed back to `sign`/`getPublicKey` verbatim.
   */
  keyRef: string;
  /**
   * The `kid` published in the JWKS and written into every token header.
   * Usually derived from `keyRef`, but kept separate on purpose: a KMS
   * resource name is an infrastructure identifier and may be rotated,
   * re-pathed or region-qualified, while a `kid` is a protocol identifier that
   * relying parties cache. They must be free to differ.
   */
  kid: string;
  alg: SigningAlg;
  /** `active` signs; `retired` stays in the JWKS for overlap (06 §3). */
  status: SigningKeyStatus;
  createdAt?: Date;
}

/**
 * What a deployment must implement. Every method may throw; the engine turns
 * throws into the custody error classes rather than into "no key".
 */
export interface RemoteCustodyAdapter {
  /** Human-readable backend name for health details and logs. Never a secret. */
  readonly name: string;

  /**
   * Every key the broker may use, active and retired. The engine will not
   * invent keys, so a backend that hides retired keys breaks JWKS overlap.
   */
  listKeys(): Promise<RemoteKeyDescriptor[]>;

  /**
   * The PUBLIC key, either as a JWK or as SPKI DER (what most KMS
   * `GetPublicKey` calls return). The engine converts DER for you.
   */
  getPublicKey(key: RemoteKeyDescriptor): Promise<PublicJwk | Uint8Array>;

  /**
   * Sign the signing-input BYTES (not a digest — the backend applies the
   * algorithm's hash). Return raw `r || s` or DER; the engine normalises.
   */
  sign(input: { key: RemoteKeyDescriptor; data: Uint8Array }): Promise<Uint8Array>;

  /**
   * Promote a new key and retire the current one. OPTIONAL, and its absence is
   * meaningful: many HSM deployments rotate through a custodian ceremony, not
   * an API call. Leave it undefined and `rotate()` throws loudly instead of
   * reporting a rotation that never happened.
   */
  rotate?(): Promise<{ promotedKid: string; retiredKids: string[] }>;

  /** Cheap backend liveness/credential check. Defaults to a `listKeys` probe. */
  health?(): Promise<{ healthy: boolean; detail?: string }>;

  /** Release sessions/handles (PKCS#11 sessions, HTTP agents). */
  close?(): Promise<void>;
}

/** Built lazily at `init()` so a boot-time backend outage is a readiness failure. */
export type RemoteCustodyAdapterFactory = () =>
  | RemoteCustodyAdapter
  | Promise<RemoteCustodyAdapter>;

interface CachedKey {
  remote: RemoteKeyDescriptor;
  descriptor: SigningKeyDescriptor;
  publicJwk: PublicJwk;
}

export class AdapterBackedKeyCustody implements KeyCustody {
  private readonly listeners: CustodyEventListener[] = [];
  private adapter: RemoteCustodyAdapter | null = null;
  private keys = new Map<string, CachedKey>();
  private active: string | null = null;

  constructor(
    readonly provider: KeyCustodyProvider,
    private readonly factory: RemoteCustodyAdapterFactory,
  ) {}

  /**
   * Only meaningful after `init()`: whether the deployment's adapter can
   * rotate is a property of the adapter, and the adapter is not built until
   * the backend is reachable. Before init this reads `false`, which is the
   * safe direction — it never claims a capability it has not seen.
   */
  get capabilities(): KeyCustodyCapabilities {
    return {
      rotate: typeof this.adapter?.rotate === 'function',
      // A remote custody boundary never creates keys behind the operator's
      // back: key creation in a KMS/HSM is a provisioned, audited, often
      // ceremony-gated act (06 §3), not something a booting pod does.
      generateOnDemand: false,
    };
  }

  onEvent(listener: CustodyEventListener): void {
    this.listeners.push(listener);
  }

  async init(): Promise<void> {
    this.adapter = await this.factory();
    await this.reload();
    if (this.active === null) {
      throw new KeyCustodyUnavailableError(
        this.provider,
        `${this.adapter.name} exposes ${this.keys.size} key(s) but none is active — the broker ` +
          'cannot mint tokens. Provision and activate an ES256 signing key in the custody ' +
          'backend; the broker will not create one for you (06 §3).',
      );
    }
  }

  async activeKid(): Promise<string> {
    if (this.active === null) {
      throw new KeyCustodyUnavailableError(this.provider, 'no active signing key in custody');
    }
    return this.active;
  }

  async listPublicJwks(): Promise<PublicJwks> {
    return { keys: [...this.keys.values()].map((k) => k.publicJwk) };
  }

  async listKeys(): Promise<SigningKeyDescriptor[]> {
    return [...this.keys.values()].map((k) => k.descriptor);
  }

  async sign(kid: string, data: Uint8Array): Promise<Uint8Array> {
    const adapter = this.requireAdapter();
    let cached = this.keys.get(kid);
    if (!cached) {
      // The key set may have changed under us (a rotation elsewhere). One
      // refresh, then fail — the signing path must not become a retry loop.
      await this.reload();
      cached = this.keys.get(kid);
    }
    if (!cached) {
      throw new KeyCustodySigningError(this.provider, kid, `no key with kid=${kid} in custody`);
    }
    let raw: Uint8Array;
    try {
      raw = await adapter.sign({ key: cached.remote, data });
    } catch (err) {
      // Never echo the backend's error verbatim into a token-path exception
      // beyond its message: it can quote request bodies. It is the operator's
      // log that needs the detail, and the message carries it.
      throw new KeyCustodySigningError(
        this.provider,
        kid,
        `${adapter.name} refused the signature: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
    // DER→r||s here rather than in every adapter: see key-custody.ts.
    const signature = normalizeEcdsaSignature(raw, cached.descriptor.alg);
    assertJwsSignatureShape(signature, cached.descriptor.alg);
    return signature;
  }

  async healthCheck(): Promise<CustodyHealth> {
    if (this.adapter === null) {
      return {
        healthy: false,
        provider: this.provider,
        activeKid: null,
        detail: 'custody adapter has not been initialised',
      };
    }
    try {
      if (this.adapter.health) {
        const result = await this.adapter.health();
        if (!result.healthy) {
          return {
            healthy: false,
            provider: this.provider,
            activeKid: this.active,
            detail: result.detail ?? `${this.adapter.name} reported unhealthy`,
          };
        }
      }
      // Refresh regardless: a credential can be valid while the key set has
      // moved on, and a rotation performed out-of-band must land without a
      // redeploy.
      await this.reload();
    } catch (err) {
      return {
        healthy: false,
        provider: this.provider,
        activeKid: this.active,
        detail: `${this.adapter.name}: ${err instanceof Error ? err.message : 'unknown'}`,
      };
    }
    if (this.active === null) {
      return {
        healthy: false,
        provider: this.provider,
        activeKid: null,
        detail: `${this.adapter.name} has no active key`,
      };
    }
    return {
      healthy: true,
      provider: this.provider,
      activeKid: this.active,
      detail: `${this.adapter.name}: ${this.keys.size} key(s)`,
    };
  }

  async rotate(): Promise<RotationResult> {
    const adapter = this.requireAdapter();
    if (typeof adapter.rotate !== 'function') {
      // Loud, not a no-op (contract point 7). A scheduled rotation job that
      // "succeeds" without rotating is worse than one that pages someone.
      throw new KeyCustodyRotationUnsupportedError(
        this.provider,
        `${adapter.name} does not support programmatic rotation. This is normal for an HSM ` +
          'whose keys are created in a custodian ceremony: rotate out-of-band, then the ' +
          'broker picks the new active key up on its next health check. Supply a rotate() on ' +
          'the adapter if the backend can do it under our own credential.',
      );
    }
    const before = this.active;
    const result = await adapter.rotate();
    await this.reload();
    for (const kid of result.retiredKids) {
      this.emit({ type: 'key_retired', kid, alg: 'ES256', provider: this.provider });
    }
    this.emit({
      type: 'key_promoted',
      kid: result.promotedKid,
      alg: 'ES256',
      provider: this.provider,
      detail: { previousActiveKid: before },
    });
    return {
      promotedKid: result.promotedKid,
      retiredKids: result.retiredKids,
      alg: this.keys.get(result.promotedKid)?.descriptor.alg ?? 'ES256',
    };
  }

  async close(): Promise<void> {
    const adapter = this.adapter;
    this.adapter = null;
    this.keys = new Map();
    this.active = null;
    if (adapter?.close) await adapter.close();
  }

  // --- internals ---------------------------------------------------------

  private requireAdapter(): RemoteCustodyAdapter {
    if (this.adapter === null) {
      throw new KeyCustodyUnavailableError(
        this.provider,
        'custody adapter has not been initialised — init() must run before any signing',
      );
    }
    return this.adapter;
  }

  private emit(event: CustodyEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  private async reload(): Promise<void> {
    const adapter = this.requireAdapter();
    const remotes = await adapter.listKeys();
    const next = new Map<string, CachedKey>();
    let active: string | null = null;
    for (const remote of remotes) {
      const material = await adapter.getPublicKey(remote);
      const publicJwk = toPublicJwk(material, remote);
      next.set(remote.kid, {
        remote,
        descriptor: {
          kid: remote.kid,
          alg: remote.alg,
          status: remote.status,
          createdAt: remote.createdAt ?? new Date(0),
        },
        publicJwk,
      });
      if (remote.status === 'active' && active === null) active = remote.kid;
    }
    this.keys = next;
    this.active = active;
  }
}

/**
 * Normalise whatever the backend returned into a JWKS entry, and stamp
 * `kid`/`alg`/`use` from OUR descriptor rather than trusting the backend's:
 * the `kid` in the JWKS must match the `kid` we put in token headers, or every
 * relying party looks up a key that is not there.
 */
function toPublicJwk(material: PublicJwk | Uint8Array, remote: RemoteKeyDescriptor): PublicJwk {
  let jwk: PublicJwk;
  if (material instanceof Uint8Array) {
    // SPKI DER — the shape AWS/GCP/Azure KMS `GetPublicKey` and PKCS#11
    // CKA_VALUE exports come back in.
    const exported = createPublicKey({
      key: Buffer.from(material),
      format: 'der',
      type: 'spki',
    }).export({ format: 'jwk' });
    jwk = exported as unknown as PublicJwk;
  } else {
    jwk = { ...material };
  }
  jwk.kid = remote.kid;
  jwk.alg = remote.alg;
  jwk.use = 'sig';
  // Defence in depth: a backend that mistakenly hands back a PRIVATE JWK must
  // not have `d` published to the world through /oidc/jwks (T13, 07 §5).
  delete (jwk as Record<string, unknown>).d;
  return jwk;
}

/**
 * A custody boundary that exists, refuses everything, and says exactly why.
 *
 * The same discipline as `trust/play-integrity.decoder.ts` and the push
 * transports: when the deployment has not supplied what a seam needs, refuse
 * loudly rather than pretend. Critically, every refusal is a
 * `KeyCustodyNotConfiguredError` — never an empty key list, never a null
 * active kid — because "we are not configured" and "there are no keys" lead an
 * operator to opposite actions, and only the first is true here.
 */
export function createUnconfiguredCustody(
  provider: KeyCustodyProvider,
  message: string,
): KeyCustody {
  const fail = (): never => {
    throw new KeyCustodyNotConfiguredError(provider, message);
  };
  return {
    provider,
    capabilities: { rotate: false, generateOnDemand: false },
    onEvent(): void {
      /* nothing will ever be emitted */
    },
    async init(): Promise<void> {
      fail();
    },
    async activeKid(): Promise<string> {
      return fail();
    },
    async listPublicJwks(): Promise<PublicJwks> {
      return fail();
    },
    async listKeys(): Promise<SigningKeyDescriptor[]> {
      return fail();
    },
    async sign(): Promise<Uint8Array> {
      return fail();
    },
    async healthCheck(): Promise<CustodyHealth> {
      // The ONE method that reports rather than throws, so /readyz can mark
      // the replica not-ready with a reason instead of exploding on a probe.
      return { healthy: false, provider, activeKid: null, detail: message };
    },
    async rotate(): Promise<RotationResult> {
      return fail();
    },
    async close(): Promise<void> {
      /* nothing to release */
    },
  };
}
