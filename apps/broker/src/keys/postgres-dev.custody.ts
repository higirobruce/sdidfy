import {
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';
import type { Pool } from 'pg';
import {
  KeyCustodySigningError,
  KeyCustodyUnavailableError,
  assertJwsSignatureShape,
  type CustodyEvent,
  type CustodyEventListener,
  type CustodyHealth,
  type KeyCustody,
  type KeyCustodyCapabilities,
  type PublicJwk,
  type PublicJwks,
  type RotationResult,
  type SigningAlg,
  type SigningKeyDescriptor,
} from './key-custody.js';

/**
 * DEVELOPMENT-ONLY custody: ES256 keys in the `signing_keys` Postgres table,
 * imported into this process and signed locally (decision #5, DECISIONS.md f).
 *
 * ===========================================================================
 * THIS IS THE ONE PROVIDER THAT VIOLATES THE CONTROL IT IMPLEMENTS.
 * ===========================================================================
 * T13 and 06 §3 require that signing keys never sit in app memory as plaintext
 * and never leave the custody boundary. Here the "boundary" is a Postgres row
 * and a `KeyObject` in this process — both plaintext, both readable by anyone
 * with a DB dump or a heap dump. 07 §5 is explicit that secrets do not belong
 * in the database. It exists because development, the test suite and the
 * ghost-login demo need to sign today, and because keeping dev keys in
 * Postgres (rather than per-process memory) is what makes multiple broker
 * processes agree on a kid.
 *
 * So the constructor REFUSES to build under `NODE_ENV=production`. That is not
 * belt-and-braces around the config guard rail in `config.ts` — it is the
 * backstop for every path that does not go through `loadConfig()`'s production
 * branch: a test harness, a script, a future embedding of the broker as a
 * library. A dev key that survives into an environment with real citizens is a
 * token-forgery key for the national identity service.
 *
 * Everything else about it is deliberately IDENTICAL to the behaviour it
 * replaced, so dev, tests and the demo see no change: first boot generates one
 * ES256 key, the active key signs, every row (active and retired) is published
 * in the JWKS.
 *
 * One behaviour is new and is an improvement rather than a divergence:
 * `healthCheck()` re-reads the table, so a key rotated by another replica or
 * by SQL is picked up without a restart (see runbook §4).
 */

/** Concatenated `r || s` comes straight out of node:crypto with this setting. */
const IEEE_P1363 = 'ieee-p1363' as const;

/** Advisory lock guarding rotation, so two replicas cannot both promote. */
const ROTATION_LOCK_KEY = 429_002;

const ALG: SigningAlg = 'ES256';

interface KeyRow {
  kid: string;
  alg: string;
  public_jwk: PublicJwk;
  private_jwk: JsonWebKey;
  status: string;
  created_at: Date;
}

/** A loaded key. The private half is a KeyObject, never re-serialised. */
interface LoadedKey {
  descriptor: SigningKeyDescriptor;
  publicJwk: PublicJwk;
  privateKey: KeyObject;
}

export class PostgresDevKeyCustody implements KeyCustody {
  readonly provider = 'postgres-dev' as const;
  readonly capabilities: KeyCustodyCapabilities = { rotate: true, generateOnDemand: true };

  private readonly listeners: CustodyEventListener[] = [];
  private keys = new Map<string, LoadedKey>();
  private active: string | null = null;

  constructor(
    private readonly pool: Pool,
    nodeEnv: string,
  ) {
    if (nodeEnv === 'production') {
      throw new Error(
        'KEY_CUSTODY=postgres-dev is refused in production: it stores the broker signing key ' +
          "as plaintext in the database and imports it into this process, which is exactly what " +
          'T13 and SPEC 06 §3 forbid ("never sit in app memory as plaintext", "never leave the ' +
          'boundary in plaintext") and what 07 §5 forbids ("secrets/keys in KMS/HSM, not the ' +
          'DB"). Spec open decision #5 requires a GoR-approved in-country KMS or an on-prem HSM. ' +
          'Set KEY_CUSTODY=kms (apps/broker/src/keys/kms.custody.ts) or KEY_CUSTODY=hsm ' +
          '(apps/broker/src/keys/hsm-pkcs11.custody.ts) and supply that provider\'s adapter — ' +
          'see docs/runbook.md §4.',
      );
    }
  }

  onEvent(listener: CustodyEventListener): void {
    this.listeners.push(listener);
  }

  async init(): Promise<void> {
    await this.reload();
    if (this.active === null) {
      // First boot of a dev database. Generation is a lifecycle event and is
      // audited by the owning service through the listener.
      await this.generateActiveKey();
      await this.reload();
    }
  }

  async activeKid(): Promise<string> {
    if (this.active === null) {
      throw new KeyCustodyUnavailableError(
        this.provider,
        'no active signing key is loaded (call init() first, or check the signing_keys table)',
      );
    }
    return this.active;
  }

  async listPublicJwks(): Promise<PublicJwks> {
    // Active AND retired: a token minted before the last rotation must keep
    // verifying for its whole lifetime (06 §3 overlap).
    return { keys: [...this.keys.values()].map((k) => k.publicJwk) };
  }

  async listKeys(): Promise<SigningKeyDescriptor[]> {
    return [...this.keys.values()].map((k) => k.descriptor);
  }

  async sign(kid: string, data: Uint8Array): Promise<Uint8Array> {
    let key = this.keys.get(kid);
    if (!key) {
      // Another replica may have rotated since our last load. One reload, then
      // give up — a signing path must not turn into an unbounded DB retry.
      await this.reload();
      key = this.keys.get(kid);
    }
    if (!key) {
      throw new KeyCustodySigningError(this.provider, kid, `no key with kid=${kid} in custody`);
    }
    let signature: Uint8Array;
    try {
      // `ieee-p1363` asks node:crypto for the raw r||s JWS form directly, so
      // this provider needs no DER conversion. A KMS/HSM generally does —
      // see normalizeEcdsaSignature() in key-custody.ts.
      signature = cryptoSign('sha256', data, { key: key.privateKey, dsaEncoding: IEEE_P1363 });
    } catch (err) {
      throw new KeyCustodySigningError(
        this.provider,
        kid,
        `local ES256 signature failed: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
    assertJwsSignatureShape(signature, ALG);
    return signature;
  }

  async healthCheck(): Promise<CustodyHealth> {
    try {
      // Reaches the backend on purpose (contract point 5): "the row exists in
      // my cache" is not the same fact as "I can sign", and re-reading also
      // means a rotation performed elsewhere lands without a restart.
      await this.reload();
    } catch (err) {
      return {
        healthy: false,
        provider: this.provider,
        activeKid: this.active,
        detail: `signing_keys read failed: ${err instanceof Error ? err.message : 'unknown'}`,
      };
    }
    if (this.active === null) {
      return {
        healthy: false,
        provider: this.provider,
        activeKid: null,
        detail: 'no active key in signing_keys',
      };
    }
    return {
      healthy: true,
      provider: this.provider,
      activeKid: this.active,
      detail: `${this.keys.size} key(s) loaded from signing_keys`,
    };
  }

  /**
   * Promote a fresh key and retire the current active one in ONE transaction,
   * under an advisory lock: there must never be a moment with zero active keys
   * (nothing can be minted) or two (replicas disagree on the signing kid).
   * Retired rows stay, so they stay in the JWKS.
   */
  async rotate(): Promise<RotationResult> {
    const client = await this.pool.connect();
    let retiredKids: string[] = [];
    let promotedKid: string;
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [ROTATION_LOCK_KEY]);
      const retired = await client.query<{ kid: string }>(
        `UPDATE signing_keys SET status = 'retired' WHERE status = 'active' RETURNING kid`,
      );
      retiredKids = retired.rows.map((r) => r.kid);
      const generated = generateEs256Jwks();
      promotedKid = generated.kid;
      await client.query(
        `INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk, status)
         VALUES ($1, $2, $3, $4, 'active')`,
        [generated.kid, ALG, JSON.stringify(generated.publicJwk), JSON.stringify(generated.privateJwk)],
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw new KeyCustodyUnavailableError(
        this.provider,
        `rotation failed: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    } finally {
      client.release();
    }
    await this.reload();
    for (const kid of retiredKids) this.emit({ type: 'key_retired', kid, alg: ALG, provider: this.provider });
    this.emit({ type: 'key_generated', kid: promotedKid, alg: ALG, provider: this.provider });
    this.emit({ type: 'key_promoted', kid: promotedKid, alg: ALG, provider: this.provider });
    return { promotedKid, retiredKids, alg: ALG };
  }

  async close(): Promise<void> {
    // The pool belongs to DbService, which closes it. Just drop key material.
    this.keys = new Map();
    this.active = null;
  }

  // --- internals ---------------------------------------------------------

  private emit(event: CustodyEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  /** Insert the very first key. `ON CONFLICT DO NOTHING` handles a boot race. */
  private async generateActiveKey(): Promise<void> {
    const generated = generateEs256Jwks();
    const inserted = await this.pool.query(
      `INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk, status)
       VALUES ($1, $2, $3, $4, 'active')
       ON CONFLICT DO NOTHING
       RETURNING kid`,
      [generated.kid, ALG, JSON.stringify(generated.publicJwk), JSON.stringify(generated.privateJwk)],
    );
    if (inserted.rowCount === 0) return; // another process won the race
    this.emit({
      type: 'key_generated',
      kid: generated.kid,
      alg: ALG,
      provider: this.provider,
      detail: { reason: 'no active key at boot' },
    });
    this.emit({ type: 'key_promoted', kid: generated.kid, alg: ALG, provider: this.provider });
  }

  private async reload(): Promise<void> {
    const { rows } = await this.pool.query<KeyRow>(
      `SELECT kid, alg, public_jwk, private_jwk, status, created_at
         FROM signing_keys
        ORDER BY created_at ASC`,
    );
    const loaded = new Map<string, LoadedKey>();
    let active: string | null = null;
    for (const row of rows) {
      // `reload()` runs on every readiness probe, so re-import only what is
      // new: a kid is the primary key and its material never changes, so an
      // already-loaded KeyObject is still the right one.
      //
      // The private JWK never leaves this function as JSON: it goes straight
      // into a KeyObject and the row object is dropped.
      const privateKey =
        this.keys.get(row.kid)?.privateKey ?? createPrivateKey({ key: row.private_jwk, format: 'jwk' });
      loaded.set(row.kid, {
        descriptor: {
          kid: row.kid,
          alg: ALG,
          status: row.status === 'active' ? 'active' : 'retired',
          createdAt: row.created_at,
        },
        publicJwk: row.public_jwk,
        privateKey,
      });
      if (row.status === 'active' && active === null) active = row.kid;
    }
    this.keys = loaded;
    this.active = active;
  }
}

/**
 * Generate an ES256 keypair as JWKs. `node:crypto` only — the previous
 * implementation used `jose.generateKeyPair`, but jose is now confined to
 * verification (it cannot reach a remote signer, see key-custody.ts).
 */
function generateEs256Jwks(): { kid: string; publicJwk: PublicJwk; privateJwk: JsonWebKey } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = randomBytes(8).toString('hex');
  const publicJwk = publicKey.export({ format: 'jwk' }) as unknown as PublicJwk;
  publicJwk.kid = kid;
  publicJwk.alg = ALG;
  publicJwk.use = 'sig';
  const privateJwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
  privateJwk.kid = kid;
  return { kid, publicJwk, privateJwk };
}
