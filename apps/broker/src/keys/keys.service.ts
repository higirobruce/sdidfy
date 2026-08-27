import { Global, Injectable, Module, OnModuleInit } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import * as jose from 'jose';
import { randomBytes } from 'node:crypto';
import { DbService } from '../db/db.module.js';
import { signingKeys } from '../db/schema.js';
import { loadConfig } from '../config.js';

/**
 * Broker token-signing keys (04 §4, T13). ES256, rotated with JWKS overlap:
 * retired keys stay in the JWKS until their tokens can no longer be live.
 *
 * DEV NOTE: private JWKs are stored in Postgres for development only. The
 * production implementation swaps this KeyStore for the GoR-approved KMS/HSM
 * (open decision #5) — the signing interface below is the seam.
 */
@Injectable()
export class KeysService implements OnModuleInit {
  private activeKid!: string;
  private privateKey!: jose.KeyLike;
  private publicJwks: jose.JSONWebKeySet = { keys: [] };

  constructor(private readonly dbService: DbService) {}

  async onModuleInit(): Promise<void> {
    await this.ensureActiveKey();
  }

  async ensureActiveKey(): Promise<void> {
    const db = this.dbService.db;
    let rows = await db.select().from(signingKeys).where(eq(signingKeys.status, 'active'));
    if (rows.length === 0) {
      const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
      const publicJwk = await jose.exportJWK(publicKey);
      const privateJwk = await jose.exportJWK(privateKey);
      const kid = randomBytes(8).toString('hex');
      publicJwk.kid = kid;
      publicJwk.alg = 'ES256';
      publicJwk.use = 'sig';
      privateJwk.kid = kid;
      await db
        .insert(signingKeys)
        .values({ kid, alg: 'ES256', publicJwk, privateJwk, status: 'active' })
        .onConflictDoNothing();
      rows = await db.select().from(signingKeys).where(eq(signingKeys.status, 'active'));
    }
    const active = rows[0]!;
    this.activeKid = active.kid;
    this.privateKey = (await jose.importJWK(active.privateJwk as jose.JWK, 'ES256')) as jose.KeyLike;
    const all = await db.select().from(signingKeys);
    this.publicJwks = { keys: all.map((k) => k.publicJwk as jose.JWK) };
  }

  get issuer(): string {
    return loadConfig().BROKER_ISSUER;
  }

  /**
   * Readiness probe (/readyz): can this replica actually SIGN?
   *
   * It performs a real signature rather than checking that a row or a variable
   * exists, because "the key is present" and "the key is usable" are different
   * facts, and only the second one determines whether a citizen can be issued
   * a token. Today they nearly always coincide (the private JWK is imported
   * once at boot); once custody moves to KMS/HSM (decision #5) they diverge
   * exactly when it matters — an expired credential, a revoked grant, an
   * unreachable HSM — and this probe is what takes the replica out of rotation
   * instead of failing citizens' logins. ES256 over a few bytes is cheap
   * enough to run on every probe.
   *
   * The probe token is never returned to anyone: it exists only to be signed.
   */
  async probeSigning(): Promise<void> {
    if (!this.activeKid || this.publicJwks.keys.length === 0) {
      throw new Error('no active signing key loaded');
    }
    await new jose.SignJWT({ probe: true })
      .setProtectedHeader({ alg: 'ES256', kid: this.activeKid, typ: 'JWT' })
      .setIssuer(this.issuer)
      .setAudience('readiness-probe')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(this.privateKey);
  }

  jwks(): jose.JSONWebKeySet {
    return this.publicJwks;
  }

  /** Sign a JWT with the active broker key. `jti` is always set (revocation denylist). */
  async signJwt(
    payload: Record<string, unknown>,
    opts: { audience: string; ttlSeconds: number; jti?: string },
  ): Promise<string> {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256', kid: this.activeKid, typ: 'JWT' })
      .setIssuer(this.issuer)
      .setAudience(opts.audience)
      .setIssuedAt()
      .setExpirationTime(`${opts.ttlSeconds}s`)
      .setJti(opts.jti ?? randomBytes(16).toString('hex'))
      .sign(this.privateKey);
  }

  /** Verify a broker-issued JWT (first-party sessions, access tokens at /userinfo). */
  async verifyJwt(token: string, opts?: { audience?: string }): Promise<jose.JWTPayload> {
    const keyset = jose.createLocalJWKSet(this.publicJwks);
    const { payload } = await jose.jwtVerify(token, keyset, {
      issuer: this.issuer,
      audience: opts?.audience,
    });
    return payload;
  }
}

@Global()
@Module({
  providers: [KeysService],
  exports: [KeysService],
})
export class KeysModule {}
