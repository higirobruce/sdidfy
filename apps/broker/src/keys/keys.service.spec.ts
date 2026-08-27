import type { INestApplication } from '@nestjs/common';
import { Test, type TestingModule } from '@nestjs/testing';
import * as jose from 'jose';
import { generateKeyPairSync, randomBytes, sign as cryptoSign, type KeyObject } from 'node:crypto';
import type { Pool } from 'pg';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditModule } from '../audit/audit.service.js';
import { DbModule, DbService } from '../db/db.module.js';
import { HealthService } from '../observability/health.service.js';
import { ObservabilityModule } from '../observability/observability.module.js';
import { RedisModule } from '../redis/redis.module.js';
import {
  KeyCustodySigningError,
  normalizeEcdsaSignature,
  type CustodyEventListener,
  type CustodyHealth,
  type KeyCustody,
  type PublicJwk,
  type PublicJwks,
  type RotationResult,
  type SigningKeyDescriptor,
} from './key-custody.js';
import { KEY_CUSTODY, KeysModule, KeysService } from './keys.service.js';

/**
 * KeysService over a real custody boundary (04 §4, 06 §3, T13, decision #5).
 *
 * Real Postgres + Redis, following the other broker specs. Two custody
 * boundaries are exercised: the `postgres-dev` provider (what dev, the test
 * suite and the demo actually run) and a hand-written in-memory one, which is
 * the load-bearing test — if the service works against a custody with no
 * database anywhere near it, the seam is a real boundary and not a Postgres
 * store wearing an interface.
 */

// ---------------------------------------------------------------------------
// A custody boundary with no Postgres in it at all
// ---------------------------------------------------------------------------

interface FakeKey {
  kid: string;
  status: 'active' | 'retired';
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/**
 * Implements `KeyCustody` from scratch. Deliberately unlike the dev provider:
 * keys live in an array, kids are not hex, `sign()` returns DER (as a real
 * backend would) and lets `normalizeEcdsaSignature` do the conversion the
 * interface documents as the provider's job.
 */
class FakeInMemoryCustody implements KeyCustody {
  readonly provider = 'kms' as const;
  readonly capabilities = { rotate: true, generateOnDemand: false };
  readonly keys: FakeKey[] = [];
  /**
   * Kids are unique per instance. `audit_events` is append-only (07 §4), so a
   * test can never clean up after itself — it must be able to find its OWN
   * rows in a table that keeps every previous run's.
   */
  readonly label = `fake-${randomBytes(4).toString('hex')}`;
  /** Flip to make every signature fail, the way an expired credential does. */
  failSigning: string | null = null;
  /** Flip to make the backend unreachable. */
  unhealthy: string | null = null;
  signCalls = 0;

  private readonly listeners: CustodyEventListener[] = [];
  private counter = 0;

  onEvent(listener: CustodyEventListener): void {
    this.listeners.push(listener);
  }

  async init(): Promise<void> {
    if (this.keys.length === 0) this.mint();
  }

  async activeKid(): Promise<string> {
    const active = this.keys.find((k) => k.status === 'active');
    if (!active) throw new Error('no active key');
    return active.kid;
  }

  async listPublicJwks(): Promise<PublicJwks> {
    return {
      keys: this.keys.map((k) => {
        const jwk = k.publicKey.export({ format: 'jwk' }) as unknown as PublicJwk;
        jwk.kid = k.kid;
        jwk.alg = 'ES256';
        jwk.use = 'sig';
        return jwk;
      }),
    };
  }

  async listKeys(): Promise<SigningKeyDescriptor[]> {
    return this.keys.map((k) => ({
      kid: k.kid,
      alg: 'ES256' as const,
      status: k.status,
      createdAt: new Date(0),
    }));
  }

  async sign(kid: string, data: Uint8Array): Promise<Uint8Array> {
    this.signCalls += 1;
    if (this.failSigning) throw new KeyCustodySigningError('kms', kid, this.failSigning);
    const key = this.keys.find((k) => k.kid === kid);
    if (!key) throw new KeyCustodySigningError('kms', kid, 'unknown kid');
    const der = cryptoSign('sha256', data, { key: key.privateKey, dsaEncoding: 'der' });
    return normalizeEcdsaSignature(new Uint8Array(der));
  }

  async healthCheck(): Promise<CustodyHealth> {
    if (this.unhealthy) {
      return { healthy: false, provider: this.provider, activeKid: null, detail: this.unhealthy };
    }
    const active = this.keys.find((k) => k.status === 'active');
    return {
      healthy: active !== undefined,
      provider: this.provider,
      activeKid: active?.kid ?? null,
      detail: `in-memory: ${this.keys.length} key(s)`,
    };
  }

  async rotate(): Promise<RotationResult> {
    const retiredKids: string[] = [];
    for (const key of this.keys) {
      if (key.status === 'active') {
        key.status = 'retired';
        retiredKids.push(key.kid);
        this.emit('key_retired', key.kid);
      }
    }
    const promoted = this.mint();
    return { promotedKid: promoted.kid, retiredKids, alg: 'ES256' };
  }

  async close(): Promise<void> {
    /* nothing to release */
  }

  private mint(): FakeKey {
    this.counter += 1;
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const key: FakeKey = {
      kid: `${this.label}-${this.counter}`,
      status: 'active',
      publicKey,
      privateKey,
    };
    this.keys.push(key);
    this.emit('key_generated', key.kid);
    this.emit('key_promoted', key.kid);
    return key;
  }

  private emit(type: 'key_generated' | 'key_promoted' | 'key_retired', kid: string): void {
    for (const listener of this.listeners) {
      listener({ type, kid, alg: 'ES256', provider: this.provider });
    }
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface Harness {
  app: INestApplication;
  moduleRef: TestingModule;
  keys: KeysService;
  pool: Pool;
  health: HealthService;
}

async function createHarness(custody?: KeyCustody): Promise<Harness> {
  let builder = Test.createTestingModule({
    imports: [ObservabilityModule, DbModule, RedisModule, AuditModule, KeysModule],
  });
  if (custody) builder = builder.overrideProvider(KEY_CUSTODY).useValue(custody);
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return {
    app,
    moduleRef,
    keys: moduleRef.get(KeysService),
    pool: moduleRef.get(DbService).pool,
    health: moduleRef.get(HealthService),
  };
}

/** Audit rows are append-only (07 §4), so tests read a window, never delete. */
async function auditHead(pool: Pool): Promise<number> {
  const { rows } = await pool.query<{ seq: string }>(
    'SELECT coalesce(max(seq), 0) AS seq FROM audit_events',
  );
  return Number(rows[0]?.seq ?? 0);
}

async function auditSince(
  pool: Pool,
  seq: number,
): Promise<Array<{ action: string; result: string; context: Record<string, unknown> | null }>> {
  const { rows } = await pool.query<{
    action: string;
    result: string;
    context: Record<string, unknown> | null;
  }>('SELECT action, result, context FROM audit_events WHERE seq > $1 ORDER BY seq ASC', [seq]);
  return rows;
}

// ---------------------------------------------------------------------------

describe('signing through the dev custody boundary', () => {
  let h: Harness;

  afterEach(async () => {
    await h.app.close();
  });

  it('mints a token that verifies against the published JWKS', async () => {
    h = await createHarness();
    const token = await h.keys.signJwt({ sub: 'citizen-1' }, { audience: 'rp-1', ttlSeconds: 60 });

    const payload = await h.keys.verifyJwt(token, { audience: 'rp-1' });
    expect(payload.sub).toBe('citizen-1');
    expect(payload.iss).toBe(h.keys.issuer);
    expect(payload.jti).toBeTypeOf('string');

    // …and independently, using nothing but the JSON the /oidc/jwks endpoint
    // serves. This is the check that matters: a relying party has the JWKS and
    // nothing else, and the whole custody refactor is worthless if the
    // signature and the published key ever diverge.
    const published = JSON.parse(JSON.stringify(h.keys.jwks())) as jose.JSONWebKeySet;
    const { payload: reverified } = await jose.jwtVerify(token, jose.createLocalJWKSet(published), {
      issuer: h.keys.issuer,
      audience: 'rp-1',
    });
    expect(reverified.sub).toBe('citizen-1');
  });

  it('emits a compact JWS assembled by hand: ES256, kid, typ, 64-byte signature', async () => {
    h = await createHarness();
    const token = await h.keys.signJwt({}, { audience: 'a', ttlSeconds: 60 });
    const [encodedHeader, , encodedSignature] = token.split('.');
    const header = JSON.parse(Buffer.from(encodedHeader ?? '', 'base64url').toString('utf8'));
    expect(header).toEqual({ alg: 'ES256', kid: expect.any(String), typ: 'JWT' });
    // Raw r||s, never DER — a DER signature here would be rejected by every RP.
    expect(Buffer.from(encodedSignature ?? '', 'base64url')).toHaveLength(64);
    expect(header.kid).toBe(h.keys.jwks().keys.find((k) => k.kid === header.kid)?.kid);
  });

  it('probeSigning exercises custody for real: health, signature, JWKS verification', async () => {
    h = await createHarness();
    await expect(h.keys.probeSigning()).resolves.toBeUndefined();
    const report = await h.health.readiness();
    expect(report.checks.signing_key).toBe('ok');
  });
});

describe('the custody seam is a real boundary (in-memory provider, no Postgres)', () => {
  let h: Harness;
  let custody: FakeInMemoryCustody;

  afterEach(async () => {
    await h.app.close();
  });

  it('signs and verifies end to end against a custody with no database', async () => {
    custody = new FakeInMemoryCustody();
    h = await createHarness(custody);

    const token = await h.keys.signJwt({ sub: 's' }, { audience: 'aud', ttlSeconds: 60 });
    const header = jose.decodeProtectedHeader(token);
    expect(header.kid).toBe(custody.keys[0]?.kid);
    // The provider returned DER; what came out is a verifiable JWS.
    await expect(h.keys.verifyJwt(token, { audience: 'aud' })).resolves.toMatchObject({ sub: 's' });
    expect(custody.signCalls).toBeGreaterThan(0);
  });

  it('audits the key generation the provider reported at init (T13)', async () => {
    custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    // The generation happened inside onModuleInit, before this test could take
    // a `seq` baseline — so the rows are found by this instance's unique kid.
    const kid = custody.keys[0]?.kid ?? '';
    const { rows } = await h.pool.query<{ action: string }>(
      "SELECT action FROM audit_events WHERE context->>'kid' = $1 ORDER BY seq ASC",
      [kid],
    );
    const actions = rows.map((r) => r.action);
    expect(actions).toContain('key.generated');
    expect(actions).toContain('key.promoted');
  });

  it('rotates: new key active, old key retired and STILL in the JWKS (overlap, 06 §3)', async () => {
    custody = new FakeInMemoryCustody();
    h = await createHarness(custody);

    const oldToken = await h.keys.signJwt({ sub: 'before' }, { audience: 'aud', ttlSeconds: 300 });
    const oldKid = jose.decodeProtectedHeader(oldToken).kid;

    const before = await auditHead(h.pool);
    const result = await h.keys.rotate();
    expect(result.retiredKids).toEqual([oldKid]);
    expect(result.promotedKid).not.toBe(oldKid);

    // New tokens use the new key…
    const newToken = await h.keys.signJwt({ sub: 'after' }, { audience: 'aud', ttlSeconds: 300 });
    expect(jose.decodeProtectedHeader(newToken).kid).toBe(result.promotedKid);
    // …and the token minted BEFORE the rotation still verifies. This is the
    // whole reason retired keys stay published.
    await expect(h.keys.verifyJwt(oldToken, { audience: 'aud' })).resolves.toMatchObject({
      sub: 'before',
    });
    expect(h.keys.jwks().keys.map((k) => k.kid)).toContain(oldKid);

    const actions = (await auditSince(h.pool, before)).map((r) => r.action);
    expect(actions).toContain('key.retired');
    expect(actions).toContain('key.promoted');
    expect(actions).toContain('key.rotated');
  });

  it('a custody signing failure fails READINESS rather than producing a bad token', async () => {
    custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    custody.failSigning = 'KMS credential expired';

    // No half-signed, unverifiable token is ever returned…
    await expect(h.keys.signJwt({}, { audience: 'aud', ttlSeconds: 60 })).rejects.toThrow(
      /KMS credential expired/,
    );
    // …and the replica takes itself out of rotation.
    await expect(h.keys.probeSigning()).rejects.toThrow(/KMS credential expired/);
    const report = await h.health.readiness();
    expect(report.ready).toBe(false);
    expect(report.checks.signing_key).toBe('fail');
    expect(report.checks.postgres).toBe('ok');
  });

  it('an unreachable custody backend also fails readiness, and the transition is audited', async () => {
    custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    await h.keys.probeSigning(); // establishes "healthy"

    const before = await auditHead(h.pool);
    custody.unhealthy = 'PKCS#11 session invalid';
    await expect(h.keys.probeSigning()).rejects.toThrow(/PKCS#11 session invalid/);
    expect((await h.health.readiness()).checks.signing_key).toBe('fail');

    const transitions = (await auditSince(h.pool, before)).filter(
      (r) => r.action === 'key.custody_health_changed',
    );
    // One row for the transition, not one per probe — the probe runs every
    // few seconds and an outage must not write a row every time.
    expect(transitions).toHaveLength(1);
    expect(transitions[0]?.result).toBe('failure');
    expect(transitions[0]?.context).toMatchObject({ healthy: false, provider: 'kms' });
  });
});

describe('key-usage audit (T13) — a summary, never a row per token', () => {
  let h: Harness;

  afterEach(async () => {
    await h.app.close();
  });

  it('writes ONE summary row for many signatures, with the per-kid tally', async () => {
    const custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    const before = await auditHead(h.pool);

    const signatures = 25;
    for (let i = 0; i < signatures; i += 1) {
      await h.keys.signJwt({ n: i }, { audience: 'aud', ttlSeconds: 60 });
    }
    await h.keys.probeSigning(); // probe signatures are counted separately
    await h.keys.flushUsageSummary('interval');

    const rows = await auditSince(h.pool, before);
    const summaries = rows.filter((r) => r.action === 'key.usage_summary');
    expect(summaries).toHaveLength(1);
    // The append-only chain grew by a handful of rows, not by 25.
    expect(rows.length).toBeLessThan(signatures);

    const context = summaries[0]?.context as {
      provider: string;
      reason: string;
      keys: Array<{ kid: string; alg: string; signatures: number; probeSignatures: number }>;
    };
    expect(context.provider).toBe('kms');
    expect(context.reason).toBe('interval');
    const tally = context.keys.find((k) => k.kid === custody.keys[0]?.kid);
    expect(tally).toMatchObject({ alg: 'ES256', signatures });
    expect(tally?.probeSignatures).toBeGreaterThanOrEqual(1);
  });

  it('flushes nothing when nothing was signed', async () => {
    h = await createHarness(new FakeInMemoryCustody());
    const before = await auditHead(h.pool);
    await h.keys.flushUsageSummary('interval');
    expect(await auditSince(h.pool, before)).toHaveLength(0);
  });

  it('records failures in the summary and writes at most one immediate row per kid', async () => {
    const custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    const before = await auditHead(h.pool);

    custody.failSigning = 'backend refused';
    for (let i = 0; i < 5; i += 1) {
      await h.keys.signJwt({}, { audience: 'aud', ttlSeconds: 60 }).catch(() => undefined);
    }
    await h.keys.flushUsageSummary('interval');

    const rows = await auditSince(h.pool, before);
    const failures = rows.filter((r) => r.action === 'key.signing_failed');
    // Throttled: a custody outage must not write a row per retry.
    expect(failures).toHaveLength(1);
    expect(failures[0]?.result).toBe('failure');

    const summary = rows.find((r) => r.action === 'key.usage_summary');
    expect(summary?.result).toBe('failure');
    const tally = (
      summary?.context as { keys: Array<{ failures: number; suppressedFailureRows: number }> }
    ).keys[0];
    expect(tally?.failures).toBe(5);
    expect(tally?.suppressedFailureRows).toBe(4);
  });

  it('flushes on rotation so a tally is attributed to the key that earned it', async () => {
    const custody = new FakeInMemoryCustody();
    h = await createHarness(custody);
    await h.keys.signJwt({}, { audience: 'aud', ttlSeconds: 60 });
    const before = await auditHead(h.pool);
    await h.keys.rotate();
    const summaries = (await auditSince(h.pool, before)).filter(
      (r) => r.action === 'key.usage_summary',
    );
    expect(summaries).toHaveLength(1);
    expect(summaries[0]?.context).toMatchObject({ reason: 'rotation' });
  });
});

describe('rotation against the real postgres-dev store', () => {
  it('promotes a new row, retires the old one, and keeps both in the JWKS', async () => {
    const h = await createHarness();
    const originalActive = await (async (): Promise<string> => {
      const { rows } = await h.pool.query<{ kid: string }>(
        "SELECT kid FROM signing_keys WHERE status = 'active'",
      );
      return rows[0]?.kid ?? '';
    })();
    expect(originalActive).not.toBe('');
    const preexisting = (
      await h.pool.query<{ kid: string }>('SELECT kid FROM signing_keys')
    ).rows.map((r) => r.kid);

    const oldToken = await h.keys.signJwt({ sub: 'pre' }, { audience: 'aud', ttlSeconds: 300 });
    try {
      const result = await h.keys.rotate();
      expect(result.retiredKids).toContain(originalActive);
      expect(result.promotedKid).not.toBe(originalActive);

      const statuses = (
        await h.pool.query<{ kid: string; status: string }>('SELECT kid, status FROM signing_keys')
      ).rows;
      expect(statuses.filter((r) => r.status === 'active')).toHaveLength(1);
      expect(statuses.find((r) => r.kid === originalActive)?.status).toBe('retired');

      // Overlap: the pre-rotation token still verifies, and the retired key is
      // still published.
      await expect(h.keys.verifyJwt(oldToken, { audience: 'aud' })).resolves.toMatchObject({
        sub: 'pre',
      });
      expect(h.keys.jwks().keys.map((k) => k.kid)).toContain(originalActive);
    } finally {
      // Leave the shared dev store exactly as it was: signing_keys is not
      // append-only (unlike audit_events, which is never touched here).
      await h.pool.query('DELETE FROM signing_keys WHERE NOT (kid = ANY($1::text[]))', [preexisting]);
      await h.pool.query("UPDATE signing_keys SET status = 'active' WHERE kid = $1", [originalActive]);
      await h.app.close();
    }
  });
});
