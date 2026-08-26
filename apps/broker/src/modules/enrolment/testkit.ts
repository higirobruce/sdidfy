import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { createHash, createHmac, randomBytes, webcrypto } from 'node:crypto';
import request from 'supertest';
import { inArray, like } from 'drizzle-orm';
import {
  MOCK_TEST_NIDS,
  mockBiometricBytes,
  uuidv7,
  type AttributeSet,
  type BiometricModality,
  type ReassertResult,
  type ReferenceBiometricResult,
  type SdidProvider,
} from '@sdid/shared';
import { AnomalyModule } from '../../anomaly/anomaly.module.js';
import { LoggingModule } from '../../logging/logging.module.js';
import { ObservabilityModule } from '../../observability/observability.module.js';
import { DbModule, DbService } from '../../db/db.module.js';
import { RedisModule, RedisService } from '../../redis/redis.module.js';
import { KeysModule } from '../../keys/keys.service.js';
import { AuditModule } from '../../audit/audit.service.js';
import { TrustModule } from '../../trust/trust.module.js';
import { PushModule } from '../../push/push.service.js';
import { SdidModule, SDID_PROVIDER } from '../../sdid/sdid.module.js';
import { BridgeErrorFilter } from '../../common/bridge-error.filter.js';
import {
  authTransactions,
  citizens,
  consentGrants,
  deviceBindings,
  pairwiseSubjects,
  relyingParties,
} from '../../db/schema.js';
import {
  ATTESTATION_VERIFIERS,
  type AttestationVerifierSource,
} from '../../trust/attestation-verifiers.provider.js';
import { EnrolmentModule } from './enrolment.module.js';
import { DevicesModule } from '../devices/devices.module.js';
import { ConsentModule } from '../consent/consent.module.js';

/**
 * Integration-test support (real Postgres + Redis). SDID_PROVIDER is overridden
 * with a local fake honoring the SdidProvider contract: it lets tests drive
 * deterministic SDID outcomes by reserved NID (unknown identity, unavailable
 * subtype) without depending on adapter internals. The real MockMatchEngine
 * from @sdid/match-engine is used as-is.
 */

export const TESTKIT_RP_CLIENT_PREFIX = 'testkit-rp-';

/** Same derivation as PairwiseService.pseudoNid (keyed hash of NID — Q8). */
export function pseudoNidOf(nid: string): string {
  const pepper = process.env.NID_PEPPER ?? 'dev-only-nid-pepper-change-me';
  return createHmac('sha256', pepper).update(nid).digest('hex');
}

/**
 * Reserved NID that makes the fake SDID surface an "unavailable" SUBTYPE error
 * (a timeout), exactly as the resilience wrapper would in production. Used to
 * prove the broker maps every SdidUnavailable subtype — not just the base
 * class — to HTTP 503 (02 §4). Not in MOCK_TEST_NIDS, so it never matches.
 */
export const SDID_UNAVAILABLE_NID = '2000000000000000';

/** Local fake for the SdidProvider contract (mock strategy semantics, 02 §2). */
export class FakeSdidProvider implements SdidProvider {
  async getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult> {
    if (input.nid === SDID_UNAVAILABLE_NID) {
      // Subtype of SdidUnavailableError — overrides `.name`, like the real
      // timeout/circuit-open/malformed errors the adapter throws.
      const err = new Error('SDID call timed out after 2000ms');
      err.name = 'SdidTimeoutError';
      throw err;
    }
    if (!(MOCK_TEST_NIDS as readonly string[]).includes(input.nid)) {
      const err = new Error('SDID does not know this identity');
      err.name = 'SdidUnknownIdentityError';
      throw err;
    }
    return {
      reference: {
        modality: input.modality,
        // Fresh buffer per call — the match engine zeroizes it post-match.
        data: mockBiometricBytes(input.nid, input.modality),
        format: 'mock',
      },
      sdidSubject: `mock-subject-${createHash('sha256').update(input.nid).digest('hex').slice(0, 16)}`,
      txnRef: `mock-txn-${randomBytes(6).toString('hex')}`,
    };
  }

  async getAttributes(): Promise<AttributeSet> {
    return { faceReferenceAvailable: true };
  }

  async reassert(): Promise<ReassertResult> {
    return { valid: true, assurance: 'AL2', txnRef: `mock-txn-${randomBytes(6).toString('hex')}` };
  }
}

/**
 * Simulated device (05): P-256 keypair via WebCrypto, ECDSA/SHA-256 raw
 * signatures base64url-encoded, mock attestation token, and a "capture"
 * derived from the canonical mock biometric bytes.
 */
type WebCryptoKeyPair = import('node:crypto').webcrypto.CryptoKeyPair;

export class SimDevice {
  private constructor(
    private readonly keyPair: WebCryptoKeyPair,
    readonly publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string },
  ) {}

  static async create(): Promise<SimDevice> {
    const keyPair = (await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as WebCryptoKeyPair;
    const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    return new SimDevice(keyPair, {
      kty: 'EC',
      crv: 'P-256',
      x: jwk.x as string,
      y: jwk.y as string,
    });
  }

  async sign(payload: string): Promise<string> {
    const sig = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.keyPair.privateKey,
      Buffer.from(payload, 'utf8'),
    );
    return Buffer.from(sig).toString('base64url');
  }

  /**
   * Mock attestation payload. `opts.nonce` is embedded in the token (as a real
   * platform token binds the server nonce under its own signature) and
   * `opts.nonceId` rides alongside; `opts.platform` lets strict-mode tests
   * present themselves as a real platform instead of 'sim'.
   */
  attestation(opts?: AttestationOpts): {
    platform: 'sim' | 'android' | 'ios';
    token: string;
    keyAttestation?: string;
    nonceId?: string;
  } {
    const token = Buffer.from(
      JSON.stringify({
        mock: true,
        deviceIntegrity: true,
        appIntegrity: true,
        hardwareBackedKey: true,
        ...(opts?.nonce !== undefined ? { nonce: opts.nonce } : {}),
      }),
      'utf8',
    ).toString('base64url');
    return {
      platform: opts?.platform ?? 'sim',
      token,
      keyAttestation: 'x',
      ...(opts?.nonceId !== undefined ? { nonceId: opts.nonceId } : {}),
    };
  }

  /** Sample "captured" for a NID. `sampleFromNid` ≠ nid simulates an impostor. */
  sample(nid: string, opts?: { score?: number; sampleFromNid?: string; modality?: 'face' | 'fingerprint' }) {
    const modality = opts?.modality ?? ('face' as const);
    return {
      modality,
      data: Buffer.from(mockBiometricBytes(opts?.sampleFromNid ?? nid, modality)).toString('base64'),
      liveness: { method: 'active-blink', score: opts?.score ?? 0.97 },
    };
  }

  enrolStartBody(
    nid: string,
    deviceLabel: string,
    sampleOpts?: Parameters<SimDevice['sample']>[1],
    attestationOpts?: AttestationOpts,
  ) {
    return {
      nid,
      devicePublicKeyJwk: this.publicKeyJwk,
      attestation: this.attestation(attestationOpts),
      deviceLabel,
      sample: this.sample(nid, sampleOpts),
    };
  }
}

export interface AttestationOpts {
  nonceId?: string;
  nonce?: string;
  platform?: 'sim' | 'android' | 'ios';
}

export interface TestContext {
  app: INestApplication;
  db: DbService;
  redis: RedisService;
  http: () => ReturnType<typeof request>;
}

export async function createTestApp(overrides?: {
  /**
   * Replace the platform verifier set at the module seam (never by patching
   * @sdid/attestation internals) so strict-mode tests can drive any verdict.
   */
  attestationVerifiers?: AttestationVerifierSource;
}): Promise<TestContext> {
  const builder = Test.createTestingModule({
    imports: [
      // Observability/logging/anomaly are global infra the domain modules now
      // inject; they must be present or DI fails at compile() (they are also
      // in AppModule, so the test graph matches production).
      ObservabilityModule,
      LoggingModule,
      AnomalyModule,
      DbModule,
      RedisModule,
      KeysModule,
      AuditModule,
      TrustModule,
      PushModule,
      SdidModule,
      EnrolmentModule,
      DevicesModule,
      ConsentModule,
    ],
  }).overrideProvider(SDID_PROVIDER).useValue(new FakeSdidProvider());
  if (overrides?.attestationVerifiers) {
    builder.overrideProvider(ATTESTATION_VERIFIERS).useValue(overrides.attestationVerifiers);
  }
  const moduleRef = await builder.compile();

  const app = moduleRef.createNestApplication();
  app.useGlobalFilters(new BridgeErrorFilter());
  await app.init();
  return {
    app,
    db: app.get(DbService),
    redis: app.get(RedisService),
    http: () => request(app.getHttpServer()),
  };
}

/**
 * Remove THIS suite's rows in FK order, keyed by the pseudo NIDs of the
 * MOCK_TEST_NIDS (plus any extra NIDs the suite probed). audit_events is
 * append-only (DB trigger) and is NEVER touched.
 */
export async function cleanTestData(ctx: TestContext, extraNids: string[] = []): Promise<void> {
  const db = ctx.db.db;
  const pseudos = [...MOCK_TEST_NIDS, ...extraNids].map(pseudoNidOf);
  const citizenRows = await db
    .select({ id: citizens.id })
    .from(citizens)
    .where(inArray(citizens.pseudoNid, pseudos));
  const ids = citizenRows.map((r) => r.id);
  if (ids.length > 0) {
    await db.delete(consentGrants).where(inArray(consentGrants.citizenId, ids));
    await db.delete(authTransactions).where(inArray(authTransactions.citizenId, ids));
    await db.delete(deviceBindings).where(inArray(deviceBindings.citizenId, ids));
    await db.delete(pairwiseSubjects).where(inArray(pairwiseSubjects.citizenId, ids));
    await db.delete(citizens).where(inArray(citizens.id, ids));
  }
  await db
    .delete(relyingParties)
    .where(like(relyingParties.clientId, `${TESTKIT_RP_CLIENT_PREFIX}%`));

  // Reset this suite's rate-limit / lockout counters so reruns stay green
  // (fixed windows outlive a test run). Prefixes are enrolment-specific.
  const client = ctx.redis.client;
  for (const pattern of ['rl:enrol:*', 'lockout:enrol:*', 'attnonce:*', 'anom:*']) {
    let cursor = '0';
    do {
      const [next, keys] = await client.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
      cursor = next;
      if (keys.length > 0) await client.del(...keys);
    } while (cursor !== '0');
  }
}

/** Clear the per-NID enrolment rate-limit window (multi-enrol tests). */
export async function clearEnrolRateLimit(ctx: TestContext, nid: string): Promise<void> {
  await ctx.redis.client.del(`rl:enrol:nid:${pseudoNidOf(nid)}`);
}

/** Insert a relying party this testkit owns (cleaned by clientId prefix). */
export async function insertTestRp(ctx: TestContext, name = 'Testkit RP'): Promise<string> {
  const id = uuidv7();
  await ctx.db.db.insert(relyingParties).values({
    id,
    clientId: `${TESTKIT_RP_CLIENT_PREFIX}${randomBytes(6).toString('hex')}`,
    name,
    authMethod: 'secret',
    allowedScopes: ['openid', 'profile'],
    maxAssurance: 'AL2',
    allowedFlows: ['ciba'],
    redirectUris: [],
    pairwiseSalt: randomBytes(16).toString('hex'),
  });
  return id;
}

/** Mint a single-use attestation nonce over HTTP (03 §2 step 1, T4). */
export async function mintAttestationNonce(
  ctx: TestContext,
): Promise<{ nonceId: string; nonce: string; expiresAt: string }> {
  const res = await ctx.http().post('/v1/enrol/attestation-challenge').expect(200);
  return res.body as { nonceId: string; nonce: string; expiresAt: string };
}

/** Full enrol→activate; returns the ACTIVE bindingId. */
export async function enrolAndActivate(
  ctx: TestContext,
  device: SimDevice,
  nid: string,
  deviceLabel = 'Sim phone',
): Promise<string> {
  const startRes = await ctx.http()
    .post('/v1/enrol/start')
    .send(device.enrolStartBody(nid, deviceLabel))
    .expect(200);
  const { bindingId, activationChallenge } = startRes.body;
  const signature = await device.sign(activationChallenge.payload);
  await ctx.http()
    .post('/v1/enrol/activate')
    .send({ bindingId, challengeId: activationChallenge.challengeId, signature })
    .expect(200);
  return bindingId;
}

/** Direct login (challenge → sign → session token). */
export async function login(
  ctx: TestContext,
  device: SimDevice,
  bindingId: string,
): Promise<string> {
  const chRes = await ctx.http()
    .post('/v1/device/login/challenge')
    .send({ bindingId })
    .expect(200);
  const signature = await device.sign(chRes.body.payload);
  const loginRes = await ctx.http()
    .post('/v1/device/login')
    .send({ bindingId, challengeId: chRes.body.challengeId, signature })
    .expect(200);
  return loginRes.body.sessionToken as string;
}
