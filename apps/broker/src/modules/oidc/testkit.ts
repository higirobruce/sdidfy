import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  uuidv7,
  type AssuranceLevel,
  type RegisterRpRequest,
  type SdidProvider,
} from '@sdid/shared';
import { inArray } from 'drizzle-orm';
import { randomBytes, webcrypto } from 'node:crypto';
import request from 'supertest';
import { AuditModule, AuditService } from '../../audit/audit.service.js';
import { BridgeErrorFilter } from '../../common/bridge-error.filter.js';
import { DbModule, DbService } from '../../db/db.module.js';
import {
  authTransactions,
  authorizationCodes,
  citizens,
  consentGrants,
  deviceBindings,
  pairwiseSubjects,
  relyingParties,
} from '../../db/schema.js';
import { KeysModule, KeysService } from '../../keys/keys.service.js';
import { PushModule } from '../../push/push.service.js';
import { RedisModule, RedisService } from '../../redis/redis.module.js';
import { SDID_PROVIDER, SdidModule } from '../../sdid/sdid.module.js';
import { DEVICE_SESSION_AUDIENCE } from '../../trust/device-session.guard.js';
import { TrustModule } from '../../trust/trust.module.js';
import { CibaModule } from '../ciba/ciba.module.js';
import { RpModule } from '../rp/rp.module.js';
import { OidcModule } from './oidc.module.js';

export const ADMIN_TOKEN = 'dev-admin-token';

export interface SdidMockState {
  reassertValid: boolean;
  attributes: { name?: string; dateOfBirth?: string; address?: string };
}

export interface Harness {
  app: INestApplication;
  http: () => ReturnType<INestApplication['getHttpServer']>;
  db: DbService;
  redis: RedisService;
  keys: KeysService;
  audit: AuditService;
  sdidState: SdidMockState;
  citizenIds: string[];
  rpIds: string[];
}

/**
 * Integration harness: the full protocol surface (RP + OIDC + CIBA modules)
 * on top of the REAL infra modules (Postgres, Redis, keys, audit, trust).
 * Only the SDID provider is stubbed — the enrolment module owns the real
 * adapter loop; here citizens/bindings are seeded by direct inserts.
 */
export async function createHarness(): Promise<Harness> {
  const sdidState: SdidMockState = {
    reassertValid: true,
    attributes: { name: 'Test Citizen', dateOfBirth: '1990-01-01', address: 'KG 7 Ave 12, Kigali' },
  };
  const sdidMock: SdidProvider = {
    async getReferenceBiometric() {
      throw new Error('not used by the protocol surface tests');
    },
    async getAttributes() {
      return { ...sdidState.attributes };
    },
    async reassert() {
      return { valid: sdidState.reassertValid, assurance: 'AL3', txnRef: 'mock-reassert-txn' };
    },
  };

  const moduleRef = await Test.createTestingModule({
    imports: [
      DbModule,
      RedisModule,
      KeysModule,
      AuditModule,
      TrustModule,
      PushModule,
      SdidModule,
      RpModule,
      OidcModule,
      CibaModule,
    ],
  })
    .overrideProvider(SDID_PROVIDER)
    .useValue(sdidMock)
    .compile();

  const app = moduleRef.createNestApplication();
  app.useGlobalFilters(new BridgeErrorFilter());
  await app.init();

  return {
    app,
    http: () => app.getHttpServer(),
    db: moduleRef.get(DbService),
    redis: moduleRef.get(RedisService),
    keys: moduleRef.get(KeysService),
    audit: moduleRef.get(AuditService),
    sdidState,
    citizenIds: [],
    rpIds: [],
  };
}

/** Delete our own rows (audit_events are append-only and stay). */
export async function destroyHarness(h: Harness): Promise<void> {
  const db = h.db.db;
  try {
    if (h.rpIds.length > 0) {
      await db.delete(authorizationCodes).where(inArray(authorizationCodes.rpId, h.rpIds));
      await db.delete(authTransactions).where(inArray(authTransactions.rpId, h.rpIds));
      await db.delete(consentGrants).where(inArray(consentGrants.rpId, h.rpIds));
      await db.delete(pairwiseSubjects).where(inArray(pairwiseSubjects.rpId, h.rpIds));
    }
    if (h.citizenIds.length > 0) {
      await db.delete(authorizationCodes).where(inArray(authorizationCodes.citizenId, h.citizenIds));
      await db.delete(authTransactions).where(inArray(authTransactions.citizenId, h.citizenIds));
      await db.delete(consentGrants).where(inArray(consentGrants.citizenId, h.citizenIds));
      await db.delete(pairwiseSubjects).where(inArray(pairwiseSubjects.citizenId, h.citizenIds));
      await db.delete(deviceBindings).where(inArray(deviceBindings.citizenId, h.citizenIds));
      await db.delete(citizens).where(inArray(citizens.id, h.citizenIds));
    }
    if (h.rpIds.length > 0) {
      await db.delete(relyingParties).where(inArray(relyingParties.id, h.rpIds));
    }
  } finally {
    await h.app.close();
  }
}

export interface TestDevice {
  citizenId: string;
  pseudoNid: string;
  bindingId: string;
  /** Device-session JWT for the authenticated backchannel. */
  sessionToken: string;
  sign: (payload: string) => Promise<string>;
}

/**
 * Seed a citizen with an ACTIVE device binding by direct insert (the
 * enrolment module owns the real path). The P-256 private key stays in this
 * process, standing in for the phone's secure hardware.
 */
export async function createCitizenWithBinding(
  h: Harness,
  assuranceLevel: AssuranceLevel = 'AL2',
): Promise<TestDevice> {
  const citizenId = uuidv7();
  const bindingId = uuidv7();
  const pseudoNid = `test-pseudo-${randomBytes(12).toString('hex')}`;
  const sdidSubject = `sdid-subj-${randomBytes(12).toString('hex')}`;

  const keyPair = (await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as webcrypto.CryptoKeyPair;
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);

  const db = h.db.db;
  await db.insert(citizens).values({ id: citizenId, pseudoNid, sdidSubject, status: 'active' });
  await db.insert(deviceBindings).values({
    id: bindingId,
    citizenId,
    devicePubkeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
    attestation: { platform: 'sim', verdict: 'test' },
    assuranceLevel,
    status: 'active',
    deviceLabel: 'protocol-test-device',
    activatedAt: new Date(),
  });
  h.citizenIds.push(citizenId);

  const sessionToken = await h.keys.signJwt(
    { sub: citizenId, binding_id: bindingId, acr: assuranceLevel, amr: ['hwk', 'bio'] },
    { audience: DEVICE_SESSION_AUDIENCE, ttlSeconds: 900 },
  );

  const sign = async (payload: string): Promise<string> => {
    const sig = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      Buffer.from(payload, 'utf8'),
    );
    return Buffer.from(sig).toString('base64url');
  };

  return { citizenId, pseudoNid, bindingId, sessionToken, sign };
}

export interface TestRp {
  rpId: string;
  clientId: string;
  clientSecret: string;
}

export async function registerRp(h: Harness, overrides: Partial<RegisterRpRequest> = {}): Promise<TestRp> {
  const body: RegisterRpRequest = {
    name: `Test RP ${randomBytes(4).toString('hex')}`,
    authMethod: 'secret',
    allowedScopes: ['openid', 'profile', 'address'],
    maxAssurance: 'AL3',
    allowedFlows: ['code', 'ciba'],
    redirectUris: ['https://rp.example.test/callback'],
    ...overrides,
  };
  const res = await request(h.http())
    .post('/admin/rps')
    .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
    .send(body)
    .expect(201);
  h.rpIds.push(res.body.rpId);
  return { rpId: res.body.rpId, clientId: res.body.clientId, clientSecret: res.body.clientSecret };
}

/** Bootstrap the RP's login_hint for a test citizen via the admin API. */
export async function provisionSubject(h: Harness, rpId: string, pseudoNid: string): Promise<string> {
  const res = await request(h.http())
    .post(`/admin/rps/${rpId}/pairwise`)
    .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
    .send({ pseudoNid })
    .expect(200);
  return res.body.subject;
}

/** Fetch the device's pending CIBA list and return the txn for authReqId. */
export async function fetchPendingTxn(
  h: Harness,
  device: TestDevice,
  authReqId: string,
): Promise<Record<string, any>> {
  const res = await request(h.http())
    .get('/v1/device/ciba/pending')
    .set('Authorization', `Bearer ${device.sessionToken}`)
    .expect(200);
  const txn = (res.body.transactions as Array<Record<string, any>>).find(
    (t) => t.authReqId === authReqId,
  );
  if (!txn) throw new Error(`pending txn ${authReqId} not found for device`);
  return txn;
}

/** Sign + submit a decision for a pending txn fetched from the device list. */
export async function decide(
  h: Harness,
  device: TestDevice,
  authReqId: string,
  decision: 'approve' | 'deny',
  opts: { reportSuspicious?: boolean } = {},
): Promise<request.Response> {
  const txn = await fetchPendingTxn(h, device, authReqId);
  const payload = decision === 'approve' ? txn.challenge.approvePayload : txn.challenge.denyPayload;
  const signature = await device.sign(payload);
  return request(h.http())
    .post('/v1/device/ciba/decision')
    .set('Authorization', `Bearer ${device.sessionToken}`)
    .send({
      authReqId,
      bindingId: device.bindingId,
      challengeId: txn.challenge.challengeId,
      decision,
      signature,
      ...(opts.reportSuspicious ? { reportSuspicious: true } : {}),
    });
}
