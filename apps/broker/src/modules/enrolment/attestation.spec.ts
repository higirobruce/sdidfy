import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { and, desc, eq } from 'drizzle-orm';
import { MOCK_TEST_NIDS } from '@sdid/shared';
import type {
  AttestationRequest,
  AttestationResult,
  AttestationVerifier,
  AttestationVerifiers,
} from '@sdid/attestation';
import { auditEvents, deviceBindings } from '../../db/schema.js';
import { resetConfigForTest } from '../../config.js';
import { ChallengeService } from '../../trust/challenge.service.js';
import type { AttestationVerifierSource } from '../../trust/attestation-verifiers.provider.js';
import {
  cleanTestData,
  clearEnrolRateLimit,
  createTestApp,
  mintAttestationNonce,
  pseudoNidOf,
  SimDevice,
  type TestContext,
} from './testkit.js';

/**
 * Server-issued attestation nonces + strict-mode attestation (03 §2 step 1,
 * 06 T4, decision #4). Real Postgres + Redis; the platform verifiers are
 * stubbed at the DI seam (ATTESTATION_VERIFIERS) — never by patching
 * @sdid/attestation internals — so these tests pin the BROKER's behaviour:
 * nonce lifecycle, key binding, verdict mapping, and the uniform client-facing
 * failure that keeps a precise reason out of an attacker's hands (03 §7).
 */

const ACCEPTED_EVIDENCE = {
  appRecognitionVerdict: 'PLAY_RECOGNIZED',
  keySecurityLevel: 'strongbox',
  appVersion: '1.2.3',
};

const ACCEPTED: AttestationResult = {
  ok: true,
  platform: 'android',
  appGenuine: true,
  keySecurityLevel: 'strongbox',
  assuranceCap: 'AL2',
  evidence: ACCEPTED_EVIDENCE,
};

/** Verifier stub: records what it was asked, answers what the test set. */
class StubVerifier implements AttestationVerifier {
  calls: AttestationRequest[] = [];
  result: AttestationResult = ACCEPTED;
  throws?: Error;

  constructor(readonly platform: 'android' | 'ios') {}

  async verify(request: AttestationRequest): Promise<AttestationResult> {
    this.calls.push(request);
    if (this.throws) throw this.throws;
    return this.result;
  }
}

const android = new StubVerifier('android');
const ios = new StubVerifier('ios');
const verifiers: AttestationVerifierSource = {
  get: (): AttestationVerifiers => ({ android, ios }),
};

function setMode(mode: 'mock' | 'strict'): void {
  process.env['ATTESTATION_MODE'] = mode;
  resetConfigForTest();
}

describe('attestation nonces + strict mode (03 §2, T4)', () => {
  let ctx: TestContext;
  const originalMode = process.env['ATTESTATION_MODE'];

  beforeAll(async () => {
    ctx = await createTestApp({ attestationVerifiers: verifiers });
    await cleanTestData(ctx);
  });

  afterEach(() => {
    setMode('mock');
    android.calls = [];
    ios.calls = [];
    android.result = ACCEPTED;
    ios.result = ACCEPTED;
    delete android.throws;
    delete ios.throws;
  });

  afterAll(async () => {
    if (originalMode === undefined) delete process.env['ATTESTATION_MODE'];
    else process.env['ATTESTATION_MODE'] = originalMode;
    resetConfigForTest();
    await ctx.app.close();
  });

  // --- nonce issuance ----------------------------------------------------

  it('mints a high-entropy nonce and consumes it exactly once (single-use)', async () => {
    const minted = await mintAttestationNonce(ctx);
    expect(minted.nonceId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(minted.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    // >= 32 bytes of randomness, base64url-encoded.
    expect(Buffer.from(minted.nonce, 'base64url').length).toBeGreaterThanOrEqual(32);
    expect(new Date(minted.expiresAt).getTime()).toBeGreaterThan(Date.now());

    const challenges = ctx.app.get(ChallengeService);
    await expect(challenges.consumeAttestationNonce(minted.nonceId)).resolves.toBe(minted.nonce);
    // Second consumption of the SAME id finds nothing — GETDEL is atomic, so
    // this holds under concurrency too.
    await expect(challenges.consumeAttestationNonce(minted.nonceId)).rejects.toMatchObject({
      code: 'challenge_invalid',
    });
  });

  it('two mints never collide and an unknown nonceId is not consumable', async () => {
    const a = await mintAttestationNonce(ctx);
    const b = await mintAttestationNonce(ctx);
    expect(a.nonceId).not.toBe(b.nonceId);
    expect(a.nonce).not.toBe(b.nonce);

    const challenges = ctx.app.get(ChallengeService);
    await expect(challenges.consumeAttestationNonce('not-a-real-nonce-id')).rejects.toMatchObject({
      code: 'challenge_invalid',
    });
  });

  // --- strict mode: happy path -------------------------------------------

  it('strict: accepted verdict enrols, binds the enrolled key, and persists evidence', async () => {
    const nid = MOCK_TEST_NIDS[0];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');

    const body = device.enrolStartBody(nid, 'Strict Pixel', undefined, {
      platform: 'android',
      nonceId: nonce.nonceId,
      nonce: nonce.nonce,
    });
    const res = await ctx.http().post('/v1/enrol/start').send(body).expect(200);
    expect(res.body.assuranceLevel).toBe('AL2');

    // The verifier was asked about THE NONCE WE ISSUED and THE KEY BEING
    // ENROLLED — the two bindings that make the verdict mean anything.
    expect(android.calls).toHaveLength(1);
    expect(android.calls[0]!.expectedNonce).toBe(nonce.nonce);
    expect(android.calls[0]!.devicePublicKeyJwk).toEqual(device.publicKeyJwk);
    expect(typeof android.calls[0]!.now).toBe('number');
    expect(ios.calls).toHaveLength(0);

    const [row] = await ctx.db.db
      .select({ attestation: deviceBindings.attestation })
      .from(deviceBindings)
      .where(eq(deviceBindings.id, res.body.bindingId));
    const attestation = row!.attestation as Record<string, unknown>;
    expect(attestation['platform']).toBe('android');
    expect(attestation['hardwareBacked']).toBe(true);
    expect(attestation['assuranceCap']).toBe('AL2');
    expect(attestation['evidence']).toEqual(ACCEPTED_EVIDENCE);
    // No raw token / certificate ever lands in the DB.
    expect(JSON.stringify(attestation)).not.toContain(body.attestation.token);
  });

  // --- strict mode: nonce enforcement ------------------------------------

  it('strict: a missing nonceId is a clean, uniform rejection (not a zod error)', async () => {
    const nid = MOCK_TEST_NIDS[1];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    setMode('strict');

    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(nid, 'No-nonce phone', undefined, { platform: 'android' }))
      .expect(403);
    expect(res.body.error).toBe('attestation_rejected');
    expect(res.body.error_description).toBe('Device attestation could not be verified');
    // Refused before the platform verifier was ever consulted.
    expect(android.calls).toHaveLength(0);

    const [audited] = await ctx.db.db
      .select({ context: auditEvents.context })
      .from(auditEvents)
      .where(and(eq(auditEvents.subjectRef, pseudoNidOf(nid)), eq(auditEvents.action, 'enrolment.failed')))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    expect(audited!.context).toMatchObject({ reason: 'attestation_rejected', code: 'nonce_mismatch' });
  });

  it('strict: replaying a consumed nonceId is rejected (T4)', async () => {
    const nid = MOCK_TEST_NIDS[2];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');

    const body = device.enrolStartBody(nid, 'Replay phone', undefined, {
      platform: 'android',
      nonceId: nonce.nonceId,
      nonce: nonce.nonce,
    });
    await ctx.http().post('/v1/enrol/start').send(body).expect(200);

    // Same nonceId, same token — a captured attestation replayed from another
    // device. The nonce is gone, so the verifier is never even called.
    await clearEnrolRateLimit(ctx, nid);
    const attacker = await SimDevice.create();
    const replay = await ctx.http()
      .post('/v1/enrol/start')
      .send({ ...body, devicePublicKeyJwk: attacker.publicKeyJwk, deviceLabel: 'Attacker phone' })
      .expect(403);
    expect(replay.body.error).toBe('attestation_rejected');
    expect(android.calls).toHaveLength(1); // only the genuine first attempt
  });

  // --- strict mode: verdict mapping --------------------------------------

  it('strict: a verifier rejection stays generic to the client but precise in the audit trail (03 §7)', async () => {
    const nid = MOCK_TEST_NIDS[3];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');
    android.result = { ok: false, code: 'device_integrity', detail: 'MEETS_DEVICE_INTEGRITY absent; device is rooted' };

    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Rooted phone', undefined, {
          platform: 'android',
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(403);
    // Uniform body: identical to the missing-nonce refusal above. Nothing here
    // tells an attacker WHICH control refused them.
    expect(res.body).toEqual({
      error: 'attestation_rejected',
      error_description: 'Device attestation could not be verified',
    });
    expect(JSON.stringify(res.body)).not.toContain('rooted');

    const [audited] = await ctx.db.db
      .select({ context: auditEvents.context })
      .from(auditEvents)
      .where(and(eq(auditEvents.subjectRef, pseudoNidOf(nid)), eq(auditEvents.action, 'enrolment.failed')))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    expect(audited!.context).toMatchObject({
      reason: 'attestation_rejected',
      code: 'device_integrity',
      detail: 'MEETS_DEVICE_INTEGRITY absent; device is rooted',
    });
  });

  it('strict: verifier_unavailable is a retryable 503, never a 403 refusal and never an acceptance', async () => {
    const nid = MOCK_TEST_NIDS[4];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');
    android.result = { ok: false, code: 'verifier_unavailable', detail: 'Play Integrity decode timed out' };

    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Outage phone', undefined, {
          platform: 'android',
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(503);
    expect(res.body.error).toBe('attestation_unavailable');

    // Nothing was bound: unavailability is not acceptance.
    const bound = await ctx.db.db
      .select({ id: deviceBindings.id })
      .from(deviceBindings)
      .where(eq(deviceBindings.deviceLabel, 'Outage phone'));
    expect(bound).toHaveLength(0);
  });

  it('strict: a THROWING verifier fails closed as 503, not as an acceptance', async () => {
    const nid = MOCK_TEST_NIDS[0];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');
    // What the unimplemented Play Integrity decode seam does today.
    android.throws = new Error('Play Integrity decode is not implemented');

    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Throwing phone', undefined, {
          platform: 'android',
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(503);
    expect(res.body.error).toBe('attestation_unavailable');
  });

  it("strict: the sim platform is not our app — refused, and the nonce is not spent on it", async () => {
    const nid = MOCK_TEST_NIDS[1];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);
    setMode('strict');

    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Sim phone in strict', undefined, {
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(403);
    expect(res.body.error).toBe('attestation_rejected');
    expect(android.calls).toHaveLength(0);
    expect(ios.calls).toHaveLength(0);
    // Platform is checked before the nonce is burned, so a mis-routed request
    // does not cost the client its nonce.
    const challenges = ctx.app.get(ChallengeService);
    await expect(challenges.consumeAttestationNonce(nonce.nonceId)).resolves.toBe(nonce.nonce);
  });

  // --- mock mode is untouched --------------------------------------------

  it('mock: enrols with no nonceId at all, exactly as before (Phase 0–2 path)', async () => {
    const nid = MOCK_TEST_NIDS[2];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(nid, 'Mock phone'))
      .expect(200);
    expect(res.body.assuranceLevel).toBe('AL2');
    expect(android.calls).toHaveLength(0);
    expect(ios.calls).toHaveLength(0);
  });

  it('mock: a supplied nonce is burned but never required, and a stale one is harmless', async () => {
    const nid = MOCK_TEST_NIDS[3];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const nonce = await mintAttestationNonce(ctx);

    await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Mock nonce phone', undefined, {
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(200);

    // The nonce was consumed by that enrolment...
    const challenges = ctx.app.get(ChallengeService);
    await expect(challenges.consumeAttestationNonce(nonce.nonceId)).rejects.toMatchObject({
      code: 'challenge_invalid',
    });
    // ...and reusing the dead id in mock mode still enrols: mock never
    // enforces the nonce, so the demo/e2e path cannot be broken by it.
    await clearEnrolRateLimit(ctx, nid);
    await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(nid, 'Mock stale nonce phone', undefined, {
          nonceId: nonce.nonceId,
          nonce: nonce.nonce,
        }),
      )
      .expect(200);
  });

  it('mock: a rooted device is still refused with its original message', async () => {
    const nid = MOCK_TEST_NIDS[4];
    await clearEnrolRateLimit(ctx, nid);
    const device = await SimDevice.create();
    const body = device.enrolStartBody(nid, 'Rooted mock phone');
    body.attestation.token = Buffer.from(
      JSON.stringify({ mock: true, deviceIntegrity: false, appIntegrity: true, hardwareBackedKey: true }),
      'utf8',
    ).toString('base64url');

    const res = await ctx.http().post('/v1/enrol/start').send(body).expect(403);
    expect(res.body.error).toBe('attestation_rejected');
    expect(res.body.error_description).toBe('Device failed integrity checks');
  });
});
