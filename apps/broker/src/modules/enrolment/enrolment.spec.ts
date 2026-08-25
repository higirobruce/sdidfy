import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS } from '@sdid/shared';
import {
  cleanTestData,
  clearEnrolRateLimit,
  createTestApp,
  enrolAndActivate,
  login,
  SDID_UNAVAILABLE_NID,
  SimDevice,
  type TestContext,
} from './testkit.js';

const UNKNOWN_NID = '9999888877776666'; // 16 digits, not seeded in mock SDID

describe('enrolment + device binding (spec 03, integration)', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestApp();
    await cleanTestData(ctx, [UNKNOWN_NID]);
  });

  afterAll(async () => {
    await ctx.app.close();
  });

  it('happy path: enrol → activate → login → list bindings', async () => {
    const nid = MOCK_TEST_NIDS[0];
    const device = await SimDevice.create();

    const startRes = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(nid, 'Pixel 9'))
      .expect(200);
    expect(startRes.body.bindingId).toMatch(/^[0-9a-f-]{36}$/);
    expect(startRes.body.assuranceLevel).toBe('AL2'); // hardware-backed + key attestation
    const { bindingId, activationChallenge } = startRes.body;
    expect(activationChallenge.payload).toContain('activation');
    expect(activationChallenge.payload).toContain(activationChallenge.challengeId);

    const signature = await device.sign(activationChallenge.payload);
    const activateRes = await ctx.http()
      .post('/v1/enrol/activate')
      .send({ bindingId, challengeId: activationChallenge.challengeId, signature })
      .expect(200);
    expect(activateRes.body).toEqual({ bindingId, status: 'active' });

    const sessionToken = await login(ctx, device, bindingId);
    expect(sessionToken.split('.')).toHaveLength(3);

    const listRes = await ctx.http()
      .get('/v1/device/bindings')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    const mine = listRes.body.devices.filter((d: { bindingId: string }) => d.bindingId === bindingId);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({
      deviceLabel: 'Pixel 9',
      assuranceLevel: 'AL2',
      status: 'active',
    });
    expect(mine[0].lastUsedAt).not.toBeNull();
  });

  it('impostor sample (bytes of another NID) → generic enrolment_failed', async () => {
    const device = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        device.enrolStartBody(MOCK_TEST_NIDS[1], 'Impostor phone', {
          sampleFromNid: MOCK_TEST_NIDS[0],
        }),
      )
      .expect(403);
    expect(res.body.error).toBe('enrolment_failed');
  });

  it('unknown NID → the SAME generic error body (anti-probing, 03 §7)', async () => {
    const deviceA = await SimDevice.create();
    const impostorRes = await ctx.http()
      .post('/v1/enrol/start')
      .send(
        deviceA.enrolStartBody(MOCK_TEST_NIDS[1], 'Impostor phone', {
          sampleFromNid: MOCK_TEST_NIDS[0],
        }),
      )
      .expect(403);

    const deviceB = await SimDevice.create();
    const unknownRes = await ctx.http()
      .post('/v1/enrol/start')
      .send(deviceB.enrolStartBody(UNKNOWN_NID, 'Probing phone'))
      .expect(403);

    // Indistinguishable: identical status and identical body.
    expect(unknownRes.body).toEqual(impostorRes.body);
    expect(unknownRes.body.error).toBe('enrolment_failed');
  });

  it('SDID unavailable subtype (timeout) → 503 sdid_unavailable, not 500 (02 §4)', async () => {
    // A timeout / open-breaker / malformed-response error is a SUBTYPE of
    // SdidUnavailableError with its own `.name`; the broker must still map it
    // to 503 sdid_unavailable so clients can key retry/backoff on it, rather
    // than a generic 500 internal_error.
    const device = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(SDID_UNAVAILABLE_NID, 'Timeout phone'))
      .expect(503);
    expect(res.body.error).toBe('sdid_unavailable');
  });

  it('PAD failure (liveness score 0.3) → enrolment_failed', async () => {
    const device = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(MOCK_TEST_NIDS[2], 'Spoof phone', { score: 0.3 }))
      .expect(403);
    expect(res.body.error).toBe('enrolment_failed');
  });

  it('fingerprint modality is rejected in v1 (appendix D1)', async () => {
    const device = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(MOCK_TEST_NIDS[2], 'Reader phone', { modality: 'fingerprint' }))
      .expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('activation challenge is single-use: a consumed challenge replays as challenge_invalid (T4)', async () => {
    const nid = MOCK_TEST_NIDS[3];
    const device = await SimDevice.create();
    const startRes = await ctx.http()
      .post('/v1/enrol/start')
      .send(device.enrolStartBody(nid, 'Replay phone'))
      .expect(200);
    const { bindingId, activationChallenge } = startRes.body;

    // First attempt consumes the challenge but fails signature verification.
    const badSig = await device.sign('sdid-bridge:v1:activation:tampered:payload');
    const firstRes = await ctx.http()
      .post('/v1/enrol/activate')
      .send({ bindingId, challengeId: activationChallenge.challengeId, signature: badSig })
      .expect(401);
    expect(firstRes.body.error).toBe('signature_invalid');

    // Replay with the CORRECT signature: the nonce is gone — rejected.
    const goodSig = await device.sign(activationChallenge.payload);
    const replayRes = await ctx.http()
      .post('/v1/enrol/activate')
      .send({ bindingId, challengeId: activationChallenge.challengeId, signature: goodSig })
      .expect(400);
    expect(replayRes.body.error).toBe('challenge_invalid');
  });

  it('multi-device cap: the 6th non-revoked binding is refused (decision #3)', async () => {
    const nid = MOCK_TEST_NIDS[4];
    for (let i = 0; i < 5; i++) {
      // Reset the per-NID fixed window (5/h) so the cap — not the rate
      // limit — is what this test exercises.
      await clearEnrolRateLimit(ctx, nid);
      const device = await SimDevice.create();
      await enrolAndActivate(ctx, device, nid, `Device ${i + 1}`);
    }
    await clearEnrolRateLimit(ctx, nid);
    const sixth = await SimDevice.create();
    const res = await ctx.http()
      .post('/v1/enrol/start')
      .send(sixth.enrolStartBody(nid, 'Device 6'))
      .expect(409);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.error_description).toBe('Device limit reached');
  });
});
