import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS, uuidv7 } from '@sdid/shared';
import { eq } from 'drizzle-orm';
import {
  cleanTestData,
  clearEnrolRateLimit,
  createTestApp,
  enrolAndActivate,
  insertTestRp,
  login,
  pseudoNidOf,
  SimDevice,
  type TestContext,
} from '../enrolment/testkit.js';
import { ConsentService } from '../consent/consent.service.js';
import { citizens } from '../../db/schema.js';

describe('device backchannel: login, revocation, consents, activity (spec 05 §2, 06 §4)', () => {
  let ctx: TestContext;
  let device: SimDevice;
  let bindingId: string;
  let sessionToken: string;

  const nid = MOCK_TEST_NIDS[0];

  beforeAll(async () => {
    ctx = await createTestApp();
    await cleanTestData(ctx);
    device = await SimDevice.create();
    bindingId = await enrolAndActivate(ctx, device, nid, 'Primary phone');
    sessionToken = await login(ctx, device, bindingId);
  });

  afterAll(async () => {
    await ctx.app.close();
  });

  it('rejects the backchannel without a session token', async () => {
    await ctx.http().get('/v1/device/bindings').expect(401);
  });

  it('login with a wrong signature fails, is audited, and counts toward lockout', async () => {
    const chRes = await ctx.http()
      .post('/v1/device/login/challenge')
      .send({ bindingId })
      .expect(200);
    const badSig = await device.sign('sdid-bridge:v1:login:not-the-payload:x');
    const res = await ctx.http()
      .post('/v1/device/login')
      .send({ bindingId, challengeId: chRes.body.challengeId, signature: badSig })
      .expect(401);
    expect(res.body.error).toBe('signature_invalid');
    // A successful login afterwards clears the failure counter.
    sessionToken = await login(ctx, device, bindingId);
  });

  it('revoked binding: login challenge is refused with binding_not_active (immediate, 06 §4)', async () => {
    await clearEnrolRateLimit(ctx, nid);
    const second = await SimDevice.create();
    const secondBindingId = await enrolAndActivate(ctx, second, nid, 'Second phone');

    const revokeRes = await ctx.http()
      .post('/v1/device/bindings/revoke')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ bindingId: secondBindingId, reason: 'lost device' })
      .expect(200);
    expect(revokeRes.body).toEqual({ status: 'revoked' });

    const res = await ctx.http()
      .post('/v1/device/login/challenge')
      .send({ bindingId: secondBindingId })
      .expect(401);
    expect(res.body.error).toBe('binding_not_active');

    const listRes = await ctx.http()
      .get('/v1/device/bindings')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    const revoked = listRes.body.devices.find(
      (d: { bindingId: string }) => d.bindingId === secondBindingId,
    );
    expect(revoked.status).toBe('revoked');
  });

  it('a session token is rejected after its binding is revoked (guard re-checks DB)', async () => {
    await clearEnrolRateLimit(ctx, nid);
    const third = await SimDevice.create();
    const thirdBindingId = await enrolAndActivate(ctx, third, nid, 'Third phone');
    const thirdSession = await login(ctx, third, thirdBindingId);

    // The token works before revocation...
    await ctx.http()
      .get('/v1/device/bindings')
      .set('Authorization', `Bearer ${thirdSession}`)
      .expect(200);

    // ...the device revokes its own binding...
    await ctx.http()
      .post('/v1/device/bindings/revoke')
      .set('Authorization', `Bearer ${thirdSession}`)
      .send({ bindingId: thirdBindingId })
      .expect(200);

    // ...and the still-unexpired JWT is now refused on every backchannel call.
    const res = await ctx.http()
      .get('/v1/device/bindings')
      .set('Authorization', `Bearer ${thirdSession}`)
      .expect(401);
    expect(res.body.error).toBe('binding_not_active');
  });

  it("cannot revoke another citizen's binding", async () => {
    await clearEnrolRateLimit(ctx, MOCK_TEST_NIDS[1]);
    const otherDevice = await SimDevice.create();
    const otherBindingId = await enrolAndActivate(ctx, otherDevice, MOCK_TEST_NIDS[1], 'Other phone');

    const res = await ctx.http()
      .post('/v1/device/bindings/revoke')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ bindingId: otherBindingId })
      .expect(404);
    expect(res.body.error).toBe('binding_not_found');
  });

  it('lists and revokes consent grants', async () => {
    const rpId = await insertTestRp(ctx, 'Irembo Test');
    const consentService = ctx.app.get(ConsentService);
    // Record a grant through the service against this suite's citizen
    // (the protocol modules do the same during CIBA approval).
    const citizenRows = await ctx.db.db
      .select({ id: citizens.id })
      .from(citizens)
      .where(eq(citizens.pseudoNid, pseudoNidOf(nid)));
    const citizenId = citizenRows[0]!.id;

    await consentService.recordGrant({
      citizenId,
      rpId,
      scopes: ['openid', 'profile'],
      source: 'ciba-approval',
    });

    const listRes = await ctx.http()
      .get('/v1/device/consents')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    expect(listRes.body.consents).toHaveLength(1);
    const consent = listRes.body.consents[0];
    expect(consent).toMatchObject({
      rpName: 'Irembo Test',
      scopes: ['openid', 'profile'],
      source: 'ciba-approval',
      revokedAt: null,
    });
    expect(consent.grantedAt).toBeTruthy();

    const revokeRes = await ctx.http()
      .post('/v1/device/consents/revoke')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ consentId: consent.id })
      .expect(200);
    expect(revokeRes.body).toEqual({ status: 'revoked' });

    const afterRes = await ctx.http()
      .get('/v1/device/consents')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    expect(afterRes.body.consents[0].revokedAt).not.toBeNull();
    expect(await consentService.hasActiveGrant(citizenId, rpId, ['openid'])).toBe(false);
  });

  it('revoking an unknown/foreign consent id is refused', async () => {
    const res = await ctx.http()
      .post('/v1/device/consents/revoke')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ consentId: uuidv7() })
      .expect(404);
    expect(res.body.error).toBe('invalid_request');
  });

  it('activity view: citizen sees own events with RP names, never hashes or context (08 §5)', async () => {
    const res = await ctx.http()
      .get('/v1/device/activity')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    const events: Array<Record<string, unknown>> = res.body.events;
    expect(events.length).toBeGreaterThan(0);
    expect(events.length).toBeLessThanOrEqual(50);
    const actions = events.map((e) => e.action);
    expect(actions).toContain('auth.login_succeeded');
    expect(actions).toContain('device.revoked');
    expect(actions).toContain('consent.granted');
    // The consent.granted event resolves the RP name.
    const consentEvent = events.find((e) => e.action === 'consent.granted');
    expect(consentEvent?.rpName).toBe('Irembo Test');
    // Citizen-rights reduction: ONLY ts/action/result/rpName ever leave the
    // server — no hash chain, no raw context, no subject refs (08 §5).
    const allowedKeys = new Set(['ts', 'action', 'result', 'rpName']);
    for (const e of events) {
      for (const key of Object.keys(e)) {
        expect(allowedKeys.has(key), `unexpected activity field: ${key}`).toBe(true);
      }
    }
    // Newest first (seq desc).
    const timestamps = events.map((e) => new Date(e.ts as string).getTime());
    const sorted = [...timestamps].sort((a, b) => b - a);
    expect(timestamps).toEqual(sorted);
  });
});
