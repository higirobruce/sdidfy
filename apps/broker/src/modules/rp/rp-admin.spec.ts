import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_TOKEN,
  createCitizenWithBinding,
  createHarness,
  destroyHarness,
  provisionSubject,
  registerRp,
  type Harness,
} from '../oidc/testkit.js';

describe('RP onboarding admin API (04 §6)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });

  afterAll(async () => {
    await destroyHarness(h);
  });

  it('gates every admin route behind the admin token', async () => {
    const calls: Array<[method: 'get' | 'post', path: string]> = [
      ['post', '/admin/rps'],
      ['get', '/admin/rps'],
      ['post', '/admin/rps/some-id/suspend'],
      ['post', '/admin/rps/some-id/pairwise'],
      ['get', '/admin/audit/verify'],
    ];
    for (const [method, path] of calls) {
      const res = await request(h.http())[method](path).set('Authorization', 'Bearer wrong-token');
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('access_denied');
    }
    const missing = await request(h.http()).get('/admin/rps');
    expect(missing.status).toBe(401);
  });

  it('registers an RP, returning the secret exactly once, and lists without secrets', async () => {
    const res = await request(h.http())
      .post('/admin/rps')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({
        name: 'Pilot RP',
        logoUri: 'https://pilot.example.test/logo.png',
        allowedScopes: ['openid', 'profile'],
        maxAssurance: 'AL2',
        allowedFlows: ['ciba'],
      })
      .expect(201);
    h.rpIds.push(res.body.rpId);
    expect(res.body.clientId).toMatch(/^rp_[0-9a-f]{12}$/);
    expect(res.body.clientSecret).toMatch(/^[A-Za-z0-9\-_]{43}$/); // 32 bytes base64url
    expect(res.body.rpId).toMatch(/^[0-9a-f-]{36}$/);

    const list = await request(h.http())
      .get('/admin/rps')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    const mine = list.body.rps.find((r: { rpId: string }) => r.rpId === res.body.rpId);
    expect(mine).toBeTruthy();
    expect(mine.name).toBe('Pilot RP');
    expect(mine.logoUri).toBe('https://pilot.example.test/logo.png');
    expect(mine.status).toBe('active');
    // No secret material in the listing.
    const listed = JSON.stringify(list.body);
    expect(listed).not.toContain(res.body.clientSecret);
    expect(listed).not.toContain('clientSecretHash');
    expect(listed).not.toContain('pairwiseSalt');
  });

  it('rejects invalid registrations', async () => {
    const res = await request(h.http())
      .post('/admin/rps')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: '', allowedScopes: [], allowedFlows: [] })
      .expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('suspends an RP and 404s unknown ones', async () => {
    const rp = await registerRp(h);
    await request(h.http())
      .post(`/admin/rps/${rp.rpId}/suspend`)
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    const list = await request(h.http())
      .get('/admin/rps')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    const mine = list.body.rps.find((r: { rpId: string }) => r.rpId === rp.rpId);
    expect(mine.status).toBe('suspended');

    const unknown = await request(h.http())
      .post('/admin/rps/00000000-0000-7000-8000-000000000000/suspend')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(unknown.status).toBe(404);
  });

  it('provisions a pairwise login_hint for a known citizen, 404s unknown pseudo-NIDs', async () => {
    const rp = await registerRp(h);
    const device = await createCitizenWithBinding(h);
    const subject = await provisionSubject(h, rp.rpId, device.pseudoNid);
    expect(subject.length).toBeGreaterThan(20);
    // Deterministic per (citizen, rp).
    const again = await provisionSubject(h, rp.rpId, device.pseudoNid);
    expect(again).toBe(subject);

    const unknown = await request(h.http())
      .post(`/admin/rps/${rp.rpId}/pairwise`)
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ pseudoNid: 'does-not-exist' });
    expect(unknown.status).toBe(404);
    expect(unknown.body.error).toBe('invalid_request');
  });

  it('verifies the audit hash chain', async () => {
    const res = await request(h.http())
      .get('/admin/audit/verify')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    expect(res.body.intact).toBe(true);
    expect(res.body.brokenAtSeq).toBeNull();
    expect(res.body.count).toBeGreaterThan(0);
  });
});
