import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_TOKEN,
  createCitizenWithBinding,
  createHarness,
  decide,
  destroyHarness,
  provisionSubject,
  registerRp,
  type Harness,
  type TestDevice,
  type TestRp,
} from '../modules/oidc/testkit.js';

/**
 * Re-verification cadence (spec 03 §6, decision #9). Routine auth only proves a
 * device signature; a binding past the SDID re-verify cadence must be
 * re-asserted at its next use — at every assurance level, not just AL3 — because
 * that is our ONLY signal for a revoked/deceased identity behind an existing
 * device. A fresh binding never pays the SDID round-trip.
 */
describe('re-verification cadence (03 §6, decision #9)', () => {
  let h: Harness;
  let rp: TestRp;

  beforeAll(async () => {
    h = await createHarness();
    rp = await registerRp(h, { name: 'Reverify Test RP' });
  });

  afterAll(async () => {
    await destroyHarness(h);
  });

  /** Backdate a binding well past the 90-day default cadence. */
  async function makeStale(bindingId: string): Promise<void> {
    await h.db.pool.query(
      `UPDATE device_bindings
         SET enrolled_at = now() - interval '200 days',
             activated_at = now() - interval '200 days',
             last_reasserted_at = NULL
       WHERE id = $1`,
      [bindingId],
    );
  }

  async function directLogin(device: TestDevice): Promise<request.Response> {
    const ch = await request(h.http())
      .post('/v1/device/login/challenge')
      .send({ bindingId: device.bindingId });
    if (ch.status !== 200) return ch;
    const signature = await device.sign(ch.body.payload);
    return request(h.http())
      .post('/v1/device/login')
      .send({ bindingId: device.bindingId, challengeId: ch.body.challengeId, signature });
  }

  async function lastReasserted(bindingId: string): Promise<Date | null> {
    const { rows } = await h.db.pool.query(
      `SELECT last_reasserted_at FROM device_bindings WHERE id = $1`,
      [bindingId],
    );
    return rows[0]?.last_reasserted_at ?? null;
  }

  async function citizenStatus(citizenId: string): Promise<string> {
    const { rows } = await h.db.pool.query(`SELECT status FROM citizens WHERE id = $1`, [citizenId]);
    return rows[0]?.status as string;
  }

  it('a fresh binding logs in WITHOUT an SDID round-trip', async () => {
    // Even with SDID poised to reject, a within-cadence binding never calls it.
    h.sdidState.reassertValid = false;
    const device = await createCitizenWithBinding(h, 'AL2');
    const res = await directLogin(device);
    expect(res.status).toBe(200);
    expect(res.body.sessionToken).toBeTruthy();
    // No re-assertion happened, so the anchor stays untouched.
    expect(await lastReasserted(device.bindingId)).toBeNull();
    h.sdidState.reassertValid = true;
  });

  it('a stale binding is re-asserted at direct login and the cadence anchor refreshes', async () => {
    h.sdidState.reassertValid = true;
    const device = await createCitizenWithBinding(h, 'AL2');
    await makeStale(device.bindingId);

    const res = await directLogin(device);
    expect(res.status).toBe(200);
    // The valid re-assertion refreshed lastReassertedAt (no longer null/stale).
    const anchor = await lastReasserted(device.bindingId);
    expect(anchor).not.toBeNull();
    expect(Date.now() - new Date(anchor as Date).getTime()).toBeLessThan(60_000);

    // Audited as a system re-assertion triggered by the direct login.
    const { rows } = await h.db.pool.query(
      `SELECT result, context FROM audit_events
       WHERE action = 'sdid.reassert' AND subject_ref = $1
       ORDER BY seq DESC LIMIT 1`,
      [device.citizenId],
    );
    expect(rows[0].result).toBe('success');
    expect(rows[0].context.trigger).toBe('direct-login');
  });

  it('a stale binding whose identity SDID rejects: login is denied, citizen suspended, bindings revoked', async () => {
    const device = await createCitizenWithBinding(h, 'AL2');
    await makeStale(device.bindingId);

    h.sdidState.reassertValid = false;
    try {
      const res = await directLogin(device);
      expect(res.status).toBe(403);
      expect(res.body.error).toBe('access_denied');
    } finally {
      h.sdidState.reassertValid = true;
    }

    expect(await citizenStatus(device.citizenId)).toBe('suspended');
    const { rows } = await h.db.pool.query(
      `SELECT status, revoke_reason FROM device_bindings WHERE id = $1`,
      [device.bindingId],
    );
    expect(rows[0].status).toBe('revoked');
    expect(rows[0].revoke_reason).toBe('sdid-reassert-invalid');
  });

  it('the cadence applies to a non-AL3 CIBA approval too (not just AL3 step-up)', async () => {
    const device = await createCitizenWithBinding(h, 'AL2');
    const hint = await provisionSubject(h, rp.rpId, device.pseudoNid);
    await makeStale(device.bindingId);

    const initiated = await request(h.http())
      .post('/oidc/bc-authorize')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ scope: 'openid', login_hint: hint, requested_al: 'AL2' })
      .expect(200);

    h.sdidState.reassertValid = false;
    try {
      const decided = await decide(h, device, initiated.body.auth_req_id, 'approve');
      expect(decided.status).toBe(403);
      expect(decided.body.error).toBe('access_denied');
    } finally {
      h.sdidState.reassertValid = true;
    }
    expect(await citizenStatus(device.citizenId)).toBe('suspended');
  });

  it('a CIBA denial on a stale binding needs no SDID round-trip', async () => {
    // A denial mints nothing, so it must not risk an SDID call (or suspension).
    const device = await createCitizenWithBinding(h, 'AL2');
    const hint = await provisionSubject(h, rp.rpId, device.pseudoNid);
    await makeStale(device.bindingId);

    const initiated = await request(h.http())
      .post('/oidc/bc-authorize')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ scope: 'openid', login_hint: hint, requested_al: 'AL2' })
      .expect(200);

    h.sdidState.reassertValid = false;
    try {
      const decided = await decide(h, device, initiated.body.auth_req_id, 'deny');
      expect(decided.status).toBe(200);
      expect(decided.body.status).toBe('denied');
    } finally {
      h.sdidState.reassertValid = true;
    }
    // The citizen is untouched — no re-assertion was attempted.
    expect(await citizenStatus(device.citizenId)).toBe('active');
  });

  it('admin sweep re-asserts stale bindings and leaves fresh ones alone', async () => {
    h.sdidState.reassertValid = true;
    const stale1 = await createCitizenWithBinding(h, 'AL2');
    const stale2 = await createCitizenWithBinding(h, 'AL2');
    const fresh = await createCitizenWithBinding(h, 'AL2');
    await makeStale(stale1.bindingId);
    await makeStale(stale2.bindingId);

    const res = await request(h.http())
      .post('/admin/reverify/sweep')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({})
      .expect(200);
    expect(res.body.due).toBeGreaterThanOrEqual(2);
    expect(res.body.reasserted).toBeGreaterThanOrEqual(2);
    expect(res.body.revoked).toBe(0);

    expect(await lastReasserted(stale1.bindingId)).not.toBeNull();
    expect(await lastReasserted(stale2.bindingId)).not.toBeNull();
    expect(await lastReasserted(fresh.bindingId)).toBeNull();
  });

  it('admin sweep revokes an identity SDID rejects and tallies it', async () => {
    const doomed = await createCitizenWithBinding(h, 'AL2');
    await makeStale(doomed.bindingId);

    h.sdidState.reassertValid = false;
    let res: request.Response;
    try {
      res = await request(h.http())
        .post('/admin/reverify/sweep')
        .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
        .send({ limit: 50 })
        .expect(200);
    } finally {
      h.sdidState.reassertValid = true;
    }
    expect(res.body.revoked).toBeGreaterThanOrEqual(1);
    expect(await citizenStatus(doomed.citizenId)).toBe('suspended');
    const { rows } = await h.db.pool.query(
      `SELECT status FROM device_bindings WHERE id = $1`,
      [doomed.bindingId],
    );
    expect(rows[0].status).toBe('revoked');
  });

  it('rejects an unauthenticated sweep', async () => {
    await request(h.http())
      .post('/admin/reverify/sweep')
      .send({})
      .expect(401);
  });
});
