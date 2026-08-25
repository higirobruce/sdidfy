import { CIBA_GRANT_TYPE, uuidv7 } from '@sdid/shared';
import * as jose from 'jose';
import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authTransactions } from '../../db/schema.js';
import {
  createCitizenWithBinding,
  createHarness,
  decide,
  destroyHarness,
  fetchPendingTxn,
  provisionSubject,
  registerRp,
  type Harness,
  type TestDevice,
  type TestRp,
} from '../oidc/testkit.js';

describe('CIBA decoupled flow (04 §3)', () => {
  let h: Harness;
  let rp: TestRp;
  let device: TestDevice;
  let loginHint: string;

  beforeAll(async () => {
    h = await createHarness();
    rp = await registerRp(h, { name: 'IFMIS Test' });
    device = await createCitizenWithBinding(h, 'AL2');
    loginHint = await provisionSubject(h, rp.rpId, device.pseudoNid);
  });

  afterAll(async () => {
    await destroyHarness(h);
  });

  function bcAuthorize(
    client: TestRp,
    form: Record<string, string>,
  ): request.Test {
    return request(h.http())
      .post('/oidc/bc-authorize')
      .auth(client.clientId, client.clientSecret)
      .type('form')
      .send(form);
  }

  function tokenPoll(client: TestRp, authReqId: string): request.Test {
    return request(h.http())
      .post('/oidc/token')
      .auth(client.clientId, client.clientSecret)
      .type('form')
      .send({ grant_type: CIBA_GRANT_TYPE, auth_req_id: authReqId });
  }

  it('completes the happy path: bc-authorize -> pending -> signed approve -> tokens -> userinfo', async () => {
    const initiated = await bcAuthorize(rp, {
      scope: 'openid profile',
      login_hint: loginHint,
      binding_message: 'Login to IFMIS · code 7Q42',
    }).expect(200);
    const authReqId: string = initiated.body.auth_req_id;
    expect(authReqId).toBeTruthy();
    expect(initiated.body.interval).toBe(2);
    expect(initiated.body.expires_in).toBeGreaterThan(0);

    // RP polls too early.
    const pendingPoll = await tokenPoll(rp, authReqId).expect(400);
    expect(pendingPoll.body.error).toBe('authorization_pending');

    // Device pulls the pending request: who is asking + what for, plain language (T7).
    const txn = await fetchPendingTxn(h, device, authReqId);
    expect(txn.rpName).toBe('IFMIS Test');
    expect(txn.bindingMessage).toBe('Login to IFMIS · code 7Q42');
    expect(txn.scopes).toEqual(['openid', 'profile']);
    expect(txn.scopeDescriptions).toEqual([
      'Confirm your identity',
      'Share your name and date of birth',
    ]);
    expect(txn.requestedAssurance).toBe('AL2');
    expect(txn.challenge.approvePayload).toContain(`ciba-approve:${authReqId}`);
    expect(txn.challenge.denyPayload).toContain(`ciba-deny:${authReqId}`);

    const decision = await decide(h, device, authReqId, 'approve');
    expect(decision.status).toBe(200);
    expect(decision.body).toEqual({ status: 'approved' });

    const tokens = await tokenPoll(rp, authReqId).expect(200);
    expect(tokens.body.token_type).toBe('Bearer');
    expect(tokens.body.scope).toBe('openid profile');
    expect(tokens.body.expires_in).toBe(600);

    // Verify the ID token against the broker's own JWKS (04 §4).
    const keyset = jose.createLocalJWKSet(h.keys.jwks() as jose.JSONWebKeySet);
    const { payload: idClaims } = await jose.jwtVerify(tokens.body.id_token, keyset, {
      issuer: 'http://localhost:3100',
      audience: rp.clientId,
    });
    expect(idClaims.sub).toBe(loginHint); // pairwise sub === the RP's login_hint
    expect(idClaims['acr']).toBe('AL2'); // approving binding's assurance
    expect(idClaims['amr']).toEqual(['hwk', 'bio']);
    expect(typeof idClaims['auth_time']).toBe('number');

    const { payload: accessClaims } = await jose.jwtVerify(tokens.body.access_token, keyset, {
      issuer: 'http://localhost:3100',
      audience: rp.clientId,
    });
    expect(accessClaims['token_use']).toBe('access');
    expect(accessClaims['client_id']).toBe(rp.clientId);
    // Pairwise privacy (04 §4): the access token the RP holds must carry ONLY
    // the per-RP pairwise sub — never a global citizen identifier that two RPs
    // could compare to correlate the same citizen.
    expect(accessClaims.sub).toBe(loginHint);
    expect(accessClaims['cid']).toBeUndefined();
    expect(Object.values(accessClaims)).not.toContain(device.citizenId);

    // auth_req_id is single-use.
    const replayed = await tokenPoll(rp, authReqId).expect(400);
    expect(replayed.body.error).toBe('invalid_grant');

    // Consent was recorded by the approval, so userinfo releases attributes.
    const userinfo = await request(h.http())
      .get('/oidc/userinfo')
      .set('Authorization', `Bearer ${tokens.body.access_token}`)
      .expect(200);
    expect(userinfo.body.sub).toBe(loginHint);
    expect(userinfo.body.acr).toBe('AL2');
    expect(userinfo.body.name).toBe('Test Citizen');
    expect(userinfo.body.dateOfBirth).toBe('1990-01-01');
    expect(userinfo.body.address).toBeUndefined(); // address scope was not requested
  });

  it('returns access_denied after a signed deny', async () => {
    const initiated = await bcAuthorize(rp, { scope: 'openid', login_hint: loginHint }).expect(200);
    const authReqId: string = initiated.body.auth_req_id;
    const decision = await decide(h, device, authReqId, 'deny', { reportSuspicious: true });
    expect(decision.status).toBe(200);
    expect(decision.body).toEqual({ status: 'denied' });
    const polled = await tokenPoll(rp, authReqId).expect(400);
    expect(polled.body.error).toBe('access_denied');
  });

  it('rejects an approve signed with the wrong payload as signature_invalid', async () => {
    const initiated = await bcAuthorize(rp, { scope: 'openid', login_hint: loginHint }).expect(200);
    const authReqId: string = initiated.body.auth_req_id;
    const txn = await fetchPendingTxn(h, device, authReqId);
    // Sign the DENY payload but claim an approve — must not verify.
    const signature = await device.sign(txn.challenge.denyPayload);
    const res = await request(h.http())
      .post('/v1/device/ciba/decision')
      .set('Authorization', `Bearer ${device.sessionToken}`)
      .send({
        authReqId,
        bindingId: device.bindingId,
        challengeId: txn.challenge.challengeId,
        decision: 'approve',
        signature,
      })
      .expect(401);
    expect(res.body.error).toBe('signature_invalid');

    // The consumed challenge cannot be replayed, even with a valid signature (T4).
    const goodSignature = await device.sign(txn.challenge.approvePayload);
    const replay = await request(h.http())
      .post('/v1/device/ciba/decision')
      .set('Authorization', `Bearer ${device.sessionToken}`)
      .send({
        authReqId,
        bindingId: device.bindingId,
        challengeId: txn.challenge.challengeId,
        decision: 'approve',
        signature: goodSignature,
      })
      .expect(400);
    expect(replay.body.error).toBe('challenge_invalid');
  });

  it('expires stale transactions: expired_token, audited once', async () => {
    const authReqId = randomBytes(32).toString('base64url');
    await h.db.db.insert(authTransactions).values({
      id: uuidv7(),
      authReqId,
      citizenId: device.citizenId,
      rpId: rp.rpId,
      flow: 'ciba',
      scopes: ['openid'],
      requestedAl: 'AL2',
      status: 'pending',
      expiresAt: new Date(Date.now() - 5_000),
    });
    const first = await tokenPoll(rp, authReqId).expect(400);
    expect(first.body.error).toBe('expired_token');
    const second = await tokenPoll(rp, authReqId).expect(400);
    expect(second.body.error).toBe('expired_token');
    const { rows } = await h.db.pool.query(
      `SELECT count(*)::int AS n FROM audit_events WHERE action = 'ciba.request_expired' AND subject_ref = $1`,
      [device.citizenId],
    );
    expect(rows[0].n).toBe(1);

    // An expired txn never shows up on the device.
    const pending = await request(h.http())
      .get('/v1/device/ciba/pending')
      .set('Authorization', `Bearer ${device.sessionToken}`)
      .expect(200);
    const listed = pending.body.transactions.find((t: { authReqId: string }) => t.authReqId === authReqId);
    expect(listed).toBeUndefined();
  });

  it('rejects scopes outside the client grant with invalid_scope', async () => {
    const narrowRp = await registerRp(h, { allowedScopes: ['openid'] });
    await provisionSubject(h, narrowRp.rpId, device.pseudoNid);
    const res = await bcAuthorize(narrowRp, { scope: 'openid profile', login_hint: loginHint }).expect(400);
    expect(res.body.error).toBe('invalid_scope');
    // openid itself is mandatory
    const noOpenid = await bcAuthorize(rp, { scope: 'profile', login_hint: loginHint }).expect(400);
    expect(noOpenid.body.error).toBe('invalid_scope');
  });

  it('rejects requested_al above the client maximum with invalid_request', async () => {
    const cappedRp = await registerRp(h, { maxAssurance: 'AL2' });
    const hint = await provisionSubject(h, cappedRp.rpId, device.pseudoNid);
    const res = await bcAuthorize(cappedRp, {
      scope: 'openid',
      login_hint: hint,
      requested_al: 'AL3',
    }).expect(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('answers unknown_user_id for unknown hints AND for citizens without a capable binding', async () => {
    const unknown = await bcAuthorize(rp, { scope: 'openid', login_hint: 'no-such-subject' }).expect(400);
    expect(unknown.body.error).toBe('unknown_user_id');

    // AL2 binding cannot serve an AL3 request — same answer, no device-state leak.
    const res = await bcAuthorize(rp, {
      scope: 'openid',
      login_hint: loginHint,
      requested_al: 'AL3',
    }).expect(400);
    expect(res.body.error).toBe('unknown_user_id');
  });

  it('refuses an auth_req_id issued to another client with invalid_grant', async () => {
    const otherRp = await registerRp(h);
    const initiated = await bcAuthorize(rp, { scope: 'openid', login_hint: loginHint }).expect(200);
    const res = await tokenPoll(otherRp, initiated.body.auth_req_id).expect(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('refuses CIBA for clients not allowed the flow', async () => {
    const codeOnly = await registerRp(h, { allowedFlows: ['code'] });
    const hint = await provisionSubject(h, codeOnly.rpId, device.pseudoNid);
    const res = await bcAuthorize(codeOnly, { scope: 'openid', login_hint: hint }).expect(400);
    expect(res.body.error).toBe('unauthorized_client');
  });

  it('authenticates via client_secret_post too, and rejects bad secrets', async () => {
    const initiated = await request(h.http())
      .post('/oidc/bc-authorize')
      .type('form')
      .send({
        client_id: rp.clientId,
        client_secret: rp.clientSecret,
        scope: 'openid',
        login_hint: loginHint,
      })
      .expect(200);
    expect(initiated.body.auth_req_id).toBeTruthy();

    const bad = await request(h.http())
      .post('/oidc/bc-authorize')
      .auth(rp.clientId, 'wrong-secret')
      .type('form')
      .send({ scope: 'openid', login_hint: loginHint })
      .expect(401);
    expect(bad.body.error).toBe('invalid_client');
  });

  it('performs the AL3 step-up re-assertion, and suspends the citizen when SDID says invalid', async () => {
    // Success path: AL3 binding + valid reassert.
    const al3Device = await createCitizenWithBinding(h, 'AL3');
    const al3Hint = await provisionSubject(h, rp.rpId, al3Device.pseudoNid);
    const ok = await bcAuthorize(rp, {
      scope: 'openid',
      login_hint: al3Hint,
      requested_al: 'AL3',
    }).expect(200);
    h.sdidState.reassertValid = true;
    const approved = await decide(h, al3Device, ok.body.auth_req_id, 'approve');
    expect(approved.status).toBe(200);
    const tokens = await tokenPoll(rp, ok.body.auth_req_id).expect(200);
    const idClaims = jose.decodeJwt(tokens.body.id_token);
    expect(idClaims['acr']).toBe('AL3');

    // Failure path: SDID declares the identity invalid -> suspend + revoke all bindings.
    const doomedDevice = await createCitizenWithBinding(h, 'AL3');
    const doomedHint = await provisionSubject(h, rp.rpId, doomedDevice.pseudoNid);
    const initiated = await bcAuthorize(rp, {
      scope: 'openid',
      login_hint: doomedHint,
      requested_al: 'AL3',
    }).expect(200);
    h.sdidState.reassertValid = false;
    try {
      const denied = await decide(h, doomedDevice, initiated.body.auth_req_id, 'approve');
      expect(denied.status).toBe(403);
      expect(denied.body.error).toBe('access_denied');
    } finally {
      h.sdidState.reassertValid = true;
    }
    // Binding revoked -> the device session is dead immediately (06 §4).
    const afterwards = await request(h.http())
      .get('/v1/device/ciba/pending')
      .set('Authorization', `Bearer ${doomedDevice.sessionToken}`)
      .expect(401);
    expect(afterwards.body.error).toBe('binding_not_active');
    const { rows } = await h.db.pool.query(
      `SELECT status FROM citizens WHERE id = $1`,
      [doomedDevice.citizenId],
    );
    expect(rows[0].status).toBe('suspended');
  });

  it('rejects a suspended RP with invalid_client', async () => {
    const doomedRp = await registerRp(h);
    await request(h.http())
      .post(`/admin/rps/${doomedRp.rpId}/suspend`)
      .set('Authorization', 'Bearer dev-admin-token')
      .expect(200);
    const res = await bcAuthorize(doomedRp, { scope: 'openid', login_hint: loginHint }).expect(401);
    expect(res.body.error).toBe('invalid_client');
  });
});
