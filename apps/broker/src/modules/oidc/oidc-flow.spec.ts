import { CIBA_GRANT_TYPE } from '@sdid/shared';
import * as jose from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
} from './testkit.js';

const REDIRECT_URI = 'https://rp.example.test/callback';

describe('OIDC surface (04): discovery, code flow + PKCE, token lifecycle, pairwise privacy', () => {
  let h: Harness;
  let rp: TestRp;
  let device: TestDevice;
  let loginHint: string;

  beforeAll(async () => {
    h = await createHarness();
    rp = await registerRp(h, { name: 'Irembo Test Portal' });
    device = await createCitizenWithBinding(h, 'AL2');
    loginHint = await provisionSubject(h, rp.rpId, device.pseudoNid);
  });

  afterAll(async () => {
    await destroyHarness(h);
  });

  it('serves discovery and JWKS', async () => {
    const res = await request(h.http()).get('/.well-known/openid-configuration').expect(200);
    expect(res.body.issuer).toBe('http://localhost:3100');
    expect(res.body.authorization_endpoint).toBe('http://localhost:3100/oidc/authorize');
    expect(res.body.token_endpoint).toBe('http://localhost:3100/oidc/token');
    expect(res.body.backchannel_authentication_endpoint).toBe('http://localhost:3100/oidc/bc-authorize');
    expect(res.body.grant_types_supported).toEqual(['authorization_code', CIBA_GRANT_TYPE]);
    expect(res.body.backchannel_token_delivery_modes_supported).toEqual(['poll']);
    expect(res.body.response_types_supported).toEqual(['code']);
    expect(res.body.code_challenge_methods_supported).toEqual(['S256']);
    expect(res.body.id_token_signing_alg_values_supported).toEqual(['ES256']);
    expect(res.body.scopes_supported).toEqual(['openid', 'profile', 'address']);
    expect(res.body.acr_values_supported).toEqual(['AL1', 'AL2', 'AL3']);
    expect(res.body.subject_types_supported).toEqual(['pairwise']);

    const jwks = await request(h.http()).get('/oidc/jwks').expect(200);
    expect(jwks.body.keys.length).toBeGreaterThan(0);
    expect(jwks.body.keys[0].kty).toBe('EC');
    // Only public members are published.
    expect(jwks.body.keys.every((k: Record<string, unknown>) => k['d'] === undefined)).toBe(true);
  });

  /** Run /oidc/authorize -> device approve -> poll, returning the redirect URL. */
  async function runAuthorize(codeChallenge: string, extra: Record<string, string> = {}): Promise<string> {
    const page = await request(h.http())
      .get('/oidc/authorize')
      .query({
        response_type: 'code',
        client_id: rp.clientId,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile',
        state: 'xyz-state',
        nonce: 'n-123',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        login_hint: loginHint,
        ...extra,
      })
      .expect(200);
    expect(page.headers['content-type']).toContain('text/html');
    expect(page.text).toContain('Approve this sign-in on your phone');
    expect(page.text).toContain('Irembo Test Portal');
    const match = page.text.match(/poll\?txn=([A-Za-z0-9\-_.~%]+)/);
    expect(match).toBeTruthy();
    const authReqId = decodeURIComponent(match![1]!);

    // Browser polls while the citizen decides.
    const early = await request(h.http()).get('/oidc/authorize/poll').query({ txn: authReqId }).expect(200);
    expect(early.body).toEqual({ status: 'pending' });

    // The code-flow transaction reaches the device like any CIBA request.
    const txn = await fetchPendingTxn(h, device, authReqId);
    expect(txn.bindingMessage).toBeNull();
    expect(txn.rpName).toBe('Irembo Test Portal');
    const decision = await decide(h, device, authReqId, 'approve');
    expect(decision.status).toBe(200);

    const done = await request(h.http()).get('/oidc/authorize/poll').query({ txn: authReqId }).expect(200);
    expect(done.body.status).toBe('approved');
    return done.body.redirect as string;
  }

  it('completes the code flow end-to-end with PKCE, and rejects a wrong verifier', async () => {
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const redirect = await runAuthorize(challenge);

    expect(redirect.startsWith(`${REDIRECT_URI}?`)).toBe(true);
    const url = new URL(redirect);
    const code = url.searchParams.get('code');
    expect(code).toBeTruthy();
    expect(url.searchParams.get('state')).toBe('xyz-state');

    // Wrong verifier fails.
    const bad = await request(h.http())
      .post('/oidc/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: randomBytes(32).toString('base64url'),
        client_id: rp.clientId,
        client_secret: rp.clientSecret,
      })
      .expect(400);
    expect(bad.body.error).toBe('invalid_grant');

    // Correct verifier succeeds (client_secret_post).
    const tokens = await request(h.http())
      .post('/oidc/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
        client_id: rp.clientId,
        client_secret: rp.clientSecret,
      })
      .expect(200);
    const keyset = jose.createLocalJWKSet(h.keys.jwks() as jose.JSONWebKeySet);
    const { payload: idClaims } = await jose.jwtVerify(tokens.body.id_token, keyset, {
      issuer: 'http://localhost:3100',
      audience: rp.clientId,
    });
    expect(idClaims.sub).toBe(loginHint);
    expect(idClaims['nonce']).toBe('n-123');
    expect(idClaims['acr']).toBe('AL2');

    // The code is single-use.
    const replay = await request(h.http())
      .post('/oidc/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
        client_id: rp.clientId,
        client_secret: rp.clientSecret,
      })
      .expect(400);
    expect(replay.body.error).toBe('invalid_grant');
  });

  it('validates authorize requests: unregistered redirect_uri, bad scopes, over-max acr, unknown login_hint', async () => {
    const base = {
      response_type: 'code',
      client_id: rp.clientId,
      redirect_uri: REDIRECT_URI,
      scope: 'openid',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
      login_hint: loginHint,
    };
    const badRedirect = await request(h.http())
      .get('/oidc/authorize')
      .query({ ...base, redirect_uri: 'https://evil.example.test/cb' })
      .expect(400);
    expect(badRedirect.body.error).toBe('invalid_request');

    const badScope = await request(h.http())
      .get('/oidc/authorize')
      .query({ ...base, scope: 'openid payments' })
      .expect(400);
    expect(badScope.body.error).toBe('invalid_scope');

    const cappedRp = await registerRp(h, { maxAssurance: 'AL1', allowedFlows: ['code'], redirectUris: [REDIRECT_URI] });
    const overMax = await request(h.http())
      .get('/oidc/authorize')
      .query({ ...base, client_id: cappedRp.clientId, acr_values: 'AL3' })
      .expect(400);
    expect(overMax.body.error).toBe('invalid_request');

    // Unknown citizen: a plain access-denied page, no protocol detail leaked.
    const unknownHint = await request(h.http())
      .get('/oidc/authorize')
      .query({ ...base, login_hint: 'not-a-subject' })
      .expect(200);
    expect(unknownHint.headers['content-type']).toContain('text/html');
    expect(unknownHint.text).toContain('We could not start this sign-in');
  });

  it('introspects an active token, revokes it, then reports inactive and blocks userinfo', async () => {
    // Mint tokens via a quick CIBA round.
    const initiated = await request(h.http())
      .post('/oidc/bc-authorize')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ scope: 'openid profile', login_hint: loginHint })
      .expect(200);
    await decide(h, device, initiated.body.auth_req_id, 'approve');
    const tokens = await request(h.http())
      .post('/oidc/token')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ grant_type: CIBA_GRANT_TYPE, auth_req_id: initiated.body.auth_req_id })
      .expect(200);
    const accessToken: string = tokens.body.access_token;

    const active = await request(h.http())
      .post('/oidc/introspect')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ token: accessToken })
      .expect(200);
    expect(active.body.active).toBe(true);
    expect(active.body.sub).toBe(loginHint);
    expect(active.body.client_id).toBe(rp.clientId);
    expect(active.body.token_use).toBe('access');
    expect(active.body.scope).toBe('openid profile');
    expect(typeof active.body.exp).toBe('number');

    // Revocation is aud-bound: another RP cannot revoke this token (RFC 7009 + T9).
    const otherRp = await registerRp(h);
    await request(h.http())
      .post('/oidc/revoke')
      .auth(otherRp.clientId, otherRp.clientSecret)
      .type('form')
      .send({ token: accessToken })
      .expect(200);
    const stillActive = await request(h.http())
      .post('/oidc/introspect')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ token: accessToken })
      .expect(200);
    expect(stillActive.body.active).toBe(true);

    await request(h.http())
      .post('/oidc/revoke')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ token: accessToken })
      .expect(200);

    const revoked = await request(h.http())
      .post('/oidc/introspect')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ token: accessToken })
      .expect(200);
    expect(revoked.body).toEqual({ active: false });

    const userinfo = await request(h.http())
      .get('/oidc/userinfo')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(401);
    expect(userinfo.body.error).toBe('access_denied');

    // Unknown tokens still answer 200 (RFC 7009).
    await request(h.http())
      .post('/oidc/revoke')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ token: 'not-a-jwt' })
      .expect(200);
  });

  it('gives each RP a DIFFERENT pairwise subject for the same citizen', async () => {
    const rp2 = await registerRp(h, { name: 'Land Registry Test' });
    const subject2 = await provisionSubject(h, rp2.rpId, device.pseudoNid);
    expect(subject2).not.toBe(loginHint);

    // And the sub minted into tokens matches each RP's own subject.
    const initiated = await request(h.http())
      .post('/oidc/bc-authorize')
      .auth(rp2.clientId, rp2.clientSecret)
      .type('form')
      .send({ scope: 'openid', login_hint: subject2 })
      .expect(200);
    await decide(h, device, initiated.body.auth_req_id, 'approve');
    const tokens = await request(h.http())
      .post('/oidc/token')
      .auth(rp2.clientId, rp2.clientSecret)
      .type('form')
      .send({ grant_type: CIBA_GRANT_TYPE, auth_req_id: initiated.body.auth_req_id })
      .expect(200);
    const claims = jose.decodeJwt(tokens.body.id_token);
    expect(claims.sub).toBe(subject2);
    expect(claims.sub).not.toBe(loginHint);
  });

  it('rejects unauthenticated and unsupported token requests', async () => {
    const noAuth = await request(h.http())
      .post('/oidc/token')
      .type('form')
      .send({ grant_type: CIBA_GRANT_TYPE, auth_req_id: 'whatever' })
      .expect(401);
    expect(noAuth.body.error).toBe('invalid_client');

    const badGrant = await request(h.http())
      .post('/oidc/token')
      .auth(rp.clientId, rp.clientSecret)
      .type('form')
      .send({ grant_type: 'password' })
      .expect(400);
    expect(badGrant.body.error).toBe('invalid_request');
  });
});
