/**
 * "Ghost login" e2e (SPEC 09 §6): a test RP completes a full CIBA login of a
 * simulated device against mock SDID — enrolment, hardware-backed signature,
 * minted tokens — through the REAL broker process over HTTP. One broker
 * instance serves the whole suite.
 */
import { createHmac } from 'node:crypto';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CIBA_GRANT_TYPE, MOCK_TEST_NIDS } from '@sdid/shared';
import { SimDevice } from '@sdid/device-sim';
import { RpClient, type RegisterViaAdminResult } from '@sdid/test-rp';
import {
  ADMIN_TOKEN,
  BROKER_URL,
  BrokerHarness,
  NID_PEPPER,
  clearEnrolmentThrottles,
  revokeAllBindingsViaSql,
} from './harness.js';

const HOOK_TIMEOUT = 180_000;
const TEST_TIMEOUT = 60_000;

const NID = MOCK_TEST_NIDS[0];
const IMPOSTOR_CLAIMED_NID = MOCK_TEST_NIDS[2];
const IMPOSTOR_SAMPLE_NID = MOCK_TEST_NIDS[3];

function pseudoNidOf(nid: string): string {
  return createHmac('sha256', NID_PEPPER).update(nid).digest('hex');
}

/** One raw (non-looping) CIBA token poll — lets us assert authorization_pending. */
async function tokenPollOnce(
  clientId: string,
  clientSecret: string,
  authReqId: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const form = new URLSearchParams();
  form.set('grant_type', CIBA_GRANT_TYPE);
  form.set('auth_req_id', authReqId);
  const res = await fetch(`${BROKER_URL}/oidc/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Raw decision POST so we can replay a captured challenge/signature verbatim. */
async function postDecision(
  device: SimDevice,
  body: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${BROKER_URL}/v1/device/ciba/decision`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${device.sessionToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** Enrol, falling back to psql cleanup once if the 5-device cap is hit. */
async function enrolWithCapHandling(device: SimDevice): Promise<{ assuranceLevel: string }> {
  try {
    return await device.enrol();
  } catch (err) {
    if (err instanceof Error && err.message.includes('Device limit reached')) {
      await revokeAllBindingsViaSql(pseudoNidOf(device.nid));
      await clearEnrolmentThrottles();
      return await device.enrol();
    }
    throw err;
  }
}

describe('ghost login (SPEC 09 §6) — full trust chain over HTTP', () => {
  const harness = new BrokerHarness();
  let rp: RegisterViaAdminResult;
  let device: SimDevice;
  let enrolResult: { bindingId: string; assuranceLevel: string };
  let subject: string;

  beforeAll(async () => {
    await harness.start();
    await clearEnrolmentThrottles();

    // Pilot RP registered through the admin-gated onboarding API (04 §6).
    rp = await RpClient.registerViaAdmin(BROKER_URL, ADMIN_TOKEN, {
      name: 'Irembo (pilot)',
      allowedFlows: ['ciba', 'code'],
      allowedScopes: ['openid', 'profile', 'address'],
      maxAssurance: 'AL2',
      redirectUris: ['http://localhost:9450/cb'],
    });

    // Citizen's phone: enrol (mock attestation + mock-NIDA face match) + login.
    device = new SimDevice({
      brokerUrl: BROKER_URL,
      nid: NID,
      deviceLabel: `e2e-suite-${randomBytes(4).toString('hex')}`,
    });
    enrolResult = await enrolWithCapHandling(device);
    await device.login();

    // Hygiene for repeated runs: this citizen keeps only the suite's binding
    // active, so the 5-device cap never accumulates across runs.
    const bindings = await device.listBindings();
    for (const b of bindings) {
      if (b.bindingId !== device.bindingId && b.status !== 'revoked') {
        await device.revokeBinding(b.bindingId, 'e2e-cleanup-previous-run');
      }
    }

    // The RP obtains its login_hint (pairwise subject) at onboarding (04 §6).
    subject = await RpClient.provisionLoginHint(
      BROKER_URL,
      ADMIN_TOKEN,
      rp.rpId,
      pseudoNidOf(NID),
    );
  }, HOOK_TIMEOUT);

  afterAll(async () => {
    try {
      if (device?.bindingId && device.sessionToken) {
        await device.revokeBinding(device.bindingId, 'e2e-suite-finished');
      }
    } catch {
      // best-effort cleanup
    }
    await harness.stop();
  }, HOOK_TIMEOUT);

  it(
    'enrols the device at AL2 (mock attestation + mock-NIDA match, key bound)',
    () => {
      expect(enrolResult.assuranceLevel).toBe('AL2');
      expect(enrolResult.bindingId).toMatch(/^[0-9a-f-]{36}$/);
      expect(device.sessionToken).toBeTruthy();
      expect(subject).toBeTruthy();
    },
    TEST_TIMEOUT,
  );

  it(
    'completes the happy-path CIBA login end to end',
    async () => {
      const initiated = await rp.client.initiateCiba({
        loginHint: subject,
        scope: 'openid profile',
        bindingMessage: 'Login to IFMIS · code 7Q42',
      });
      expect(initiated.authReqId).toBeTruthy();
      expect(initiated.expiresIn).toBeGreaterThan(0);

      // 04 §3 step 6: the RP polls before the citizen decided → pending.
      const early = await tokenPollOnce(rp.clientId, rp.clientSecret, initiated.authReqId);
      expect(early.status).toBe(400);
      expect(early.body.error).toBe('authorization_pending');

      // Step 5: the device pulls the pending request over the authenticated
      // backchannel and sees who is asking, for what, with the binding code.
      const pending = await device.pullPending();
      const txn = pending.find((t) => t.authReqId === initiated.authReqId);
      expect(txn).toBeDefined();
      expect(txn!.rpName).toBe('Irembo (pilot)');
      expect(txn!.bindingMessage).toBe('Login to IFMIS · code 7Q42');
      expect(txn!.scopeDescriptions).toContain('Confirm your identity');
      expect(txn!.scopeDescriptions).toContain('Share your name and date of birth');

      // Step 7: biometric unlock → hardware-backed signature → approve.
      const decision = await device.decide(initiated.authReqId, 'approve');
      expect(decision.status).toBe('approved');

      // Steps 8–9: broker verified the signature and mints tokens.
      const tokens = await rp.client.pollForTokens(initiated.authReqId, { timeoutMs: 30_000 });
      expect(tokens.idToken).toBeTruthy();
      expect(tokens.accessToken).toBeTruthy();

      // The RP verifies the ID token against the broker JWKS (04 §4).
      const claims = await rp.client.verifyIdToken(tokens.idToken);
      expect(claims.sub).toBe(subject);
      expect(claims.acr).toBe('AL2');
      expect(claims.amr).toContain('hwk');
      expect(typeof claims.auth_time).toBe('number');

      // The approval was the consent event → userinfo releases the name.
      const userinfo = (await rp.client.userinfo(tokens.accessToken)) as Record<string, unknown>;
      expect(typeof userinfo.name).toBe('string');
      expect((userinfo.name as string).length).toBeGreaterThan(0);

      // Token lifecycle: introspect live → revoke → introspect dead.
      const live = (await rp.client.introspect(tokens.accessToken)) as Record<string, unknown>;
      expect(live.active).toBe(true);
      await rp.client.revoke(tokens.accessToken);
      const dead = (await rp.client.introspect(tokens.accessToken)) as Record<string, unknown>;
      expect(dead.active).toBe(false);
    },
    TEST_TIMEOUT,
  );

  it(
    'issues pairwise subjects: a second RP sees a different sub for the same citizen',
    async () => {
      const rp2 = await RpClient.registerViaAdmin(BROKER_URL, ADMIN_TOKEN, {
        name: 'RRA e-Tax (pilot)',
        allowedFlows: ['ciba'],
        allowedScopes: ['openid', 'profile'],
        maxAssurance: 'AL2',
        redirectUris: [],
      });
      const subject2 = await RpClient.provisionLoginHint(
        BROKER_URL,
        ADMIN_TOKEN,
        rp2.rpId,
        pseudoNidOf(NID),
      );
      expect(subject2).not.toBe(subject);

      // Complete a CIBA login at the second RP too.
      const initiated = await rp2.client.initiateCiba({
        loginHint: subject2,
        scope: 'openid profile',
        bindingMessage: 'Login to e-Tax · code K9X1',
      });
      await device.decide(initiated.authReqId, 'approve');
      const tokens = await rp2.client.pollForTokens(initiated.authReqId, { timeoutMs: 30_000 });

      // Each RP's token verifies against its OWN audience and carries its own sub.
      const claims2 = await rp2.client.verifyIdToken(tokens.idToken);
      expect(claims2.sub).toBe(subject2);
      expect(claims2.sub).not.toBe(subject);
      // The first RP cannot accept the second RP's token (audience-bound).
      await expect(rp.client.verifyIdToken(tokens.idToken)).rejects.toThrow();
    },
    TEST_TIMEOUT,
  );

  it(
    'returns access_denied when the citizen denies (with suspicious-report flag)',
    async () => {
      const initiated = await rp.client.initiateCiba({
        loginHint: subject,
        scope: 'openid',
        bindingMessage: 'Login to IFMIS · code 0000',
      });
      const decision = await device.decide(initiated.authReqId, 'deny', {
        reportSuspicious: true,
      });
      expect(decision.status).toBe('denied');
      await expect(
        rp.client.pollForTokens(initiated.authReqId, { timeoutMs: 15_000 }),
      ).rejects.toThrow(/access_denied/);
    },
    TEST_TIMEOUT,
  );

  it(
    'rejects a replayed decision: the same signature POSTed twice ends in challenge_invalid',
    async () => {
      const initiated = await rp.client.initiateCiba({
        loginHint: subject,
        scope: 'openid',
        bindingMessage: 'Login to IFMIS · code 7777',
      });
      const pending = await device.pullPending();
      const txn = pending.find((t) => t.authReqId === initiated.authReqId);
      expect(txn).toBeDefined();

      // Capture ONE signature over the approve payload and POST it twice
      // verbatim (raw fetch — SimDevice would refresh the challenge). The
      // first POST consumes the single-use challenge while proving the
      // signature cannot be repurposed for a different decision; the second,
      // byte-identical POST replays an already-consumed challenge → T4.
      const signature = await device.sign(txn!.challenge.approvePayload);
      const body = {
        authReqId: initiated.authReqId,
        bindingId: device.bindingId,
        challengeId: txn!.challenge.challengeId,
        decision: 'deny', // signature is over the APPROVE payload → must not verify
        signature,
      };
      const first = await postDecision(device, body);
      expect(first.status).toBe(401);
      expect(first.body.error).toBe('signature_invalid');

      const second = await postDecision(device, body);
      expect(second.status).toBe(400);
      expect(second.body.error).toBe('challenge_invalid');

      // A genuine approve replayed after resolution is refused too — the
      // transaction is single-decision.
      const approved = await device.decide(initiated.authReqId, 'approve');
      expect(approved.status).toBe('approved');
      const fresh = await device.pullPending(); // no pending txns remain for it
      expect(fresh.find((t) => t.authReqId === initiated.authReqId)).toBeUndefined();
      await rp.client.pollForTokens(initiated.authReqId, { timeoutMs: 15_000 });
    },
    TEST_TIMEOUT,
  );

  it(
    'rejects an impostor enrolment with the generic enrolment_failed (anti-probing)',
    async () => {
      const impostor = new SimDevice({
        brokerUrl: BROKER_URL,
        nid: IMPOSTOR_CLAIMED_NID,
        deviceLabel: `e2e-impostor-${randomBytes(4).toString('hex')}`,
      });
      await expect(
        impostor.enrol({ sampleOverrides: { impostorNid: IMPOSTOR_SAMPLE_NID } }),
      ).rejects.toThrow(/enrolment_failed/);
    },
    TEST_TIMEOUT,
  );

  it(
    'audit chain verifies intact end to end',
    async () => {
      const res = await fetch(`${BROKER_URL}/admin/audit/verify`, {
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { intact: boolean; brokenAtSeq: number | null; count: number };
      expect(body.intact).toBe(true);
      expect(body.brokenAtSeq).toBeNull();
      expect(body.count).toBeGreaterThan(0);
    },
    TEST_TIMEOUT,
  );
});
