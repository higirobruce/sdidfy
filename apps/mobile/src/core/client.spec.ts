import {
  MOCK_TEST_NIDS,
  buildChallengePayload,
  type PendingTransaction,
} from '@sdid/shared';
import { beforeEach, describe, expect, it } from 'vitest';
import { ProtocolClient } from './client.js';
import { MobileError } from './errors.js';
import {
  FakeClock,
  FakeTransport,
  MockAttestation,
  MockBiometricPrompt,
  MockFaceCapture,
} from './testing/doubles.js';
import { WebCryptoKeyStore, verifySignature } from './testing/webcrypto-keystore.js';
import { MemoryBindingStore } from './types.js';
import { ENDPOINTS } from './wire.js';

const NID = MOCK_TEST_NIDS[0]!;
const BINDING_ID = '018f5c00-0000-7000-8000-000000000001';
const OTHER_BINDING_ID = '018f5c00-0000-7000-8000-000000000002';
const T0 = Date.parse('2026-08-26T10:00:00.000Z');
const ATT_NONCE = 'Nk9OQ0UtVkFMVUU_-0123456789abcdef';
const ATT_NONCE_ID = 'attnonce-1';

const NO_WAIT = { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1, random: () => 0, sleep: async () => undefined };

function iso(offsetMs: number): string {
  return new Date(T0 + offsetMs).toISOString();
}

interface Harness {
  client: ProtocolClient;
  transport: FakeTransport;
  keyStore: WebCryptoKeyStore;
  faceCapture: MockFaceCapture;
  bindingStore: MemoryBindingStore;
  clock: FakeClock;
  biometrics: MockBiometricPrompt;
}

function harness(overrides: Partial<Parameters<typeof buildClient>[0]> = {}): Harness {
  return buildClient({
    transport: new FakeTransport(),
    keyStore: new WebCryptoKeyStore(),
    faceCapture: new MockFaceCapture(NID),
    bindingStore: new MemoryBindingStore(),
    clock: new FakeClock(T0),
    biometrics: new MockBiometricPrompt(),
    minKeySecurityLevel: 'software' as const,
    ...overrides,
  });
}

function buildClient(parts: {
  transport: FakeTransport;
  keyStore: WebCryptoKeyStore;
  faceCapture: MockFaceCapture;
  bindingStore: MemoryBindingStore;
  clock: FakeClock;
  biometrics: MockBiometricPrompt;
  minKeySecurityLevel: 'software' | 'tee' | 'strongbox';
}): Harness {
  const client = new ProtocolClient({
    brokerUrl: 'http://broker.test/',
    transport: parts.transport,
    keyStore: parts.keyStore,
    attestation: new MockAttestation(),
    faceCapture: parts.faceCapture,
    biometrics: parts.biometrics,
    bindingStore: parts.bindingStore,
    clock: parts.clock,
    retry: NO_WAIT,
    minKeySecurityLevel: parts.minKeySecurityLevel,
  });
  return { ...parts, client };
}

/** Stub the three enrolment endpoints with a consistent activation challenge. */
function stubEnrol(
  transport: FakeTransport,
  options: { challengeId?: string; challengeNonce?: string; payload?: string } = {},
): { challengeId: string; challengeNonce: string; payload: string } {
  const challengeId = options.challengeId ?? 'act-chal-1';
  const challengeNonce = options.challengeNonce ?? 'act-nonce-1';
  const payload =
    options.payload ?? buildChallengePayload({ kind: 'activation' }, challengeId, challengeNonce);

  transport.json('POST', ENDPOINTS.attestationChallenge, {
    nonceId: ATT_NONCE_ID,
    nonce: ATT_NONCE,
    expiresAt: iso(300_000),
  });
  transport.json('POST', ENDPOINTS.enrolStart, {
    bindingId: BINDING_ID,
    assuranceLevel: 'AL2',
    activationChallenge: { challengeId, nonce: challengeNonce, payload, expiresAt: iso(120_000) },
  });
  transport.json('POST', ENDPOINTS.enrolActivate, { bindingId: BINDING_ID, status: 'active' });
  return { challengeId, challengeNonce, payload };
}

function stubLogin(transport: FakeTransport, token = 'session-token-1'): void {
  const challengeId = 'login-chal-1';
  const nonce = 'login-nonce-1';
  transport.json('POST', ENDPOINTS.loginChallenge, {
    challengeId,
    nonce,
    payload: buildChallengePayload({ kind: 'login' }, challengeId, nonce),
    expiresAt: iso(120_000),
  });
  transport.json('POST', ENDPOINTS.login, { sessionToken: token, expiresIn: 900 });
}

function pendingTxn(overrides: Partial<PendingTransaction> = {}): PendingTransaction {
  const authReqId = overrides.authReqId ?? 'authreq-1';
  const challengeId = 'ciba-chal-1';
  const nonce = 'ciba-nonce-1';
  return {
    authReqId,
    rpName: 'Irembo',
    rpLogoUri: null,
    scopes: ['openid', 'profile'],
    scopeDescriptions: ['Confirm your identity', 'Share your name and date of birth'],
    bindingMessage: 'Login to Irembo · code 7Q42',
    requestedAssurance: 'AL2',
    createdAt: iso(0),
    expiresAt: iso(180_000),
    challenge: {
      challengeId,
      nonce,
      approvePayload: buildChallengePayload({ kind: 'ciba-approve', authReqId }, challengeId, nonce),
      denyPayload: buildChallengePayload({ kind: 'ciba-deny', authReqId }, challengeId, nonce),
      expiresAt: iso(120_000),
    },
    ...overrides,
  };
}

async function enrolled(h: Harness): Promise<Harness> {
  stubEnrol(h.transport);
  await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });
  return h;
}

// ── Enrolment (03 §2) ───────────────────────────────────────────────────────

describe('enrolment', () => {
  let h: Harness;
  beforeEach(() => {
    h = harness();
  });

  it('runs nonce → key → attest → capture → start → sign → activate', async () => {
    const { payload } = stubEnrol(h.transport);
    const result = await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });

    expect(result).toEqual({ bindingId: BINDING_ID, assuranceLevel: 'AL2' });
    expect(h.transport.countOf('POST', ENDPOINTS.attestationChallenge)).toBe(1);
    expect(h.transport.countOf('POST', ENDPOINTS.enrolStart)).toBe(1);
    expect(h.transport.countOf('POST', ENDPOINTS.enrolActivate)).toBe(1);
    // The activation challenge is what got signed, and nothing else.
    expect(h.keyStore.signedPayloads).toEqual([payload]);
  });

  it('feeds the broker nonce into key generation AND back as attestation.nonceId (T4)', async () => {
    stubEnrol(h.transport);
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });

    // Android bakes the challenge into the cert chain at keygen — runbook §10.
    expect(h.keyStore.attestationChallenges).toEqual([ATT_NONCE]);

    const body = h.transport.lastBody('POST', ENDPOINTS.enrolStart) as {
      attestation: { nonceId: string; token: string };
    };
    expect(body.attestation.nonceId).toBe(ATT_NONCE_ID);
    // …and the nonce itself rides INSIDE the token, under the platform signature.
    const claims = JSON.parse(Buffer.from(body.attestation.token, 'base64url').toString('utf8'));
    expect(claims.nonce).toBe(ATT_NONCE);
  });

  it('sends a signature the broker can verify against the enrolled public key', async () => {
    const { payload } = stubEnrol(h.transport);
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });

    const start = h.transport.lastBody('POST', ENDPOINTS.enrolStart) as {
      devicePublicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
    };
    const activate = h.transport.lastBody('POST', ENDPOINTS.enrolActivate) as {
      signature: string;
    };
    expect(await verifySignature(start.devicePublicKeyJwk, payload, activate.signature)).toBe(true);
  });

  it('mints a FRESH nonce and a FRESH key on every attempt (runbook §10)', async () => {
    stubEnrol(h.transport);
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });

    expect(h.transport.countOf('POST', ENDPOINTS.attestationChallenge)).toBe(2);
    const bodies = h.transport.requests
      .filter((r) => new URL(r.request.url).pathname === ENDPOINTS.enrolStart)
      .map((r) => (r.body as { devicePublicKeyJwk: { x: string } }).devicePublicKeyJwk.x);
    expect(bodies[0]).not.toBe(bodies[1]);
  });

  it('persists a binding that contains no NID and no session token (07 §1)', async () => {
    stubEnrol(h.transport);
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });

    const persisted = await h.client.currentBinding();
    expect(persisted).toMatchObject({ bindingId: BINDING_ID, assuranceLevel: 'AL2' });
    expect(JSON.stringify(persisted)).not.toContain(NID);
    expect(JSON.stringify(persisted)).not.toMatch(/session/i);
  });

  it('disposes the biometric sample, even when the request fails', async () => {
    stubEnrol(h.transport);
    await h.client.enrol({ nid: NID, deviceLabel: 'Test Phone' });
    expect(h.faceCapture.captured[0]!.isDisposed).toBe(true);

    const failing = harness();
    failing.transport.json('POST', ENDPOINTS.attestationChallenge, {
      nonceId: ATT_NONCE_ID,
      nonce: ATT_NONCE,
      expiresAt: iso(300_000),
    });
    failing.transport.fail('POST', ENDPOINTS.enrolStart, 403, 'enrolment_failed');
    await expect(failing.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toBeInstanceOf(
      MobileError,
    );
    expect(failing.faceCapture.captured[0]!.isDisposed).toBe(true);
  });

  it('rejects a malformed NID locally, before anything leaves the phone', async () => {
    await expect(h.client.enrol({ nid: '123', deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'invalid_request',
      source: 'client',
      detail: 'nid_format',
    });
    expect(h.transport.requests).toHaveLength(0);
  });

  it('refuses a software-held key when hardware backing is required (06 §6)', async () => {
    const strict = harness({ minKeySecurityLevel: 'tee' });
    stubEnrol(strict.transport);
    await expect(strict.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'secure_hardware_unavailable',
    });
    expect(strict.transport.requests).toHaveLength(0);
  });

  it('refuses when no biometric is enrolled, or when only weak biometry exists (05 §3)', async () => {
    const noBio = harness({
      biometrics: new MockBiometricPrompt({
        available: true,
        enrolled: false,
        strong: true,
        kinds: ['face'],
      }),
    });
    await expect(noBio.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'biometric_not_enrolled',
    });

    const weak = harness({
      biometrics: new MockBiometricPrompt({
        available: true,
        enrolled: true,
        strong: false,
        kinds: ['face'],
      }),
    });
    await expect(weak.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'biometric_unavailable',
      detail: 'weak_biometry',
    });
  });

  it('REFUSES to sign an activation payload it cannot reconstruct', async () => {
    // A broker that is compromised or spoofed hands back a payload of its own
    // choosing; the device rebuilds the canonical one and compares (T4).
    stubEnrol(h.transport, { payload: 'sdid-bridge:v1:login:act-chal-1:act-nonce-1' });
    await expect(h.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'unexpected_response',
      detail: 'challenge_payload_mismatch',
    });
    expect(h.keyStore.signedPayloads).toEqual([]);
    expect(h.transport.countOf('POST', ENDPOINTS.enrolActivate)).toBe(0);
  });

  it('maps a broker refusal to a citizen-facing key and drops the server prose (03 §7)', async () => {
    h.transport.json('POST', ENDPOINTS.attestationChallenge, {
      nonceId: ATT_NONCE_ID,
      nonce: ATT_NONCE,
      expiresAt: iso(300_000),
    });
    h.transport.fail('POST', ENDPOINTS.enrolStart, 403, 'attestation_rejected');

    const error = (await h.client
      .enrol({ nid: NID, deviceLabel: 'x' })
      .catch((e: unknown) => e)) as MobileError;
    expect(error.code).toBe('attestation_rejected');
    expect(error.messageKey).toBe('errors.attestation_rejected');
    expect(error.userRetryable).toBe(false);
    expect(error.message).not.toContain('server prose');
  });

  it('reports an interrupted nonce-consuming call as "start again", without retrying', async () => {
    h.transport.json('POST', ENDPOINTS.attestationChallenge, {
      nonceId: ATT_NONCE_ID,
      nonce: ATT_NONCE,
      expiresAt: iso(300_000),
    });
    h.transport.drop('POST', ENDPOINTS.enrolStart, 'timeout');

    await expect(h.client.enrol({ nid: NID, deviceLabel: 'x' })).rejects.toMatchObject({
      code: 'interrupted',
    });
    expect(h.transport.countOf('POST', ENDPOINTS.enrolStart)).toBe(1);
  });
});

// ── Direct login + session handling (01 §2.2, 04 §7) ────────────────────────

describe('direct login and session handling', () => {
  it('signs the login challenge and holds the session in memory only', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const token = await h.client.login();

    expect(token).toBe('session-token-1');
    expect(h.keyStore.signedPayloads).toHaveLength(2); // activation + login
    expect(JSON.stringify(await h.client.currentBinding())).not.toContain('session-token-1');
  });

  it('reuses a live session instead of re-signing on every call', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('GET', ENDPOINTS.bindings, { devices: [] });

    await h.client.listBindings();
    await h.client.listBindings();
    expect(h.transport.countOf('POST', ENDPOINTS.login)).toBe(1);
  });

  it('re-logs in once when the session JWT is rejected (401 access_denied)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport
      .fail('GET', ENDPOINTS.bindings, 401, 'access_denied')
      .json('GET', ENDPOINTS.bindings, { devices: [] });

    await expect(h.client.listBindings()).resolves.toEqual([]);
    expect(h.transport.countOf('POST', ENDPOINTS.login)).toBe(2);
  });

  it('re-logs in when the session has expired by the clock', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('GET', ENDPOINTS.bindings, { devices: [] });

    await h.client.listBindings();
    h.clock.advance(900_000);
    await h.client.listBindings();
    expect(h.transport.countOf('POST', ENDPOINTS.login)).toBe(2);
  });

  it('wipes local state when the binding has been revoked server-side (06 §4)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.fail('GET', ENDPOINTS.bindings, 401, 'binding_not_active');

    await expect(h.client.listBindings()).rejects.toMatchObject({
      code: 'binding_not_active',
      terminalForBinding: true,
    });
    expect(await h.client.isEnrolled()).toBe(false);
    expect(await h.keyStore.hasKey('sdid.bridge.device.v1')).toBe(false);
  });

  it('refuses to act at all before enrolment', async () => {
    const h = harness();
    await expect(h.client.login()).rejects.toMatchObject({ code: 'not_enrolled' });
    await expect(h.client.listBindings()).rejects.toMatchObject({ code: 'not_enrolled' });
  });
});

// ── CIBA approval (04 §3, T7) ──────────────────────────────────────────────

describe('CIBA approval', () => {
  it('pulls pending requests over the authenticated backchannel (T6)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    h.transport.json('GET', ENDPOINTS.cibaPending, { transactions: [txn] });

    const pending = await h.client.pullPending();
    expect(pending).toEqual([txn]);
    const call = h.transport.requests.find(
      (r) => new URL(r.request.url).pathname === ENDPOINTS.cibaPending,
    );
    expect(call!.request.headers['authorization']).toBe('Bearer session-token-1');
  });

  it('approves by signing the approve payload for THAT auth request', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    h.transport.json('POST', ENDPOINTS.cibaDecision, { status: 'approved' });

    await expect(h.client.approve(txn)).resolves.toEqual({ status: 'approved' });
    expect(h.keyStore.signedPayloads.at(-1)).toBe(txn.challenge.approvePayload);

    const body = h.transport.lastBody('POST', ENDPOINTS.cibaDecision) as Record<string, unknown>;
    expect(body).toMatchObject({
      authReqId: txn.authReqId,
      bindingId: BINDING_ID,
      challengeId: txn.challenge.challengeId,
      decision: 'approve',
    });
    expect(body['reportSuspicious']).toBeUndefined();
  });

  it('denies with a signature too — a denial is authentic, not just a silence', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    h.transport.json('POST', ENDPOINTS.cibaDecision, { status: 'denied' });

    await h.client.deny(txn);
    expect(h.keyStore.signedPayloads.at(-1)).toBe(txn.challenge.denyPayload);
  });

  it('"I did not request this" denies AND flags (05 §2, T7)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    h.transport.json('POST', ENDPOINTS.cibaDecision, { status: 'denied' });

    await h.client.reportNotMe(txn);
    expect(h.transport.lastBody('POST', ENDPOINTS.cibaDecision)).toMatchObject({
      decision: 'deny',
      reportSuspicious: true,
    });
  });

  it('shows who is asking inside the biometric prompt itself (T7)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    h.transport.json('POST', ENDPOINTS.cibaDecision, { status: 'approved' });

    await h.client.approve(txn);
    const prompt = h.keyStore.promptLog.at(-1)!;
    expect(prompt.subtitle).toContain('Irembo');
    expect(prompt.subtitle).toContain('7Q42');
  });

  it('REFUSES a payload bound to a different auth request (relay defence, T7)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const attacker = pendingTxn({ authReqId: 'authreq-attacker' });
    const victim = pendingTxn({ authReqId: 'authreq-victim' });
    // Screen shows the victim's request; the payload approves the attacker's.
    const spliced: PendingTransaction = {
      ...victim,
      challenge: { ...victim.challenge, approvePayload: attacker.challenge.approvePayload },
    };
    await h.client.login(); // warm the session so only the approval remains
    const signaturesBefore = h.keyStore.signedPayloads.length;

    await expect(h.client.approve(spliced)).rejects.toMatchObject({
      code: 'unexpected_response',
      detail: 'challenge_payload_mismatch',
    });
    expect(h.keyStore.signedPayloads).toHaveLength(signaturesBefore);
    expect(h.transport.countOf('POST', ENDPOINTS.cibaDecision)).toBe(0);
  });

  it('refuses an expired challenge before prompting the citizen', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    const txn = pendingTxn();
    await h.client.login();
    const promptsBefore = h.keyStore.promptLog.length;
    h.clock.advance(130_000); // past the 120 s challenge TTL

    await expect(h.client.approve(txn)).rejects.toMatchObject({
      code: 'challenge_invalid',
      source: 'client',
    });
    expect(h.keyStore.promptLog).toHaveLength(promptsBefore); // never prompted
  });

  it('produces no decision at all when the citizen cancels the biometric prompt', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('POST', ENDPOINTS.cibaDecision, { status: 'approved' });
    await h.client.login();
    h.keyStore.gate = 'cancel';

    await expect(h.client.approve(pendingTxn())).rejects.toMatchObject({
      code: 'biometric_cancelled',
    });
    expect(h.transport.countOf('POST', ENDPOINTS.cibaDecision)).toBe(0);
  });
});

// ── Devices, consents, activity ────────────────────────────────────────────

describe('device, consent and activity management', () => {
  it('revoking THIS device wipes local state and destroys the key (03 §5)', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('POST', ENDPOINTS.revokeBinding, { status: 'revoked' });

    await h.client.revokeBinding(BINDING_ID, 'lost');
    expect(h.transport.lastBody('POST', ENDPOINTS.revokeBinding)).toEqual({
      bindingId: BINDING_ID,
      reason: 'lost',
    });
    expect(await h.client.isEnrolled()).toBe(false);
    expect(await h.keyStore.hasKey('sdid.bridge.device.v1')).toBe(false);
  });

  it('revoking ANOTHER device leaves this one enrolled', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('POST', ENDPOINTS.revokeBinding, { status: 'revoked' });

    await h.client.revokeBinding(OTHER_BINDING_ID);
    expect(await h.client.isEnrolled()).toBe(true);
    expect(h.transport.lastBody('POST', ENDPOINTS.revokeBinding)).toEqual({
      bindingId: OTHER_BINDING_ID,
    });
  });

  it('parses the device list, consents and activity', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('GET', ENDPOINTS.bindings, {
      devices: [
        {
          bindingId: BINDING_ID,
          deviceLabel: 'Test Phone',
          assuranceLevel: 'AL2',
          status: 'active',
          enrolledAt: iso(0),
          lastUsedAt: null,
        },
      ],
    });
    h.transport.json('GET', ENDPOINTS.consents, {
      consents: [
        {
          id: 'c1',
          rpName: 'Irembo',
          scopes: ['openid'],
          grantedAt: iso(0),
          revokedAt: null,
          source: 'ciba-approval',
        },
      ],
    });
    h.transport.json('GET', ENDPOINTS.activity, {
      events: [{ ts: iso(0), action: 'auth.login_succeeded', result: 'success' }],
    });
    h.transport.json('POST', ENDPOINTS.revokeConsent, { status: 'revoked' });

    expect(await h.client.listBindings()).toHaveLength(1);
    expect((await h.client.listConsents())[0]!.rpName).toBe('Irembo');
    expect((await h.client.activity())[0]!.action).toBe('auth.login_succeeded');
    await expect(h.client.revokeConsent('c1')).resolves.toBeUndefined();
  });

  it('treats a malformed broker response as unexpected_response, not as data', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.json('GET', ENDPOINTS.bindings, { devices: [{ bindingId: 'not-a-uuid' }] });

    await expect(h.client.listBindings()).rejects.toMatchObject({
      code: 'unexpected_response',
    });
  });

  it('treats a non-JSON success body as unexpected_response', async () => {
    const h = await enrolled(harness());
    stubLogin(h.transport);
    h.transport.on('GET', ENDPOINTS.activity, () => ({ status: 200, body: '<html>oops</html>' }));

    await expect(h.client.activity()).rejects.toMatchObject({ code: 'unexpected_response' });
  });
});
