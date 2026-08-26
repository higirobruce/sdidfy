/**
 * ProtocolClient — the authenticator's complete conversation with the broker.
 *
 * This is `apps/device-sim/src/sim-device.ts` re-shaped for production: same
 * wire protocol, byte for byte, but with typed errors instead of `throw new
 * Error(HTTP 4xx …)`, a real retry policy, a hardware KeyStore behind an
 * interface instead of a WebCrypto keypair, and none of the simulator's
 * negative-test affordances (no impostor NID, no spoofed liveness, no
 * attestation-claim overrides — those exist to attack the broker in tests and
 * have no place in a citizen's phone).
 *
 * Flows implemented:
 *   enrolment (03 §2)                   attestation nonce → key → attest →
 *                                       capture → start → sign → activate
 *   direct login (01 §2.2)              challenge → sign → session
 *   CIBA approval (04 §3 steps 5–8)     pull pending → show → sign → decide
 *   device list / revoke (03 §4, 05 §2)
 *   consents + activity (04 §5, 07 §4)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE CLIENT NEVER SIGNS A STRING IT DID NOT RECONSTRUCT
 * ─────────────────────────────────────────────────────────────────────────────
 * Every challenge the broker returns carries a `payload` the device is asked to
 * sign. We do NOT sign it as given: we rebuild the canonical payload with
 * `buildChallengePayload(purpose, challengeId, nonce)` from @sdid/shared and
 * require an exact match (03 §2 step 9, T4). A broker that is compromised,
 * spoofed, or simply buggy therefore cannot steer this device into signing an
 * arbitrary or differently-purposed string — in particular it cannot hand back
 * a `ciba-approve:<other authReqId>` payload while the screen shows a
 * different request (T7). Mismatch ⇒ refuse, `unexpected_response`.
 */
import {
  buildChallengePayload,
  type AssuranceLevel,
  type DeviceListItem,
  type EnrolActivateRequest,
  type EnrolStartRequest,
  type PendingTransaction,
} from '@sdid/shared';
import { createTranslator, type Translator } from '../i18n/index.js';
import type { Attestation } from './attestation.js';
import type { BiometricPrompt, FaceCapture } from './biometrics.js';
import { MobileError, toMobileError } from './errors.js';
import type { KeySecurityLevel, KeyStore, SignPromptSpec } from './keystore.js';
import {
  DEFAULT_RETRY,
  sendWithRetry,
  type HttpTransport,
  type Idempotency,
  type RetryPolicy,
} from './transport.js';
import {
  MemoryBindingStore,
  systemClock,
  type BindingStore,
  type Clock,
  type PersistedBinding,
} from './types.js';
import {
  ENDPOINTS,
  activityResponseSchema,
  attestationChallengeResponseSchema,
  bindingsResponseSchema,
  cibaDecisionResponseSchema,
  consentsResponseSchema,
  enrolActivateResponseSchema,
  enrolStartResponseSchema,
  issuedChallengeSchema,
  loginResponseSchema,
  pendingTransactionsResponseSchema,
  revokedResponseSchema,
  type ActivityItem,
  type CibaDecisionResponse,
  type ConsentListItem,
} from './wire.js';

/** 16 digits, matching `enrolStartRequestSchema` — checked locally so an
 *  obviously malformed NID never leaves the phone (and never reaches a log). */
const NID_PATTERN = /^\d{16}$/;

/** Default alias for this device's binding key. One binding per install. */
export const DEFAULT_KEY_ALIAS = 'sdid.bridge.device.v1';

/** Re-login this many ms before the session JWT actually expires. */
const SESSION_SKEW_MS = 30_000;

export interface ProtocolClientOptions {
  brokerUrl: string;
  transport: HttpTransport;
  keyStore: KeyStore;
  attestation: Attestation;
  faceCapture: FaceCapture;
  biometrics?: BiometricPrompt;
  bindingStore?: BindingStore;
  /** Supplies the localised text shown inside the platform biometric prompt. */
  translator?: Translator;
  clock?: Clock;
  retry?: RetryPolicy;
  requestTimeoutMs?: number;
  keyAlias?: string;
  /**
   * Lowest acceptable key security level (06 §6). Default `tee`: a
   * software-held key is refused at enrolment rather than silently enrolled
   * and later capped at AL1 by the broker. Set to `software` only in dev.
   */
  minKeySecurityLevel?: KeySecurityLevel;
}

export interface EnrolInput {
  /** 16-digit NID. Used once, in one request; never persisted, never logged. */
  nid: string;
  deviceLabel: string;
}

export interface EnrolResult {
  bindingId: string;
  assuranceLevel: AssuranceLevel;
}

export interface DenyOptions {
  /** "I did not request this" (05 §2 help/report path, T7). */
  reportSuspicious?: boolean;
}

interface CallSpec<T> {
  method: 'GET' | 'POST';
  path: string;
  idempotency: Idempotency;
  parse: (value: unknown) => T;
  body?: unknown;
  bearer?: string;
}

const SECURITY_RANK: Record<KeySecurityLevel, number> = {
  software: 0,
  tee: 1,
  strongbox: 2,
};

export class ProtocolClient {
  private readonly baseUrl: string;
  private readonly opts: ProtocolClientOptions;
  private readonly bindings: BindingStore;
  private readonly clock: Clock;
  private readonly t: Translator;
  private readonly keyAlias: string;
  private readonly timeoutMs: number;
  private readonly minSecurity: KeySecurityLevel;

  /**
   * Session token + expiry, IN MEMORY ONLY. It is a short-lived bearer
   * credential (default 900 s); persisting it would put a usable credential in
   * a filesystem dump for no benefit — re-login costs one signature.
   */
  private session: { token: string; expiresAtMs: number } | null = null;

  constructor(options: ProtocolClientOptions) {
    this.opts = options;
    this.baseUrl = options.brokerUrl.replace(/\/+$/, '');
    this.bindings = options.bindingStore ?? new MemoryBindingStore();
    this.clock = options.clock ?? systemClock;
    this.t = options.translator ?? createTranslator();
    this.keyAlias = options.keyAlias ?? DEFAULT_KEY_ALIAS;
    this.timeoutMs = options.requestTimeoutMs ?? 15_000;
    this.minSecurity = options.minKeySecurityLevel ?? 'tee';
  }

  // ── Enrolment (03 §2) ─────────────────────────────────────────────────────

  /**
   * Full enrolment. Ordering is load-bearing:
   *   1. mint a FRESH attestation nonce (never reused, even on retry — T4);
   *   2. generate a FRESH hardware key with that nonce as its Android
   *      attestation challenge (the challenge cannot be attached later);
   *   3. attest the app/device, binding the same nonce and the same key;
   *   4. capture the face + liveness;
   *   5. POST /enrol/start (single request carrying the sample);
   *   6. sign the activation challenge with the new key — proof of possession;
   *   7. POST /enrol/activate → binding becomes ACTIVE.
   *
   * The biometric sample is disposed in a `finally`. Note the honest limit:
   * once encoded into a JSON request body the bytes exist as an immutable JS
   * string that cannot be zeroed. The controls that remain are that the copy
   * is short-lived, never persisted, and never logged (07 §1) — and that the
   * native capture buffer, which is the long-lived one, IS zeroed.
   */
  async enrol(input: EnrolInput): Promise<EnrolResult> {
    if (!NID_PATTERN.test(input.nid)) {
      // Detail names the field, never the value (07 §1: no raw NIDs anywhere).
      throw new MobileError('invalid_request', { source: 'client', detail: 'nid_format' });
    }
    await this.assertDeviceCanEnrol();

    const challenge = await this.call({
      method: 'POST',
      path: ENDPOINTS.attestationChallenge,
      idempotency: 'safe',
      parse: (v) => attestationChallengeResponseSchema.parse(v),
    });

    const key = await this.opts.keyStore.generate({
      alias: this.keyAlias,
      attestationChallenge: challenge.nonce,
    });
    this.assertSecurityLevel(key.securityLevel);

    const attestation = await this.opts.attestation.attest({
      nonce: challenge.nonce,
      keyAlias: this.keyAlias,
      publicJwk: key.publicJwk,
      ...(key.keyAttestation !== undefined ? { keyAttestation: key.keyAttestation } : {}),
    });

    const sample = await this.opts.faceCapture.capture({
      instruction: this.t.t('enrol.capture.instruction'),
      cancelLabel: this.t.t('common.cancel'),
    });

    let start;
    try {
      const body: EnrolStartRequest = {
        nid: input.nid,
        devicePublicKeyJwk: key.publicJwk,
        attestation: { ...attestation, nonceId: challenge.nonceId },
        deviceLabel: input.deviceLabel,
        sample: sample.toDto(),
      };
      start = await this.call({
        method: 'POST',
        path: ENDPOINTS.enrolStart,
        idempotency: 'consumes-nonce',
        body,
        parse: (v) => enrolStartResponseSchema.parse(v),
      });
    } finally {
      sample.dispose();
    }

    const payload = this.expectPayload(
      { kind: 'activation' },
      start.activationChallenge.challengeId,
      start.activationChallenge.nonce,
      start.activationChallenge.payload,
    );
    const signature = await this.sign(payload, {
      title: this.t.t('enrol.progress.activating'),
      subtitle: this.t.t('enrol.consent.point.deviceKey'),
      cancelLabel: this.t.t('common.cancel'),
    });

    const activateBody: EnrolActivateRequest = {
      bindingId: start.bindingId,
      challengeId: start.activationChallenge.challengeId,
      signature,
    };
    const activated = await this.call({
      method: 'POST',
      path: ENDPOINTS.enrolActivate,
      idempotency: 'consumes-nonce',
      body: activateBody,
      parse: (v) => enrolActivateResponseSchema.parse(v),
    });

    const persisted: PersistedBinding = {
      bindingId: activated.bindingId,
      keyAlias: this.keyAlias,
      deviceLabel: input.deviceLabel,
      assuranceLevel: start.assuranceLevel,
      enrolledAt: new Date(this.clock.now()).toISOString(),
    };
    await this.bindings.save(persisted);
    return { bindingId: activated.bindingId, assuranceLevel: start.assuranceLevel };
  }

  /** Pre-flight gates (05 §3, 06 §6). Refuse early, with an actionable reason. */
  private async assertDeviceCanEnrol(): Promise<void> {
    const keyCaps = await this.opts.keyStore.capabilities();
    if (!keyCaps.available) {
      throw MobileError.local('secure_hardware_unavailable', { detail: 'keystore_unavailable' });
    }
    this.assertSecurityLevel(keyCaps.securityLevel);

    const bio = this.opts.biometrics;
    if (bio) {
      const caps = await bio.capabilities();
      if (!caps.available) throw MobileError.local('biometric_unavailable');
      if (!caps.enrolled) throw MobileError.local('biometric_not_enrolled');
      // Only strong biometry may gate the signing key (05 §3, T1).
      if (!caps.strong) throw MobileError.local('biometric_unavailable', { detail: 'weak_biometry' });
    }
  }

  private assertSecurityLevel(level: KeySecurityLevel): void {
    if (SECURITY_RANK[level] < SECURITY_RANK[this.minSecurity]) {
      throw MobileError.local('secure_hardware_unavailable', {
        detail: `key_security_level=${level}`,
      });
    }
  }

  // ── Direct login (01 §2.2) ────────────────────────────────────────────────

  /** Challenge → signature → short-lived session JWT. Held in memory only. */
  async login(): Promise<string> {
    const binding = await this.requireBinding();
    const challenge = await this.call({
      method: 'POST',
      path: ENDPOINTS.loginChallenge,
      idempotency: 'safe',
      body: { bindingId: binding.bindingId },
      parse: (v) => issuedChallengeSchema.parse(v),
    });

    const payload = this.expectPayload(
      { kind: 'login' },
      challenge.challengeId,
      challenge.nonce,
      challenge.payload,
    );
    const signature = await this.sign(payload, {
      title: this.t.t('onboarding.welcomeTitle'),
      subtitle: this.t.t('approval.approveHint'),
      cancelLabel: this.t.t('common.cancel'),
    });

    const result = await this.call({
      method: 'POST',
      path: ENDPOINTS.login,
      idempotency: 'consumes-nonce',
      body: { bindingId: binding.bindingId, challengeId: challenge.challengeId, signature },
      parse: (v) => loginResponseSchema.parse(v),
    });
    this.session = {
      token: result.sessionToken,
      expiresAtMs: this.clock.now() + result.expiresIn * 1000,
    };
    return result.sessionToken;
  }

  // ── CIBA (04 §3) ──────────────────────────────────────────────────────────

  /**
   * Pull pending transactions over the authenticated backchannel. The push
   * channel is wake-only and its payload is never trusted (T6) — this call is
   * the only source of truth for what is being asked.
   */
  async pullPending(): Promise<PendingTransaction[]> {
    const body = await this.authed({
      method: 'GET',
      path: ENDPOINTS.cibaPending,
      idempotency: 'safe',
      parse: (v) => pendingTransactionsResponseSchema.parse(v),
    });
    return body.transactions;
  }

  /**
   * Decide the transaction the citizen actually looked at.
   *
   * Takes the `PendingTransaction` object the approval screen rendered — NOT
   * an id to re-fetch — so the thing signed is provably the thing displayed
   * (T7). Each `pullPending` mints a fresh challenge, so re-fetching before
   * signing would sign a challenge attached to a screen nobody saw.
   */
  async decide(
    txn: PendingTransaction,
    decision: 'approve' | 'deny',
    opts?: DenyOptions,
  ): Promise<CibaDecisionResponse> {
    const binding = await this.requireBinding();
    // Establish the backchannel session FIRST. `login()` needs a signature of
    // its own, and a session acquired *after* the approval signature would
    // raise a second, unexplained biometric prompt in the middle of the
    // approval — exactly the kind of prompt the citizen learns to tap through
    // (T7). One prompt at a time, each with its own stated reason.
    await this.ensureSession();

    // Client-side expiry check: signing an expired challenge burns the
    // citizen's attempt and returns a confusing `challenge_invalid`.
    if (Date.parse(txn.challenge.expiresAt) <= this.clock.now()) {
      throw new MobileError('challenge_invalid', { source: 'client', detail: 'challenge_expired' });
    }

    const purpose =
      decision === 'approve'
        ? ({ kind: 'ciba-approve', authReqId: txn.authReqId } as const)
        : ({ kind: 'ciba-deny', authReqId: txn.authReqId } as const);
    const given = decision === 'approve' ? txn.challenge.approvePayload : txn.challenge.denyPayload;
    const payload = this.expectPayload(
      purpose,
      txn.challenge.challengeId,
      txn.challenge.nonce,
      given,
    );

    const signature = await this.sign(payload, {
      title:
        decision === 'approve'
          ? this.t.t('approval.approve')
          : this.t.t('approval.deny'),
      // The prompt repeats WHO is asking, at the moment of authorisation, so
      // the platform sheet cannot be the step where context is lost (T7).
      subtitle: `${txn.rpName}${txn.bindingMessage ? ` · ${txn.bindingMessage}` : ''}`,
      cancelLabel: this.t.t('common.cancel'),
    });

    return this.authed({
      method: 'POST',
      path: ENDPOINTS.cibaDecision,
      idempotency: 'consumes-nonce',
      body: {
        authReqId: txn.authReqId,
        bindingId: binding.bindingId,
        challengeId: txn.challenge.challengeId,
        decision,
        signature,
        ...(opts?.reportSuspicious !== undefined
          ? { reportSuspicious: opts.reportSuspicious }
          : {}),
      },
      parse: (v) => cibaDecisionResponseSchema.parse(v),
    });
  }

  approve(txn: PendingTransaction): Promise<CibaDecisionResponse> {
    return this.decide(txn, 'approve');
  }

  deny(txn: PendingTransaction, opts?: DenyOptions): Promise<CibaDecisionResponse> {
    return this.decide(txn, 'deny', opts);
  }

  /** "I did not request this" — deny AND flag for the security team (T7). */
  reportNotMe(txn: PendingTransaction): Promise<CibaDecisionResponse> {
    return this.decide(txn, 'deny', { reportSuspicious: true });
  }

  // ── Devices, consents, activity (05 §2) ───────────────────────────────────

  async listBindings(): Promise<DeviceListItem[]> {
    const body = await this.authed({
      method: 'GET',
      path: ENDPOINTS.bindings,
      idempotency: 'safe',
      parse: (v) => bindingsResponseSchema.parse(v),
    });
    return body.devices;
  }

  /**
   * Revoke a binding (03 §4/§5). Revoking THIS device also wipes local state
   * and destroys the hardware key — leaving a usable key behind after the
   * citizen said "stop this phone" would be the wrong failure mode.
   */
  async revokeBinding(bindingId: string, reason?: string): Promise<void> {
    await this.authed({
      method: 'POST',
      path: ENDPOINTS.revokeBinding,
      idempotency: 'safe',
      body: { bindingId, ...(reason !== undefined ? { reason } : {}) },
      parse: (v) => revokedResponseSchema.parse(v),
    });
    const current = await this.bindings.load();
    if (current?.bindingId === bindingId) {
      await this.reset();
    }
  }

  async listConsents(): Promise<ConsentListItem[]> {
    const body = await this.authed({
      method: 'GET',
      path: ENDPOINTS.consents,
      idempotency: 'safe',
      parse: (v) => consentsResponseSchema.parse(v),
    });
    return body.consents;
  }

  async revokeConsent(consentId: string): Promise<void> {
    await this.authed({
      method: 'POST',
      path: ENDPOINTS.revokeConsent,
      idempotency: 'safe',
      body: { consentId },
      parse: (v) => revokedResponseSchema.parse(v),
    });
  }

  async activity(): Promise<ActivityItem[]> {
    const body = await this.authed({
      method: 'GET',
      path: ENDPOINTS.activity,
      idempotency: 'safe',
      parse: (v) => activityResponseSchema.parse(v),
    });
    return body.events;
  }

  // ── Local state ───────────────────────────────────────────────────────────

  async currentBinding(): Promise<PersistedBinding | null> {
    return this.bindings.load();
  }

  async isEnrolled(): Promise<boolean> {
    return (await this.bindings.load()) !== null;
  }

  /** Drop the session, the stored binding, and the hardware key. */
  async reset(): Promise<void> {
    this.session = null;
    const current = await this.bindings.load();
    await this.bindings.clear();
    // Best effort: a keystore that cannot delete must not block the citizen
    // from re-enrolling, and the key is useless without a live binding anyway.
    try {
      await this.opts.keyStore.delete(current?.keyAlias ?? this.keyAlias);
    } catch {
      /* ignore */
    }
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  private async requireBinding(): Promise<PersistedBinding> {
    const binding = await this.bindings.load();
    if (!binding) throw MobileError.local('not_enrolled');
    return binding;
  }

  /**
   * Rebuild the canonical payload and require the broker's to match exactly
   * before we let the hardware key touch it. See the class comment.
   */
  private expectPayload(
    purpose: Parameters<typeof buildChallengePayload>[0],
    challengeId: string,
    nonce: string,
    given: string,
  ): string {
    const expected = buildChallengePayload(purpose, challengeId, nonce);
    if (expected !== given) {
      throw MobileError.local('unexpected_response', { detail: 'challenge_payload_mismatch' });
    }
    return expected;
  }

  /** Every signature goes through the biometric-gated key (05 §3, T1). */
  private async sign(payload: string, prompt: SignPromptSpec): Promise<string> {
    try {
      return await this.opts.keyStore.sign(this.keyAlias, payload, prompt);
    } catch (error) {
      throw toMobileError(error);
    }
  }

  /** Reuse a live session, otherwise log in. */
  private async ensureSession(): Promise<string> {
    const live = this.session;
    if (live && live.expiresAtMs - SESSION_SKEW_MS > this.clock.now()) return live.token;
    this.session = null;
    return this.login();
  }

  /**
   * Authenticated backchannel call.
   *
   * A 401 `access_denied` means the session JWT is gone/expired — re-login
   * once and repeat. A 401 `binding_not_active` means the binding was revoked
   * (06 §4 — the guard re-checks it on every request), which is terminal: wipe
   * local state so the app cannot keep pretending it is enrolled.
   *
   * The retry after re-login is only attempted for `safe` calls. A
   * `consumes-nonce` call cannot be repeated (its challenge is spent), so its
   * error surfaces to the citizen instead.
   */
  private async authed<T>(spec: CallSpec<T>): Promise<T> {
    const token = await this.ensureSession();
    try {
      return await this.call({ ...spec, bearer: token });
    } catch (error) {
      const err = toMobileError(error);
      if (err.terminalForBinding) {
        await this.reset();
        throw err;
      }
      if (err.code === 'access_denied' && err.httpStatus === 401 && spec.idempotency === 'safe') {
        this.session = null;
        const fresh = await this.ensureSession();
        return this.call({ ...spec, bearer: fresh });
      }
      throw err;
    }
  }

  private async call<T>(spec: CallSpec<T>): Promise<T> {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (spec.body !== undefined) headers['content-type'] = 'application/json';
    if (spec.bearer) headers['authorization'] = `Bearer ${spec.bearer}`;

    const response = await sendWithRetry({
      transport: this.opts.transport,
      idempotency: spec.idempotency,
      ...(this.opts.retry ? { policy: this.opts.retry } : { policy: DEFAULT_RETRY }),
      request: {
        method: spec.method,
        url: this.baseUrl + spec.path,
        headers,
        ...(spec.body !== undefined ? { body: JSON.stringify(spec.body) } : {}),
        timeoutMs: this.timeoutMs,
      },
    });

    if (response.status < 200 || response.status >= 300) {
      // Parse leniently: a proxy or gateway may return HTML, in which case the
      // code is `unknown` and the citizen gets a generic message (03 §7).
      throw MobileError.fromBrokerBody(safeJson(response.body), response.status);
    }

    const parsed = response.body.length > 0 ? safeJson(response.body) : {};
    if (parsed === undefined) {
      throw MobileError.local('unexpected_response', { detail: 'non_json_body' });
    }
    try {
      return spec.parse(parsed);
    } catch (error) {
      // A zod failure here means broker/app version skew. Never surface the
      // issue paths to the citizen — they can name fields (03 §7).
      throw MobileError.local('unexpected_response', {
        detail: `schema:${spec.path}`,
        cause: error,
      });
    }
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}
