/**
 * SimDevice — simulated citizen phone (SPEC 05, Phase 0–2 stand-in).
 *
 * Simulates the security-relevant behaviour of the mobile authenticator:
 * - a non-exportable ECDSA P-256 keypair (Secure Enclave / StrongBox stand-in,
 *   05 §3): the private key is generated with extractable=false;
 * - every signing operation is gated through a biometric unlock (T1);
 * - mock biometric capture derived from the shared mockBiometricBytes so the
 *   mock SDID matches deterministically (02 §2), with impostor/spoof/corrupt
 *   overrides for negative tests;
 * - mock device/app attestation (05 §4) with overrides (e.g. rooted device);
 * - the full enrolment (03 §2), direct-login and CIBA approval (04 §3)
 *   protocols against the broker HTTP API.
 */
import { webcrypto } from 'node:crypto';
import {
  buildChallengePayload,
  mockBiometricBytes,
  type AssuranceLevel,
  type DeviceListItem,
  type EnrolActivateRequest,
  type EnrolStartRequest,
  type IssuedChallenge,
  type LoginRequest,
  type PendingTransaction,
  enrolActivateResponseSchema,
  enrolStartResponseSchema,
  loginResponseSchema,
  pendingTransactionsResponseSchema,
} from '@sdid/shared';

export interface SimDeviceOptions {
  /** Broker base URL, e.g. http://localhost:3100 */
  brokerUrl: string;
  /** 16-digit NID of the citizen this device belongs to. */
  nid: string;
  deviceLabel?: string;
  /**
   * When false the device biometric is "unavailable" and every attempt to use
   * the (biometric-gated) private key throws — simulates a locked-out sensor.
   */
  biometricAvailable?: boolean;
}

export interface BiometricSampleDto {
  modality: 'face' | 'fingerprint';
  data: string;
  liveness: { method: string; score: number };
}

export interface CaptureOverrides {
  /** Derive the sample from a different NID — simulates an impostor. */
  impostorNid?: string;
  /** Presentation attack: liveness score drops to 0.2. */
  spoof?: boolean;
  /** Flip exactly n bytes of the capture — simulates a corrupted sample. */
  corruptBytes?: number;
}

export interface MockAttestationDto {
  platform: 'sim';
  token: string;
  keyAttestation: string;
}

export interface AttestationClaimOverrides {
  mock?: boolean;
  deviceIntegrity?: boolean;
  appIntegrity?: boolean;
  hardwareBackedKey?: boolean;
  [claim: string]: unknown;
}

export interface EnrolOptions {
  sampleOverrides?: CaptureOverrides;
  attestationOverrides?: AttestationClaimOverrides;
}

export interface EnrolResult {
  bindingId: string;
  assuranceLevel: AssuranceLevel;
}

export interface DecideOptions {
  /** "I didn't request this" flag on deny (05 §2 help/report path). */
  reportSuspicious?: boolean;
}

export interface DecisionResult {
  status: string;
}

export interface PublicKeyJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

const { subtle } = webcrypto;

export class SimDevice {
  readonly brokerUrl: string;
  readonly nid: string;
  readonly deviceLabel: string;
  readonly biometricAvailable: boolean;

  bindingId?: string;
  assuranceLevel?: AssuranceLevel;
  sessionToken?: string;

  /** Keypair generation is async; started in the constructor, awaited on use. */
  private readonly keyPairPromise: Promise<webcrypto.CryptoKeyPair>;

  constructor(options: SimDeviceOptions) {
    this.brokerUrl = options.brokerUrl.replace(/\/+$/, '');
    this.nid = options.nid;
    this.deviceLabel = options.deviceLabel ?? 'Simulated Device';
    this.biometricAvailable = options.biometricAvailable ?? true;
    // extractable: FALSE — the private key can never leave the "enclave"
    // (05 §3: keys non-exportable). The public key is always exportable.
    this.keyPairPromise = subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);
  }

  /** Export the public key as the minimal JWK the enrolment DTO expects. */
  async publicKeyJwk(): Promise<PublicKeyJwk> {
    const { publicKey } = await this.keyPairPromise;
    const jwk = await subtle.exportKey('jwk', publicKey);
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      throw new Error('unexpected public key JWK shape');
    }
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  /**
   * Sign a challenge payload: ECDSA P-256 / SHA-256 over the exact UTF-8
   * bytes, returned as base64url of the raw (r||s) signature — the wire form
   * the challenge protocol expects (packages/shared protocol.ts).
   * Every signature goes through the biometric gate first (T1).
   */
  async sign(payload: string): Promise<string> {
    this.biometricUnlock();
    const { privateKey } = await this.keyPairPromise;
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      Buffer.from(payload, 'utf8'),
    );
    return Buffer.from(signature).toString('base64url');
  }

  /**
   * Simulated biometric-gated key access: on a real device every signing op
   * requires a fresh biometric unlock (05 §3). Here it throws when the
   * device was constructed with biometricAvailable: false.
   */
  private biometricUnlock(): void {
    if (!this.biometricAvailable) {
      throw new Error(
        'biometric unlock failed: biometric unavailable on this device (key access is biometric-gated)',
      );
    }
  }

  /**
   * Mock biometric capture (02 §2): the genuine sample is derived from the
   * device's NID so the mock SDID's reference matches deterministically.
   */
  captureBiometric(overrides?: CaptureOverrides): BiometricSampleDto {
    const sourceNid = overrides?.impostorNid ?? this.nid;
    const bytes = Uint8Array.from(mockBiometricBytes(sourceNid, 'face'));
    const corrupt = overrides?.corruptBytes ?? 0;
    for (let i = 0; i < corrupt && i < bytes.length; i++) {
      bytes[i] = bytes[i]! ^ 0xff;
    }
    return {
      modality: 'face',
      data: Buffer.from(bytes).toString('base64'),
      liveness: {
        method: 'active-blink',
        score: overrides?.spoof ? 0.2 : 0.97,
      },
    };
  }

  /**
   * Mock device/app attestation (05 §4). Overrides simulate failure modes,
   * e.g. { deviceIntegrity: false } for a rooted device.
   */
  mockAttestation(overrides?: AttestationClaimOverrides): MockAttestationDto {
    const claims = {
      mock: true,
      deviceIntegrity: true,
      appIntegrity: true,
      hardwareBackedKey: true,
      ...overrides,
    };
    return {
      platform: 'sim',
      token: Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url'),
      keyAttestation: 'mock-key-attestation-v1',
    };
  }

  /** Full enrolment (03 §2): start → sign activation challenge → activate. */
  async enrol(opts?: EnrolOptions): Promise<EnrolResult> {
    const startBody: EnrolStartRequest = {
      nid: this.nid,
      devicePublicKeyJwk: await this.publicKeyJwk(),
      attestation: this.mockAttestation(opts?.attestationOverrides),
      deviceLabel: this.deviceLabel,
      sample: this.captureBiometric(opts?.sampleOverrides),
    };
    const start = enrolStartResponseSchema.parse(
      await this.request('POST', '/v1/enrol/start', startBody),
    );

    const activateBody: EnrolActivateRequest = {
      bindingId: start.bindingId,
      challengeId: start.activationChallenge.challengeId,
      signature: await this.sign(start.activationChallenge.payload),
    };
    const activated = enrolActivateResponseSchema.parse(
      await this.request('POST', '/v1/enrol/activate', activateBody),
    );

    this.bindingId = activated.bindingId;
    this.assuranceLevel = start.assuranceLevel;
    return { bindingId: activated.bindingId, assuranceLevel: start.assuranceLevel };
  }

  /** Direct first-party login (01 §2.2): challenge → sign → session token. */
  async login(): Promise<string> {
    const bindingId = this.requireBindingId();
    const challenge = (await this.request('POST', '/v1/device/login/challenge', {
      bindingId,
    })) as IssuedChallenge;

    const loginBody: LoginRequest = {
      bindingId,
      challengeId: challenge.challengeId,
      signature: await this.sign(challenge.payload),
    };
    const login = loginResponseSchema.parse(
      await this.request('POST', '/v1/device/login', loginBody),
    );
    this.sessionToken = login.sessionToken;
    return login.sessionToken;
  }

  /** Pull pending CIBA transactions over the authenticated backchannel (04 §3 step 5). */
  async pullPending(): Promise<PendingTransaction[]> {
    const body = await this.authedRequest('GET', '/v1/device/ciba/pending');
    return pendingTransactionsResponseSchema.parse(body).transactions;
  }

  /**
   * Approve or deny a pending CIBA transaction (04 §3 steps 5–8): find it,
   * sign the matching challenge payload with the biometric-gated key, submit.
   */
  async decide(
    authReqId: string,
    decision: 'approve' | 'deny',
    opts?: DecideOptions,
  ): Promise<DecisionResult> {
    const pending = await this.pullPending();
    const txn = pending.find((t) => t.authReqId === authReqId);
    if (!txn) {
      throw new Error(`no pending transaction with authReqId ${authReqId}`);
    }
    return this.submitDecision(txn, decision, opts);
  }

  /** Convenience for tests/demos: approve the oldest pending transaction. */
  async approveFirstPending(): Promise<DecisionResult & { authReqId: string }> {
    const pending = await this.pullPending();
    const txn = pending[0];
    if (!txn) {
      throw new Error('no pending transactions');
    }
    const result = await this.submitDecision(txn, 'approve');
    return { ...result, authReqId: txn.authReqId };
  }

  private async submitDecision(
    txn: PendingTransaction,
    decision: 'approve' | 'deny',
    opts?: DecideOptions,
  ): Promise<DecisionResult> {
    const payload = decision === 'approve' ? txn.challenge.approvePayload : txn.challenge.denyPayload;
    const body = {
      authReqId: txn.authReqId,
      bindingId: this.requireBindingId(),
      challengeId: txn.challenge.challengeId,
      decision,
      signature: await this.sign(payload),
      ...(opts?.reportSuspicious !== undefined ? { reportSuspicious: opts.reportSuspicious } : {}),
    };
    return (await this.authedRequest('POST', '/v1/device/ciba/decision', body)) as DecisionResult;
  }

  async listBindings(): Promise<DeviceListItem[]> {
    const body = (await this.authedRequest('GET', '/v1/device/bindings')) as
      | DeviceListItem[]
      | { devices: DeviceListItem[] };
    return Array.isArray(body) ? body : body.devices;
  }

  async revokeBinding(bindingId: string, reason?: string): Promise<unknown> {
    return this.authedRequest('POST', '/v1/device/bindings/revoke', {
      bindingId,
      ...(reason !== undefined ? { reason } : {}),
    });
  }

  async listConsents(): Promise<unknown> {
    return this.authedRequest('GET', '/v1/device/consents');
  }

  async activity(): Promise<unknown> {
    return this.authedRequest('GET', '/v1/device/activity');
  }

  private requireBindingId(): string {
    if (!this.bindingId) {
      throw new Error('device is not enrolled: call enrol() first');
    }
    return this.bindingId;
  }

  /** Authenticated backchannel call; logs in first when no session is held. */
  private async authedRequest(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown> {
    if (!this.sessionToken) {
      await this.login();
    }
    return this.request(method, path, body, this.sessionToken);
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    bearer?: string,
  ): Promise<unknown> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (bearer) headers['authorization'] = `Bearer ${bearer}`;
    const res = await fetch(this.brokerUrl + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${method} ${path}: ${text}`);
    }
    return text ? (JSON.parse(text) as unknown) : {};
  }
}

// Re-export the payload builder so consumers of the sim can reconstruct
// expected payloads in tests without importing @sdid/shared directly.
export { buildChallengePayload };
