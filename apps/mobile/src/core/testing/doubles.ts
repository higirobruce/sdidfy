/**
 * ⚠ DEV / TEST ONLY — never bundle into a release build (see webcrypto-keystore.ts).
 *
 * Test doubles for the three device-side seams: attestation, face capture and
 * the biometric prompt, plus a scriptable HTTP transport. They mirror the
 * simulator's mock shapes (apps/device-sim) so the same broker accepts them in
 * `ATTESTATION_MODE=mock`, but they live behind the production interfaces.
 */
import { mockBiometricBytes } from '@sdid/shared';
import type { AttestInput, Attestation, AttestationPlatform } from '../attestation.js';
import type {
  BiometricCapabilities,
  BiometricConfirmSpec,
  BiometricPrompt,
  EnrolmentSample,
  FaceCapture,
  FaceCaptureOptions,
} from '../biometrics.js';
import { MobileError } from '../errors.js';
import {
  TransportFailure,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
} from '../transport.js';
import type { AttestationPayload, BiometricSampleDto } from '../wire.js';

// ── Attestation ─────────────────────────────────────────────────────────────

/**
 * Emits the same `platform: 'sim'` structured token `SimDevice.mockAttestation`
 * emits, with the broker's nonce embedded INSIDE the token — the production
 * shape, where Play Integrity / App Attest bind the nonce under the platform
 * signature (runbook §10).
 */
export class MockAttestation implements Attestation {
  constructor(private readonly claims: Record<string, unknown> = {}) {}

  platform(): AttestationPlatform {
    return 'sim';
  }

  async attest(input: AttestInput): Promise<Omit<AttestationPayload, 'nonceId'>> {
    const claims = {
      mock: true,
      deviceIntegrity: true,
      appIntegrity: true,
      hardwareBackedKey: true,
      nonce: input.nonce,
      ...this.claims,
    };
    return {
      platform: 'sim',
      token: Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url'),
      keyAttestation: input.keyAttestation ?? 'mock-key-attestation-v1',
    };
  }
}

/** An attestation provider whose platform refuses to produce a token at all. */
export class UnavailableAttestation implements Attestation {
  platform(): AttestationPlatform {
    return 'sim';
  }

  async attest(): Promise<never> {
    throw MobileError.local('attestation_failed_local', { detail: 'test_double' });
  }
}

// ── Face capture ────────────────────────────────────────────────────────────

/**
 * Produces the deterministic sample the MOCK SDID matches against
 * (packages/shared mock-biometrics). It exists so the enrolment path is
 * exercisable end-to-end offline; it is not a capture implementation and has
 * no liveness of any kind.
 */
export class MockFaceCapture implements FaceCapture {
  readonly captured: MockEnrolmentSample[] = [];
  /** Set to make the next capture behave as if the citizen backed out. */
  cancelNext = false;

  constructor(
    private readonly nid: string,
    private readonly livenessScore = 0.97,
  ) {}

  async capture(_options: FaceCaptureOptions): Promise<EnrolmentSample> {
    if (this.cancelNext) {
      this.cancelNext = false;
      throw MobileError.local('biometric_cancelled', { detail: 'test_double' });
    }
    const sample = new MockEnrolmentSample(
      Uint8Array.from(mockBiometricBytes(this.nid, 'face')),
      this.livenessScore,
    );
    this.captured.push(sample);
    return sample;
  }
}

export class MockEnrolmentSample implements EnrolmentSample {
  private disposed = false;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly livenessScore: number,
  ) {}

  toDto(): BiometricSampleDto {
    if (this.disposed) {
      throw MobileError.local('unknown', { detail: 'sample_used_after_dispose' });
    }
    return {
      modality: 'face',
      data: Buffer.from(this.bytes).toString('base64'),
      liveness: { method: 'active-blink', score: this.livenessScore },
    };
  }

  /** Zeroes the buffer, exactly as a native implementation must (07 §1). */
  dispose(): void {
    this.bytes.fill(0);
    this.disposed = true;
  }

  get isDisposed(): boolean {
    return this.disposed;
  }
}

// ── Biometric prompt ────────────────────────────────────────────────────────

export class MockBiometricPrompt implements BiometricPrompt {
  confirmations = 0;

  constructor(
    private readonly caps: BiometricCapabilities = {
      available: true,
      enrolled: true,
      strong: true,
      kinds: ['face', 'fingerprint'],
    },
    private readonly confirmResult = true,
  ) {}

  async capabilities(): Promise<BiometricCapabilities> {
    return this.caps;
  }

  async confirm(_spec: BiometricConfirmSpec): Promise<boolean> {
    this.confirmations += 1;
    return this.confirmResult;
  }
}

// ── Transport ───────────────────────────────────────────────────────────────

export type RouteHandler = (
  request: HttpRequest,
  body: unknown,
) => HttpResponse | Promise<HttpResponse>;

/**
 * Scriptable transport. Routes are keyed `"<METHOD> <path>"`; a route may be a
 * single handler or a queue consumed one call at a time (for retry tests).
 */
export class FakeTransport implements HttpTransport {
  readonly pinned: boolean;
  readonly requests: { request: HttpRequest; body: unknown }[] = [];
  private readonly routes = new Map<string, RouteHandler[]>();

  constructor(options: { pinned?: boolean } = {}) {
    this.pinned = options.pinned ?? true;
  }

  /** Register (or append to) the queue for a route. */
  on(method: 'GET' | 'POST', path: string, handler: RouteHandler): this {
    const key = `${method} ${path}`;
    const queue = this.routes.get(key) ?? [];
    queue.push(handler);
    this.routes.set(key, queue);
    return this;
  }

  /** Convenience: always answer this route with a 200 + JSON body. */
  json(method: 'GET' | 'POST', path: string, value: unknown, status = 200): this {
    return this.on(method, path, () => ({ status, body: JSON.stringify(value) }));
  }

  /** Convenience: answer with a broker-style error body. */
  fail(method: 'GET' | 'POST', path: string, status: number, code: string): this {
    return this.on(method, path, () => ({
      status,
      body: JSON.stringify({ error: code, error_description: 'server prose the app must not show' }),
    }));
  }

  /** Convenience: fail at the transport layer (no HTTP response at all). */
  drop(method: 'GET' | 'POST', path: string, kind: 'timeout' | 'unreachable' = 'unreachable'): this {
    return this.on(method, path, () => {
      throw new TransportFailure(kind, 'test double');
    });
  }

  async send(request: HttpRequest): Promise<HttpResponse> {
    const path = new URL(request.url).pathname;
    const key = `${request.method} ${path}`;
    const queue = this.routes.get(key);
    const body = request.body !== undefined ? (JSON.parse(request.body) as unknown) : undefined;
    this.requests.push({ request, body });
    if (!queue || queue.length === 0) {
      return { status: 404, body: JSON.stringify({ error: 'invalid_request' }) };
    }
    // The last handler sticks, so a route registered once answers every call.
    const handler = queue.length > 1 ? queue.shift()! : queue[0]!;
    return handler(request, body);
  }

  /** Count of calls made to a route. */
  countOf(method: 'GET' | 'POST', path: string): number {
    return this.requests.filter(
      (r) => r.request.method === method && new URL(r.request.url).pathname === path,
    ).length;
  }

  lastBody(method: 'GET' | 'POST', path: string): unknown {
    const matching = this.requests.filter(
      (r) => r.request.method === method && new URL(r.request.url).pathname === path,
    );
    return matching[matching.length - 1]?.body;
  }
}

/** A clock the test drives by hand. */
export class FakeClock {
  constructor(private ms: number) {}

  now(): number {
    return this.ms;
  }

  advance(ms: number): void {
    this.ms += ms;
  }
}
