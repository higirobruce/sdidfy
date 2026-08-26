import { randomInt } from 'node:crypto';
import { z } from 'zod';
import {
  ASSURANCE_LEVELS,
  type AttributeSet,
  type BiometricModality,
  type ReassertResult,
  type ReferenceBiometricResult,
  type SdidProvider,
} from '@sdid/shared';
import {
  SdidCircuitOpenError,
  SdidConfigurationError,
  SdidMalformedResponseError,
  SdidTimeoutError,
  SdidUnknownIdentityError,
} from './errors.js';

/** Resilience wrapper knobs (spec 02 §4). Defaults are production values. */
export interface ResilienceOptions {
  /** Per-call timeout applied to every attempt. */
  timeoutMs?: number;
  /** Retries after the first attempt. All three methods are idempotent reads. */
  retries?: number;
  /** Base for exponential-backoff-with-full-jitter between attempts. */
  retryBaseDelayMs?: number;
  /** Consecutive attempt failures that open the circuit. */
  breakerFailureThreshold?: number;
  /** Time the circuit stays open before a half-open probe is allowed. */
  breakerResetMs?: number;
}

const DEFAULTS = {
  timeoutMs: 5000,
  retries: 2,
  retryBaseDelayMs: 100,
  breakerFailureThreshold: 5,
  breakerResetMs: 30_000,
} as const;

export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Consecutive-failure circuit breaker. Opens after `threshold` consecutive
 * attempt failures; after `resetMs` a single half-open probe is allowed —
 * probe success closes the circuit, probe failure re-opens it.
 */
export class CircuitBreaker {
  private internal: CircuitState = 'closed';
  private consecutiveFailures = 0;
  private openedAt = 0;
  private probeInFlight = false;

  constructor(
    private readonly threshold: number,
    private readonly resetMs: number,
  ) {}

  get state(): CircuitState {
    if (this.internal === 'open' && Date.now() - this.openedAt >= this.resetMs) {
      return 'half-open';
    }
    return this.internal;
  }

  /** Gate an attempt; throws SdidCircuitOpenError when the circuit rejects it. */
  beforeAttempt(): void {
    const s = this.state;
    if (s === 'open') throw new SdidCircuitOpenError();
    if (s === 'half-open') {
      if (this.probeInFlight) throw new SdidCircuitOpenError();
      this.internal = 'half-open';
      this.probeInFlight = true;
    }
  }

  onSuccess(): void {
    this.internal = 'closed';
    this.consecutiveFailures = 0;
    this.probeInFlight = false;
  }

  onFailure(): void {
    this.probeInFlight = false;
    if (this.internal === 'half-open') {
      this.trip();
      return;
    }
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= this.threshold) this.trip();
  }

  private trip(): void {
    this.internal = 'open';
    this.openedAt = Date.now();
    this.consecutiveFailures = 0;
  }
}

// --- Boundary validation (02 §4): a malformed strategy response never
// --- reaches the broker. Values are never echoed into errors — issue paths
// --- and codes only (a received value could be identity data).
const nonEmptyString = z.string().min(1);

const referenceResultSchema = z.object({
  reference: z.object({
    modality: z.enum(['face', 'fingerprint']),
    data: z
      .instanceof(Uint8Array)
      .refine((d) => d.byteLength > 0, { message: 'empty biometric reference' }),
    format: z.enum(['iso-19794', 'jpeg2000', 'mock']),
  }),
  sdidSubject: nonEmptyString,
  txnRef: nonEmptyString,
});

const attributeSetSchema = z
  .object({
    name: nonEmptyString.optional(),
    dateOfBirth: nonEmptyString.optional(),
    address: nonEmptyString.optional(),
    faceReferenceAvailable: z.boolean().optional(),
  })
  .strict();

const reassertResultSchema = z.object({
  valid: z.boolean(),
  assurance: z.enum(ASSURANCE_LEVELS),
  txnRef: nonEmptyString,
});

function validateBoundary(schema: z.ZodTypeAny, value: unknown): void {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`)
      .join('; ');
    throw new SdidMalformedResponseError(detail);
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new SdidTimeoutError(timeoutMs)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Full jitter: uniform in [0, base * 2^(attempt-1)]. */
function jitteredDelayMs(baseMs: number, attempt: number): number {
  const cap = Math.max(1, baseMs * 2 ** (attempt - 1));
  return randomInt(0, cap + 1);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Resilience wrapper around any SdidProvider strategy (spec 02 §4):
 * per-attempt timeout, retry with jitter (idempotent reads only — a
 * definitive SdidUnknownIdentityError is never retried), a consecutive-failure
 * circuit breaker, and zod validation of every strategy output.
 */
export class ResilientSdidProvider implements SdidProvider {
  readonly breaker: CircuitBreaker;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryBaseDelayMs: number;

  constructor(
    private readonly inner: SdidProvider,
    opts: ResilienceOptions = {},
  ) {
    this.timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
    this.retries = opts.retries ?? DEFAULTS.retries;
    this.retryBaseDelayMs = opts.retryBaseDelayMs ?? DEFAULTS.retryBaseDelayMs;
    this.breaker = new CircuitBreaker(
      opts.breakerFailureThreshold ?? DEFAULTS.breakerFailureThreshold,
      opts.breakerResetMs ?? DEFAULTS.breakerResetMs,
    );
  }

  /** Exposed for tests / health reporting. */
  get circuitState(): CircuitState {
    return this.breaker.state;
  }

  getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult> {
    return this.execute(referenceResultSchema, () => this.inner.getReferenceBiometric(input));
  }

  getAttributes(idOrSubject: string, scopes: string[]): Promise<AttributeSet> {
    return this.execute(attributeSetSchema, () => this.inner.getAttributes(idOrSubject, scopes));
  }

  reassert(idOrSubject: string): Promise<ReassertResult> {
    return this.execute(reassertResultSchema, () => this.inner.reassert(idOrSubject));
  }

  private async execute<T>(schema: z.ZodTypeAny, attempt: () => Promise<T>): Promise<T> {
    let lastError: unknown;
    for (let n = 0; n <= this.retries; n += 1) {
      if (n > 0) await sleep(jitteredDelayMs(this.retryBaseDelayMs, n));
      this.breaker.beforeAttempt(); // throws immediately when open — no retry past an open circuit
      try {
        const result = await withTimeout(attempt(), this.timeoutMs);
        validateBoundary(schema, result);
        this.breaker.onSuccess();
        return result;
      } catch (err) {
        if (err instanceof SdidConfigurationError) {
          // An unfilled A1/A2 integration gap (02 §3) is our misconfiguration,
          // not an SDID fault: retrying cannot fix it and tripping the breaker
          // would mislabel a deployment bug as an outage. Surface it at once.
          throw err;
        }
        if (err instanceof SdidUnknownIdentityError) {
          // A definitive negative answer: the service is up (resets the
          // breaker) and retrying an idempotent read cannot change it.
          this.breaker.onSuccess();
          throw err;
        }
        this.breaker.onFailure();
        lastError = err;
      }
    }
    throw lastError;
  }
}
