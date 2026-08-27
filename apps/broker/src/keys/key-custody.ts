/**
 * The signing-key custody boundary (06 §3, 07 §5, T13; spec open decision #5).
 *
 * ===========================================================================
 * THE ONE CONSTRAINT THAT SHAPES THIS FILE: SIGN-AS-A-SERVICE
 * ===========================================================================
 * The spec says broker signing keys "never sit in app memory as plaintext"
 * (01 §3) and "never leave the boundary in plaintext" (06 §3). So this
 * interface deliberately has NO `getPrivateKey(kid)`, no `exportKey`, no
 * `KeyLike` accessor, and no way to obtain key material by any name. The
 * custody boundary PERFORMS the signature and returns only the signature
 * bytes. Anything else would be unimplementable against a real KMS or an
 * on-prem HSM — a PKCS#11 token will not hand you a private key, and a KMS
 * that would is not one we should be using — and, worse, it would let the
 * broker keep doing exactly what T13 says it must stop doing while the
 * codebase *looked* like it had solved the problem.
 *
 * Practical consequence, called out here because it surprises people:
 * `jose.SignJWT(...).sign(key)` cannot be used any more. It requires a local
 * `KeyLike` and has no path to a remote signer. JWS compact serialisation is
 * assembled by hand instead (see `KeysService.signCompactJws`):
 *
 *     signingInput = base64url(header) + "." + base64url(payload)
 *     signature    = custody.sign(kid, utf8(signingInput))
 *     token        = signingInput + "." + base64url(signature)
 *
 * `jose` is still used for VERIFICATION, which only ever needs public keys.
 *
 * ===========================================================================
 * WHAT A PROVIDER MUST GUARANTEE
 * ===========================================================================
 *  1. **No private material crosses this interface.** Not in a return value,
 *     not in an error message, not in a log line, not in a health detail.
 *  2. **`sign()` returns a JWS-form signature**, i.e. for ES256 the raw
 *     64-byte `r || s` concatenation of RFC 7515 §3.4 — NOT the DER
 *     `SEQUENCE { INTEGER r, INTEGER s }` that most KMS and virtually every
 *     PKCS#11 token actually produce. That conversion belongs in the
 *     provider, next to the backend that produced the DER; `normalizeEcdsaSignature()`
 *     below is the shared helper. A provider that returns DER produces tokens
 *     that every relying party rejects, which is a very expensive way to find
 *     out about a missing four lines.
 *  3. **`sign()` hashes internally per the algorithm.** Callers pass the
 *     signing input BYTES, never a digest. (KMS APIs differ here: some take a
 *     digest, some take the message. The provider owns that difference.)
 *  4. **`listPublicJwks()` returns PUBLIC material only**, for every key that
 *     may have signed a still-live token — active *and* retired. That overlap
 *     is what makes rotation non-breaking (06 §3), so a provider that returns
 *     only the active key has silently broken every token minted in the last
 *     rotation window.
 *  5. **`healthCheck()` answers "can this replica sign RIGHT NOW"**, reaching
 *     the backend rather than reading a cached flag. This is what takes a
 *     replica with an expired KMS credential or an unreachable HSM out of the
 *     load-balancer rotation instead of failing citizens' logins.
 *  6. **Failure is loud.** Unconfigured is `KeyCustodyNotConfiguredError`,
 *     unreachable is `KeyCustodyUnavailableError`, a rejected signature is
 *     `KeyCustodySigningError`. None of them may be reported as "there is no
 *     key" — "we cannot reach the HSM" and "this deployment has no keys" lead
 *     to opposite operator actions, and conflating them is how an outage gets
 *     mistaken for a first boot and "fixed" by generating a fresh key.
 *  7. **Rotation is honest.** A provider that cannot rotate programmatically
 *     sets `capabilities.rotate = false` AND throws
 *     `KeyCustodyRotationUnsupportedError` from `rotate()`. It must never
 *     no-op successfully: a rotation that silently did nothing is the worst
 *     possible outcome of a scheduled key-rotation job, because the alerting
 *     says it succeeded.
 */

/** Algorithms the broker will sign with. ES256 only, per 04 §4. */
export const SIGNING_ALGS = ['ES256'] as const;
export type SigningAlg = (typeof SIGNING_ALGS)[number];

/**
 * Bytes per ECDSA coordinate. The JWS signature is exactly twice this
 * (`r || s`, each left-padded to this width) — RFC 7515 §3.4.
 */
export const ALG_COORDINATE_BYTES: Record<SigningAlg, number> = { ES256: 32 };

/** Which custody boundary this deployment runs. Mirrors `KEY_CUSTODY`. */
export type KeyCustodyProvider = 'postgres-dev' | 'kms' | 'hsm';

/** `active` signs; `retired` still verifies (JWKS overlap, 06 §3). */
export type SigningKeyStatus = 'active' | 'retired';

/**
 * Public JWK. Structurally assignable to `jose.JWK`, so a `PublicJwks` can be
 * handed straight to `jose.createLocalJWKSet` without a cast — but declared
 * here rather than imported so the custody contract does not depend on the
 * JOSE library a provider may not use.
 *
 * There is no private-JWK type in this file. That absence is the control.
 */
export interface PublicJwk {
  kty: string;
  kid: string;
  alg: string;
  use?: string;
  crv?: string;
  x?: string;
  y?: string;
  [propName: string]: unknown;
}

export interface PublicJwks {
  keys: PublicJwk[];
}

/** What custody knows about a key WITHOUT touching its private half. */
export interface SigningKeyDescriptor {
  kid: string;
  alg: SigningAlg;
  status: SigningKeyStatus;
  /** When the key came into existence, as far as the backend can report it. */
  createdAt: Date;
}

/** Result of `healthCheck()`. `detail` is operator-facing, never secret-bearing. */
export interface CustodyHealth {
  healthy: boolean;
  provider: KeyCustodyProvider;
  /** null means "no active key" — a DISTINCT condition from `healthy=false`. */
  activeKid: string | null;
  detail: string;
}

/** Outcome of a promote-and-retire cycle. */
export interface RotationResult {
  /** The new active key. */
  promotedKid: string;
  /** Keys that stopped signing. They stay in the JWKS for overlap. */
  retiredKids: string[];
  alg: SigningAlg;
}

/**
 * What a provider can actually do. Declared rather than inferred so callers
 * (and the runbook) can distinguish "rotation is a `rotate()` call" from
 * "rotation is a ticket to the HSM custodians".
 */
export interface KeyCustodyCapabilities {
  /** `rotate()` works. When false it MUST throw, never silently no-op. */
  readonly rotate: boolean;
  /** The provider will create a key when none exists (dev convenience only). */
  readonly generateOnDemand: boolean;
}

/**
 * Key lifecycle events, surfaced so the owning service can audit them
 * (T13 "key-usage audit"). Reported by the provider because only the provider
 * knows when its backend actually did the thing.
 */
export type CustodyEventType = 'key_generated' | 'key_promoted' | 'key_retired';

export interface CustodyEvent {
  type: CustodyEventType;
  kid: string;
  alg: SigningAlg;
  provider: KeyCustodyProvider;
  /** Bounded, non-secret extras for the audit context. */
  detail?: Record<string, unknown>;
}

export type CustodyEventListener = (event: CustodyEvent) => void;

// ---------------------------------------------------------------------------
// Errors. Distinct classes because they demand distinct operator actions, and
// because none of them may be mistaken for "this deployment has no keys".
// ---------------------------------------------------------------------------

/** The custody backend cannot be used right now. Readiness must fail. */
export class KeyCustodyUnavailableError extends Error {
  constructor(
    readonly provider: KeyCustodyProvider,
    message: string,
  ) {
    super(message);
    this.name = 'KeyCustodyUnavailableError';
  }
}

/**
 * The deployment never supplied what this provider needs. Its own class so an
 * operator can tell a missing configuration from an outage — and so nothing
 * downstream can treat it as "no key yet" and helpfully generate one.
 */
export class KeyCustodyNotConfiguredError extends KeyCustodyUnavailableError {
  constructor(provider: KeyCustodyProvider, message: string) {
    super(provider, message);
    this.name = 'KeyCustodyNotConfiguredError';
  }
}

/** The backend was reachable and refused (or fumbled) this signature. */
export class KeyCustodySigningError extends Error {
  constructor(
    readonly provider: KeyCustodyProvider,
    readonly kid: string,
    message: string,
  ) {
    super(message);
    this.name = 'KeyCustodySigningError';
  }
}

/** `rotate()` on a provider whose backend rotates out-of-band. */
export class KeyCustodyRotationUnsupportedError extends Error {
  constructor(provider: KeyCustodyProvider, message: string) {
    super(message);
    this.name = 'KeyCustodyRotationUnsupportedError';
  }
}

// ---------------------------------------------------------------------------
// The interface
// ---------------------------------------------------------------------------

/**
 * The custody boundary. Everything the broker is allowed to know about its
 * signing keys, and nothing more.
 *
 * Lifecycle: `onEvent()` (optional) → `init()` → many `sign()` /
 * `listPublicJwks()` / `healthCheck()` → `close()`.
 */
export interface KeyCustody {
  readonly provider: KeyCustodyProvider;
  readonly capabilities: KeyCustodyCapabilities;

  /**
   * Subscribe to key lifecycle events. Register BEFORE `init()` — first boot
   * of a dev deployment generates a key inside `init()` and that generation
   * has to be auditable. Listeners are synchronous and must not throw.
   */
  onEvent(listener: CustodyEventListener): void;

  /**
   * Reach the backend, discover the keys, and make this instance usable.
   * Throws `KeyCustodyNotConfiguredError` / `KeyCustodyUnavailableError`
   * rather than degrading into a keyless-but-running state.
   */
  init(): Promise<void>;

  /** The kid the broker must sign with. Throws if there is not exactly one. */
  activeKid(): Promise<string>;

  /**
   * PUBLIC material for every key that may have signed a live token, active
   * and retired — this is the `/oidc/jwks` document (06 §3 overlap).
   */
  listPublicJwks(): Promise<PublicJwks>;

  /** Key metadata for operators/tests. Never any private material. */
  listKeys(): Promise<SigningKeyDescriptor[]>;

  /**
   * Sign `data` with `kid` and return the JWS-form signature: for ES256 the
   * raw 64-byte `r || s`, never DER. `data` is the signing input bytes; the
   * provider applies the algorithm's digest itself.
   */
  sign(kid: string, data: Uint8Array): Promise<Uint8Array>;

  /** Can this replica sign right now? Must reach the backend. */
  healthCheck(): Promise<CustodyHealth>;

  /**
   * Promote a fresh key and retire the previous active one, atomically enough
   * that no window exists with zero or two active keys. Retired keys stay in
   * `listPublicJwks()`. Throws `KeyCustodyRotationUnsupportedError` when
   * `capabilities.rotate` is false.
   */
  rotate(): Promise<RotationResult>;

  /** Release backend handles (sessions, pools, PKCS#11 slots). Idempotent. */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// ECDSA signature encoding
// ---------------------------------------------------------------------------

/**
 * DER `SEQUENCE { INTEGER r, INTEGER s }` → JWS `r || s` (RFC 7515 §3.4).
 *
 * Lives here, not in one provider, because EVERY remote signer needs it: AWS
 * KMS, GCP KMS, Azure Key Vault's EC keys, SoftHSM, Thales, Utimaco and
 * essentially all of PKCS#11 `C_Sign` over `CKM_ECDSA`… some return DER, some
 * return raw, and the ones that return DER do not announce it. Getting this
 * wrong produces a signature that is *structurally* valid and *cryptographically*
 * rejected by every relying party, so it is worth a shared, tested function.
 *
 * DER INTEGERs are signed and minimally encoded: a leading 0x00 appears when
 * the high bit of the first content byte is set, and short values are shorter
 * than the coordinate width. Both are handled by trimming then left-padding.
 */
export function derEcdsaToJoseSignature(der: Uint8Array, coordinateBytes: number): Uint8Array {
  const fail = (why: string): never => {
    throw new Error(`not a DER ECDSA signature: ${why}`);
  };
  let i = 0;
  if (der[i++] !== 0x30) fail('missing SEQUENCE tag');
  // Length may be short-form (< 0x80) or long-form (0x81 xx / 0x82 xx xx). A
  // two-coordinate ECDSA signature is never long enough to need more.
  let seqLen = der[i++] ?? fail('truncated length');
  if (seqLen === 0x81) seqLen = der[i++] ?? fail('truncated 0x81 length');
  else if (seqLen === 0x82) {
    const hi = der[i++] ?? fail('truncated 0x82 length');
    const lo = der[i++] ?? fail('truncated 0x82 length');
    seqLen = (hi << 8) | lo;
  } else if (seqLen > 0x82) fail('unsupported long-form length');
  if (i + seqLen !== der.length) fail('declared SEQUENCE length does not match the buffer');

  const readInteger = (): Uint8Array => {
    if (der[i++] !== 0x02) fail('missing INTEGER tag');
    const len = der[i++] ?? fail('truncated INTEGER length');
    if (len === 0 || len > 0x7f) fail('unsupported INTEGER length');
    if (i + len > der.length) fail('INTEGER runs past the buffer');
    const value = der.subarray(i, i + len);
    i += len;
    return value;
  };

  const pad = (value: Uint8Array): Uint8Array => {
    // Drop the sign byte(s) DER adds, then left-pad to the fixed width.
    let start = 0;
    while (start < value.length - 1 && value[start] === 0x00) start += 1;
    const trimmed = value.subarray(start);
    if (trimmed.length > coordinateBytes) {
      throw new Error(
        `ECDSA coordinate is ${trimmed.length} bytes, wider than the ${coordinateBytes}-byte curve`,
      );
    }
    const out = new Uint8Array(coordinateBytes);
    out.set(trimmed, coordinateBytes - trimmed.length);
    return out;
  };

  const r = pad(readInteger());
  const s = pad(readInteger());
  if (i !== der.length) fail('trailing bytes after s');
  const joined = new Uint8Array(coordinateBytes * 2);
  joined.set(r, 0);
  joined.set(s, coordinateBytes);
  return joined;
}

/**
 * Accept whatever the backend produced and return the JWS form.
 *
 * Providers should call this on every signature rather than trusting vendor
 * documentation: the two encodings are trivially distinguishable (a raw
 * signature is exactly `2 * coordinateBytes` and a DER one starts with 0x30
 * and is a different length), so autodetection costs nothing and removes a
 * whole class of "worked in the sandbox" failures.
 */
export function normalizeEcdsaSignature(
  signature: Uint8Array,
  alg: SigningAlg = 'ES256',
): Uint8Array {
  const width = ALG_COORDINATE_BYTES[alg];
  if (signature.length === width * 2) return signature; // already r || s
  if (signature.length > 8 && signature[0] === 0x30) {
    return derEcdsaToJoseSignature(signature, width);
  }
  throw new Error(
    `signature is ${signature.length} bytes: neither raw r||s (${width * 2}) nor DER for ${alg}`,
  );
}

/**
 * Guard applied to every signature before it becomes part of a token. A
 * provider bug that returns the wrong shape must fail the mint, not ship a
 * token that no relying party can verify.
 */
export function assertJwsSignatureShape(signature: Uint8Array, alg: SigningAlg): void {
  const expected = ALG_COORDINATE_BYTES[alg] * 2;
  if (signature.length !== expected) {
    throw new Error(
      `custody returned a ${signature.length}-byte signature; ${alg} JWS requires exactly ` +
        `${expected} bytes of raw r||s (see the DER note in key-custody.ts)`,
    );
  }
}
