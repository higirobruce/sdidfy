/**
 * ⚠ DEV / TEST ONLY — never bundle into a release build.
 *
 * An in-memory `KeyStore` backed by Node/WebCrypto. It reproduces the two
 * properties the vitest suite can actually verify about the real thing:
 *   - the private key is generated with `extractable: false`, so it cannot be
 *     exported (the software analogue of "non-exportable", 05 §3);
 *   - every `sign()` passes through a simulated biometric gate, so a test can
 *     assert one fresh unlock per signature (T1).
 *
 * It reports `securityLevel: 'software'` on purpose — it is not hardware and
 * must never look like it. A test that wants to enrol against it has to pass
 * `minKeySecurityLevel: 'software'` explicitly, which keeps that concession
 * visible in the test rather than hidden in a default.
 *
 * The RN Metro config must exclude `src/core/testing/**` from release bundles
 * (see README) — the same discipline that keeps device-sim out of the broker.
 */
import { webcrypto } from 'node:crypto';
import { MobileError } from '../errors.js';
import type {
  GenerateKeyOptions,
  GeneratedKey,
  KeySecurityLevel,
  KeyStore,
  KeyStoreCapabilities,
  SignPromptSpec,
} from '../keystore.js';
import type { PublicKeyJwk } from '../types.js';

const { subtle } = webcrypto;

/** What the simulated biometric gate does on the next signature. */
export type BiometricGateOutcome = 'ok' | 'cancel' | 'fail' | 'not_enrolled';

export interface WebCryptoKeyStoreOptions {
  securityLevel?: KeySecurityLevel;
  available?: boolean;
  supportsKeyAttestation?: boolean;
  /** Fixed value returned as the Android key-attestation chain. */
  keyAttestation?: string;
}

export class WebCryptoKeyStore implements KeyStore {
  private readonly keys = new Map<string, webcrypto.CryptoKeyPair>();
  private readonly options: Required<Omit<WebCryptoKeyStoreOptions, 'keyAttestation'>> &
    Pick<WebCryptoKeyStoreOptions, 'keyAttestation'>;

  /** Test observability: one entry per completed signature. */
  readonly promptLog: SignPromptSpec[] = [];
  /** Payloads presented to the gate, in order. */
  readonly signedPayloads: string[] = [];
  /** Challenges handed to `generate()` — asserts the nonce reaches the key. */
  readonly attestationChallenges: (string | undefined)[] = [];
  /** Set this to make the NEXT signature take a different path. */
  gate: BiometricGateOutcome = 'ok';

  constructor(options: WebCryptoKeyStoreOptions = {}) {
    this.options = {
      securityLevel: options.securityLevel ?? 'software',
      available: options.available ?? true,
      supportsKeyAttestation: options.supportsKeyAttestation ?? true,
      ...(options.keyAttestation !== undefined ? { keyAttestation: options.keyAttestation } : {}),
    };
  }

  async capabilities(): Promise<KeyStoreCapabilities> {
    return {
      available: this.options.available,
      securityLevel: this.options.securityLevel,
      supportsKeyAttestation: this.options.supportsKeyAttestation,
    };
  }

  async hasKey(alias: string): Promise<boolean> {
    return this.keys.has(alias);
  }

  async generate(options: GenerateKeyOptions): Promise<GeneratedKey> {
    this.attestationChallenges.push(options.attestationChallenge);
    // extractable: false — the private key can never leave (05 §3, T3).
    const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ])) as webcrypto.CryptoKeyPair;
    this.keys.set(options.alias, pair);
    return {
      alias: options.alias,
      publicJwk: await this.exportPublicJwk(options.alias),
      securityLevel: this.options.securityLevel,
      ...(this.options.keyAttestation !== undefined
        ? { keyAttestation: this.options.keyAttestation }
        : {}),
    };
  }

  async exportPublicJwk(alias: string): Promise<PublicKeyJwk> {
    const pair = this.require(alias);
    const jwk = await subtle.exportKey('jwk', pair.publicKey);
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
      throw MobileError.local('keystore_failed', { detail: 'unexpected_jwk_shape' });
    }
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  async sign(alias: string, payload: string, prompt: SignPromptSpec): Promise<string> {
    const pair = this.require(alias);
    // The gate stands in for the platform raising a biometric prompt as part
    // of the key operation — one prompt, one signature (05 §3, T1).
    switch (this.gate) {
      case 'cancel':
        throw MobileError.local('biometric_cancelled');
      case 'fail':
        throw MobileError.local('biometric_failed');
      case 'not_enrolled':
        throw MobileError.local('biometric_not_enrolled');
      case 'ok':
      default:
        break;
    }
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.privateKey,
      Buffer.from(payload, 'utf8'),
    );
    this.promptLog.push(prompt);
    this.signedPayloads.push(payload);
    return Buffer.from(signature).toString('base64url');
  }

  async delete(alias: string): Promise<void> {
    this.keys.delete(alias);
  }

  /** Test helper: the raw pair, to assert non-extractability. */
  rawPair(alias: string): webcrypto.CryptoKeyPair {
    return this.require(alias);
  }

  private require(alias: string): webcrypto.CryptoKeyPair {
    const pair = this.keys.get(alias);
    if (!pair) throw MobileError.local('keystore_failed', { detail: 'unknown_alias' });
    return pair;
  }
}

/** Verify a base64url r||s ES256 signature against a public JWK — test helper. */
export async function verifySignature(
  publicJwk: PublicKeyJwk,
  payload: string,
  signatureB64Url: string,
): Promise<boolean> {
  const key = await subtle.importKey(
    'jwk',
    { ...publicJwk, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );
  return subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    Buffer.from(signatureB64Url, 'base64url'),
    Buffer.from(payload, 'utf8'),
  );
}
