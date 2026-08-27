/**
 * Shared primitives for the attestation verifiers: strict base64,
 * constant-time comparison, hashing, and EC P-256 point handling.
 *
 * Nothing here is clever. It exists so that the three verifiers cannot each
 * grow their own subtly different idea of "are these two keys the same" — the
 * key-binding check (types.ts) is only as good as its comparison.
 */

import { createHash, timingSafeEqual, type KeyObject } from 'node:crypto';

import type { AttestationRejected, AttestationRejectionCode } from './types.js';

/** Builds a rejection. Detail is operator-facing only (03 §7). */
export function reject(code: AttestationRejectionCode, detail: string): AttestationRejected {
  return { ok: false, code, detail };
}

export function sha256(...parts: readonly Uint8Array[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

/**
 * Constant-time byte comparison. Length inequality short-circuits — that leaks
 * only the length, which is public for every value compared here (nonces,
 * digests, EC points are all fixed-size).
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

/**
 * Constant-time string comparison over UTF-8 bytes. Used for the nonce (T4):
 * an early-exit compare lets an attacker walk a nonce out byte by byte.
 */
export function stringsEqual(a: string, b: string): boolean {
  return bytesEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/** Thrown by the strict decoders below; callers map it to `malformed`. */
export class MalformedInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MalformedInputError';
  }
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

/**
 * Strict standard base64. `Buffer.from(s, 'base64')` silently skips characters
 * it does not understand, so `"AA!!AA"` and `"AAAA"` decode alike — a decoder
 * differential we refuse to inherit on an attacker-controlled input path.
 */
export function decodeBase64Strict(input: string, what: string): Buffer {
  if (input.length === 0 || input.length % 4 !== 0 || !BASE64_RE.test(input)) {
    throw new MalformedInputError(`${what}: not strict base64`);
  }
  const decoded = Buffer.from(input, 'base64');
  if (decoded.toString('base64') !== input) {
    throw new MalformedInputError(`${what}: non-canonical base64`);
  }
  return decoded;
}

/** Strict unpadded base64url, as used by JWK coordinates. */
export function decodeBase64UrlStrict(input: string, what: string): Buffer {
  if (input.length === 0 || input.length % 4 === 1 || !BASE64URL_RE.test(input)) {
    throw new MalformedInputError(`${what}: not strict base64url`);
  }
  const decoded = Buffer.from(input, 'base64url');
  if (decoded.toString('base64url') !== input) {
    throw new MalformedInputError(`${what}: non-canonical base64url`);
  }
  return decoded;
}

/** Uncompressed SEC1 point length for P-256: 0x04 || X(32) || Y(32). */
export const P256_POINT_LENGTH = 65;
const P256_COORD_LENGTH = 32;

/**
 * The raw uncompressed EC point of the key being enrolled.
 *
 * Comparing raw points (rather than JWK objects, PEM text or DER SPKI) is
 * deliberate: JSON key order, base64url padding and SPKI parameter encodings
 * all vary without changing the key, and any of those differences would turn a
 * genuine match into a false `key_mismatch` — or, worse, a mismatch into an
 * accidental match if compared loosely.
 */
export function jwkToRawPoint(
  jwk: { kty: string; crv: string; x: string; y: string },
  what: string,
): Buffer {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new MalformedInputError(`${what}: only EC P-256 keys are supported`);
  }
  const x = decodeBase64UrlStrict(jwk.x, `${what}.x`);
  const y = decodeBase64UrlStrict(jwk.y, `${what}.y`);
  if (x.length !== P256_COORD_LENGTH || y.length !== P256_COORD_LENGTH) {
    // P-256 coordinates are always 32 bytes; a short coordinate would have to
    // be left-padded to compare, and accepting that invites two encodings of
    // the same key.
    throw new MalformedInputError(`${what}: coordinates must be 32 bytes`);
  }
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

/** Raw uncompressed EC point of a public key, or undefined if it is not EC P-256. */
export function keyObjectToRawPoint(key: KeyObject): Buffer | undefined {
  if (key.asymmetricKeyType !== 'ec') return undefined;
  const jwk = key.export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string; y?: string };
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) return undefined;
  try {
    return jwkToRawPoint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, 'certificate key');
  } catch {
    return undefined;
  }
}
