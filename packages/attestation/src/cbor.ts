/**
 * Minimal CBOR (RFC 8949) decoder — just enough for an Apple App Attest
 * object (spec 05 §4, 06 T2/T3).
 *
 * Why hand-rolled: the attestation path is the trust root of a national
 * identity system. Every byte decoded here is attacker-supplied and arrives
 * *before* any signature has been checked, so a parser bug is a pre-auth
 * remote bug. A dependency-free ~250-line decoder we can read in full is a
 * smaller risk than a transitive supply chain (decision: no CBOR/ASN.1
 * libraries on this path).
 *
 * Deliberately NOT supported — each omission removes an attack surface we
 * would otherwise have to defend:
 *   - indefinite-length items (streaming, chunked strings): rejected outright;
 *   - tags (major type 6): App Attest uses none;
 *   - floats and unassigned simple values: only false/true/null/undefined;
 *   - duplicate map keys: a classic parser-differential smuggling trick;
 *   - non-UTF-8 text strings;
 *   - trailing bytes after the top-level item.
 *
 * Hostile-input discipline, applied without exception:
 *   - a declared length is NEVER used to allocate. It is compared against the
 *     bytes actually remaining first, so `bytes(0xffffffff)` fails on a 12-byte
 *     buffer instead of asking for 4 GiB;
 *   - container element counts are likewise bounded by the bytes remaining
 *     (every element costs at least one byte), so a map claiming 2^53 pairs
 *     cannot spin;
 *   - depth, total item count and total input size are hard-capped, so nesting
 *     cannot exhaust the stack.
 */

/** Value produced by {@link decodeCbor}. */
export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | CborMap;

/** Keys are restricted to text strings and integers (see {@link decodeCbor}). */
export type CborMap = Map<string | number, CborValue>;

/** Thrown for any malformed or policy-violating input. Never carries payload bytes. */
export class CborError extends Error {
  constructor(message: string) {
    super(`cbor: ${message}`);
    this.name = 'CborError';
  }
}

export interface CborLimits {
  /** Maximum nesting depth of arrays/maps. */
  maxDepth: number;
  /** Maximum number of data items (including container members) decoded. */
  maxItems: number;
  /** Maximum accepted input size in bytes. */
  maxBytes: number;
}

/**
 * Defaults sized for App Attest: the object is a 3-entry map whose largest
 * member is a receipt of a few kilobytes plus two certificates. Anything an
 * order of magnitude larger is not a credible attestation.
 */
export const DEFAULT_CBOR_LIMITS: CborLimits = {
  maxDepth: 8,
  maxItems: 1024,
  maxBytes: 128 * 1024,
};

const MT_UNSIGNED = 0;
const MT_NEGATIVE = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;
const MT_SIMPLE = 7;

const AI_INDEFINITE = 31;

const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Decodes exactly one CBOR item from `input`, requiring the whole buffer to be
 * consumed. Trailing bytes are an error: an attestation object with a payload
 * appended is not an attestation object we understand, and "parse a prefix" is
 * how signed and verified views of the same blob drift apart.
 */
export function decodeCbor(input: Uint8Array, limits: Partial<CborLimits> = {}): CborValue {
  const effective: CborLimits = { ...DEFAULT_CBOR_LIMITS, ...limits };
  if (input.length > effective.maxBytes) {
    throw new CborError(`input of ${input.length} bytes exceeds limit ${effective.maxBytes}`);
  }
  const reader = new CborReader(input, effective);
  const value = reader.readValue(0);
  reader.requireEnd();
  return value;
}

class CborReader {
  private pos = 0;
  private items = 0;

  constructor(
    private readonly buf: Uint8Array,
    private readonly limits: CborLimits,
  ) {}

  requireEnd(): void {
    if (this.pos !== this.buf.length) {
      throw new CborError(`${this.buf.length - this.pos} trailing byte(s) after top-level item`);
    }
  }

  private remaining(): number {
    return this.buf.length - this.pos;
  }

  private byte(): number {
    if (this.pos >= this.buf.length) throw new CborError('unexpected end of input');
    return this.buf[this.pos++]!;
  }

  /** Reads `n` raw bytes as a copy, after checking they exist. */
  private bytes(n: number): Uint8Array {
    if (n > this.remaining()) {
      throw new CborError(`declared length ${n} exceeds ${this.remaining()} byte(s) remaining`);
    }
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /**
   * Reads the argument of a head byte. Rejects indefinite length and
   * non-canonical (non-shortest) encodings — the latter is another parser
   * differential: two encodings of the same value must not both be accepted.
   */
  private argument(ai: number): { value: number; big: bigint } {
    if (ai < 24) return { value: ai, big: BigInt(ai) };
    if (ai === AI_INDEFINITE) throw new CborError('indefinite-length items are not accepted');
    if (ai > 27) throw new CborError(`reserved additional information ${ai}`);

    const width = 1 << (ai - 24); // 1, 2, 4 or 8 bytes
    const raw = this.bytes(width);
    let big = 0n;
    for (const b of raw) big = (big << 8n) | BigInt(b);

    // Canonical (shortest-form) check: e.g. 0x18 0x05 must have been 0x05.
    const minimum = ai === 24 ? 24n : 1n << BigInt(8 * (width >> 1));
    if (big < minimum) throw new CborError('non-canonical integer encoding');

    const value = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : Number.NaN;
    return { value, big };
  }

  /** A length or element count must be a safe integer AND fit the buffer. */
  private countArgument(ai: number, what: string): number {
    const { value, big } = this.argument(ai);
    if (!Number.isSafeInteger(value)) {
      throw new CborError(`${what} ${big} is absurd`);
    }
    if (value > this.remaining()) {
      // Each element/byte costs at least one byte of input, so this bound is
      // sound for strings AND containers, and it is checked before any
      // allocation or loop.
      throw new CborError(`${what} ${value} exceeds ${this.remaining()} byte(s) remaining`);
    }
    return value;
  }

  private countItem(): void {
    if (++this.items > this.limits.maxItems) {
      throw new CborError(`more than ${this.limits.maxItems} items`);
    }
  }

  readValue(depth: number): CborValue {
    if (depth > this.limits.maxDepth) {
      throw new CborError(`nesting deeper than ${this.limits.maxDepth}`);
    }
    this.countItem();

    const head = this.byte();
    const major = head >> 5;
    const ai = head & 0x1f;

    switch (major) {
      case MT_UNSIGNED: {
        const { value, big } = this.argument(ai);
        return Number.isSafeInteger(value) ? value : big;
      }
      case MT_NEGATIVE: {
        const { value, big } = this.argument(ai);
        return Number.isSafeInteger(value) ? -1 - value : -1n - big;
      }
      case MT_BYTES:
        return this.bytes(this.countArgument(ai, 'byte string length'));
      case MT_TEXT: {
        const raw = this.bytes(this.countArgument(ai, 'text string length'));
        try {
          return utf8.decode(raw);
        } catch {
          throw new CborError('text string is not valid UTF-8');
        }
      }
      case MT_ARRAY: {
        const n = this.countArgument(ai, 'array length');
        const out: CborValue[] = [];
        for (let i = 0; i < n; i++) out.push(this.readValue(depth + 1));
        return out;
      }
      case MT_MAP: {
        // A map of n pairs needs at least 2n bytes; countArgument already
        // bounded n by the bytes remaining, and each readValue consumes at
        // least one, so a lying count fails fast rather than looping.
        const n = this.countArgument(ai, 'map size');
        const out: CborMap = new Map();
        for (let i = 0; i < n; i++) {
          const key = this.readValue(depth + 1);
          if (typeof key !== 'string' && typeof key !== 'number') {
            throw new CborError('map keys must be text strings or small integers');
          }
          if (out.has(key)) throw new CborError('duplicate map key');
          out.set(key, this.readValue(depth + 1));
        }
        return out;
      }
      case MT_TAG:
        throw new CborError('tagged items are not accepted');
      case MT_SIMPLE:
      default:
        switch (ai) {
          case 20:
            return false;
          case 21:
            return true;
          case 22:
            return null;
          case 23:
            return undefined;
          default:
            // Floats (25/26/27) and every other simple value: an App Attest
            // object contains none, so accepting them only widens the surface.
            throw new CborError(`unsupported simple value ${ai}`);
        }
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Typed accessors — callers must never cast a CborValue by hand.              */
/* -------------------------------------------------------------------------- */

export function cborAsMap(value: CborValue, what: string): CborMap {
  if (!(value instanceof Map)) throw new CborError(`${what} is not a map`);
  return value;
}

export function cborAsBytes(value: CborValue, what: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new CborError(`${what} is not a byte string`);
  return value;
}

export function cborAsText(value: CborValue, what: string): string {
  if (typeof value !== 'string') throw new CborError(`${what} is not a text string`);
  return value;
}

export function cborAsArray(value: CborValue, what: string): CborValue[] {
  if (!Array.isArray(value)) throw new CborError(`${what} is not an array`);
  return value;
}

export function cborAsInteger(value: CborValue, what: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new CborError(`${what} is not an integer`);
  }
  return value;
}
