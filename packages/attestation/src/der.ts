/**
 * Minimal DER (X.690 distinguished encoding rules) reader — enough to walk the
 * custom attestation extensions that no standard Node API exposes:
 * Android's KeyDescription (`1.3.6.1.4.1.11129.2.1.17`) and Apple's App Attest
 * nonce extension (`1.2.840.113635.100.8.2`).
 *
 * Scope discipline (same reasoning as `cbor.ts`): certificates themselves are
 * parsed and verified by Node's `crypto.X509Certificate`, i.e. by OpenSSL.
 * This reader only walks extension payloads and the TBS structure needed to
 * find them. It is not a general ASN.1 implementation and must not become one.
 *
 * DER, not BER — the difference is the security property here:
 *   - indefinite lengths are rejected;
 *   - non-minimal length encodings are rejected (0x81 0x05 must have been 0x05);
 *   - non-minimal / padded high-tag-number forms are rejected;
 *   - trailing bytes after the top-level element are rejected;
 *   - INTEGER must be minimally encoded.
 * Each of those is a place where two parsers can disagree about the same bytes,
 * and an attacker who can make our reader and OpenSSL see different structures
 * gets to smuggle a different key or challenge past us.
 *
 * Hostile-input discipline: a declared length is compared against the bytes
 * actually remaining before any slice, node count and depth are capped, and no
 * allocation is ever sized by an unvalidated number.
 */

export class DerError extends Error {
  constructor(message: string) {
    super(`der: ${message}`);
    this.name = 'DerError';
  }
}

export type DerTagClass = 'universal' | 'application' | 'context' | 'private';

export interface DerNode {
  readonly tagClass: DerTagClass;
  readonly constructed: boolean;
  /** Tag number within the class (SEQUENCE = 16 universal, `[704]` = 704 context). */
  readonly tagNumber: number;
  /** Raw content octets (excludes identifier and length). */
  readonly content: Uint8Array;
  /** Parsed children; empty for primitive nodes. */
  readonly children: readonly DerNode[];
}

export interface DerLimits {
  maxDepth: number;
  maxNodes: number;
  maxBytes: number;
}

/**
 * Sized for certificates and their extensions: an Android chain leaf is a few
 * kilobytes, a KeyDescription a few hundred bytes.
 */
export const DEFAULT_DER_LIMITS: DerLimits = {
  maxDepth: 24,
  maxNodes: 4096,
  maxBytes: 64 * 1024,
};

/** Universal tag numbers used by this package. */
export const DER_BOOLEAN = 1;
export const DER_INTEGER = 2;
export const DER_BIT_STRING = 3;
export const DER_OCTET_STRING = 4;
export const DER_NULL = 5;
export const DER_OID = 6;
export const DER_ENUMERATED = 10;
export const DER_UTF8_STRING = 12;
export const DER_SEQUENCE = 16;
export const DER_SET = 17;

/** Parses exactly one DER element, requiring the whole buffer to be consumed. */
export function parseDer(input: Uint8Array, limits: Partial<DerLimits> = {}): DerNode {
  const effective: DerLimits = { ...DEFAULT_DER_LIMITS, ...limits };
  if (input.length > effective.maxBytes) {
    throw new DerError(`input of ${input.length} bytes exceeds limit ${effective.maxBytes}`);
  }
  const reader = new DerReader(input, effective);
  const node = reader.readNode(0);
  reader.requireEnd();
  return node;
}

class DerReader {
  private pos = 0;
  private nodes = 0;

  constructor(
    private readonly buf: Uint8Array,
    private readonly limits: DerLimits,
  ) {}

  requireEnd(): void {
    if (this.pos !== this.buf.length) {
      throw new DerError(`${this.buf.length - this.pos} trailing byte(s) after top-level element`);
    }
  }

  private remaining(): number {
    return this.buf.length - this.pos;
  }

  private byte(): number {
    if (this.pos >= this.buf.length) throw new DerError('unexpected end of input');
    return this.buf[this.pos++]!;
  }

  private readTagNumber(first: number): number {
    const low = first & 0x1f;
    if (low !== 0x1f) return low; // low-tag-number form

    // High-tag-number form: base-128, most significant first, no leading 0x80,
    // capped so a long run of 0xff bytes cannot build an unbounded number.
    let value = 0;
    let octets = 0;
    for (;;) {
      const b = this.byte();
      if (octets === 0 && b === 0x80) throw new DerError('non-minimal high tag number');
      value = value * 128 + (b & 0x7f);
      octets++;
      if (value > 0x0fff_ffff) throw new DerError('tag number too large');
      if ((b & 0x80) === 0) break;
      if (octets > 4) throw new DerError('tag number too long');
    }
    if (value < 0x1f) throw new DerError('high tag number should have used the short form');
    return value;
  }

  private readLength(): number {
    const first = this.byte();
    if (first === 0x80) throw new DerError('indefinite length is not valid DER');
    if (first < 0x80) return first;

    const count = first & 0x7f;
    if (count > 4) throw new DerError('length field too long');
    const bytes: number[] = [];
    for (let i = 0; i < count; i++) bytes.push(this.byte());
    if (bytes[0] === 0x00) throw new DerError('non-minimal length encoding (leading zero)');

    let value = 0;
    for (const b of bytes) value = value * 256 + b;
    if (value < 0x80) throw new DerError('non-minimal length encoding (short form available)');
    return value;
  }

  readNode(depth: number): DerNode {
    if (depth > this.limits.maxDepth) {
      throw new DerError(`nesting deeper than ${this.limits.maxDepth}`);
    }
    if (++this.nodes > this.limits.maxNodes) {
      throw new DerError(`more than ${this.limits.maxNodes} elements`);
    }

    const identifier = this.byte();
    const tagClass = TAG_CLASSES[(identifier >> 6) & 0x03]!;
    const constructed = (identifier & 0x20) !== 0;
    const tagNumber = this.readTagNumber(identifier);

    const length = this.readLength();
    if (length > this.remaining()) {
      throw new DerError(`declared length ${length} exceeds ${this.remaining()} byte(s) remaining`);
    }
    const content = this.buf.subarray(this.pos, this.pos + length);
    this.pos += length;

    const children: DerNode[] = [];
    if (constructed) {
      // Children are parsed over the parent's content slice, so every child
      // length check is bounded by the parent element rather than by the whole
      // buffer: a child cannot reach past its parent's declared end.
      const inner = new DerReader(content, this.limits);
      inner.nodes = this.nodes;
      while (inner.remaining() > 0) {
        children.push(inner.readNode(depth + 1));
        this.nodes = inner.nodes; // node budget is global, not per element
      }
    }

    return { tagClass, constructed, tagNumber, content, children };
  }
}

const TAG_CLASSES: readonly DerTagClass[] = ['universal', 'application', 'context', 'private'];

/* -------------------------------------------------------------------------- */
/* Typed accessors                                                             */
/* -------------------------------------------------------------------------- */

export function derExpect(
  node: DerNode,
  tagClass: DerTagClass,
  tagNumber: number,
  what: string,
): DerNode {
  if (node.tagClass !== tagClass || node.tagNumber !== tagNumber) {
    throw new DerError(`${what}: expected ${tagClass} tag ${tagNumber}, got ${node.tagClass} ${node.tagNumber}`);
  }
  return node;
}

export function derSequence(node: DerNode, what: string): readonly DerNode[] {
  derExpect(node, 'universal', DER_SEQUENCE, what);
  if (!node.constructed) throw new DerError(`${what}: SEQUENCE must be constructed`);
  return node.children;
}

export function derSet(node: DerNode, what: string): readonly DerNode[] {
  derExpect(node, 'universal', DER_SET, what);
  if (!node.constructed) throw new DerError(`${what}: SET must be constructed`);
  return node.children;
}

/** INTEGER as a bigint, enforcing DER minimal encoding. */
export function derInteger(node: DerNode, what: string): bigint {
  derExpect(node, 'universal', DER_INTEGER, what);
  return decodeTwosComplement(node.content, what);
}

/** INTEGER constrained to a safe JS integer (all attestation enums and tags are tiny). */
export function derSmallInteger(node: DerNode, what: string): number {
  const value = derInteger(node, what);
  if (value < BigInt(Number.MIN_SAFE_INTEGER) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new DerError(`${what}: integer out of range`);
  }
  return Number(value);
}

export function derEnumerated(node: DerNode, what: string): number {
  derExpect(node, 'universal', DER_ENUMERATED, what);
  const value = decodeTwosComplement(node.content, what);
  if (value < 0n || value > 0xffffn) throw new DerError(`${what}: enumerated out of range`);
  return Number(value);
}

export function derBoolean(node: DerNode, what: string): boolean {
  derExpect(node, 'universal', DER_BOOLEAN, what);
  if (node.content.length !== 1) throw new DerError(`${what}: BOOLEAN must be one octet`);
  const b = node.content[0]!;
  // DER: TRUE is exactly 0xff. BER would accept any non-zero; accepting that
  // here would let two encodings of "true" exist.
  if (b !== 0x00 && b !== 0xff) throw new DerError(`${what}: non-DER BOOLEAN encoding`);
  return b === 0xff;
}

export function derOctetString(node: DerNode, what: string): Uint8Array {
  derExpect(node, 'universal', DER_OCTET_STRING, what);
  if (node.constructed) throw new DerError(`${what}: constructed OCTET STRING is not DER`);
  return node.content;
}

/** BIT STRING content, requiring a whole number of octets (0 unused bits). */
export function derBitString(node: DerNode, what: string): Uint8Array {
  derExpect(node, 'universal', DER_BIT_STRING, what);
  if (node.constructed) throw new DerError(`${what}: constructed BIT STRING is not DER`);
  if (node.content.length < 1) throw new DerError(`${what}: empty BIT STRING`);
  const unused = node.content[0]!;
  if (unused !== 0) throw new DerError(`${what}: ${unused} unused bit(s) not supported`);
  return node.content.subarray(1);
}

/** OBJECT IDENTIFIER in dotted-decimal form. */
export function derOid(node: DerNode, what: string): string {
  derExpect(node, 'universal', DER_OID, what);
  const bytes = node.content;
  if (bytes.length === 0) throw new DerError(`${what}: empty OID`);
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) throw new DerError(`${what}: truncated OID`);

  const parts: string[] = [];
  let value = 0n;
  let started = false;
  let first = true;
  for (const b of bytes) {
    if (!started && b === 0x80) throw new DerError(`${what}: non-minimal OID arc`);
    started = true;
    value = (value << 7n) | BigInt(b & 0x7f);
    if (value > 1n << 128n) throw new DerError(`${what}: OID arc too large`);
    if ((b & 0x80) === 0) {
      if (first) {
        // First octet packs arcs 1 and 2: 40*a1 + a2.
        const v = Number(value);
        const a1 = v >= 80 ? 2 : Math.floor(v / 40);
        parts.push(String(a1), String(v - a1 * 40));
        first = false;
      } else {
        parts.push(value.toString());
      }
      value = 0n;
      started = false;
    }
  }
  return parts.join('.');
}

/**
 * Unwraps an EXPLICIT context-specific tag (`[n] EXPLICIT Type`), which is how
 * every optional field in an Android AuthorizationList is encoded.
 */
export function derExplicit(node: DerNode, what: string): DerNode {
  if (node.tagClass !== 'context' || !node.constructed) {
    throw new DerError(`${what}: expected a constructed context-specific tag`);
  }
  if (node.children.length !== 1) {
    throw new DerError(`${what}: EXPLICIT tag must wrap exactly one element`);
  }
  return node.children[0]!;
}

/** Finds the single child carrying context-specific tag `tagNumber`, if any. */
export function derFindContext(
  children: readonly DerNode[],
  tagNumber: number,
): DerNode | undefined {
  let found: DerNode | undefined;
  for (const child of children) {
    if (child.tagClass === 'context' && child.tagNumber === tagNumber) {
      if (found) throw new DerError(`duplicate context tag [${tagNumber}]`);
      found = child;
    }
  }
  return found;
}

function decodeTwosComplement(content: Uint8Array, what: string): bigint {
  if (content.length === 0) throw new DerError(`${what}: empty integer`);
  if (content.length > 1) {
    const a = content[0]!;
    const b = content[1]!;
    // DER minimality: 0x00 0x7f and 0xff 0x80 are both forbidden redundancies.
    if ((a === 0x00 && (b & 0x80) === 0) || (a === 0xff && (b & 0x80) !== 0)) {
      throw new DerError(`${what}: non-minimal integer encoding`);
    }
  }
  let value = 0n;
  for (const byte of content) value = (value << 8n) | BigInt(byte);
  if ((content[0]! & 0x80) !== 0) value -= 1n << BigInt(8 * content.length);
  return value;
}
