/**
 * DER reader tests, including the hostile inputs the reader exists to survive,
 * and the DER-vs-BER strictness that stops two parsers disagreeing about the
 * same certificate extension.
 */

import { describe, expect, it } from 'vitest';

import {
  DerError,
  derBitString,
  derBoolean,
  derEnumerated,
  derExplicit,
  derFindContext,
  derInteger,
  derOctetString,
  derOid,
  derSequence,
  derSet,
  derSmallInteger,
  parseDer,
} from './der.js';
import {
  boolean,
  derLength,
  enumerated,
  explicit,
  integer,
  octetString,
  oid,
  seq,
  set,
  tlv,
} from './fixtures.spec.js';

const hex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'));

function expectFastRejection(bytes: Uint8Array, label: string): void {
  const started = process.hrtime.bigint();
  expect(() => parseDer(bytes), label).toThrow(DerError);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  expect(elapsedMs, `${label} should fail fast`).toBeLessThan(250);
}

describe('parseDer — well-formed input', () => {
  it('parses a SEQUENCE and its children', () => {
    const children = derSequence(parseDer(seq(integer(1), octetString(Buffer.from('ab', 'hex')))), 's');
    expect(children).toHaveLength(2);
    expect(derSmallInteger(children[0]!, 'i')).toBe(1);
    expect(Buffer.from(derOctetString(children[1]!, 'o')).toString('hex')).toBe('ab');
  });

  it('parses INTEGER, ENUMERATED, BOOLEAN, BIT STRING and SET', () => {
    expect(derInteger(parseDer(integer(0)), 'i')).toBe(0n);
    expect(derInteger(parseDer(integer(255)), 'i')).toBe(255n);
    expect(derInteger(parseDer(hex('020180')), 'i')).toBe(-128n); // two's complement
    expect(derEnumerated(parseDer(enumerated(2)), 'e')).toBe(2);
    expect(derBoolean(parseDer(boolean(true)), 'b')).toBe(true);
    expect(derBoolean(parseDer(boolean(false)), 'b')).toBe(false);
    expect(Buffer.from(derBitString(parseDer(hex('03020041')), 'bs')).toString('hex')).toBe('41');
    expect(derSet(parseDer(set(integer(1), integer(2))), 'set')).toHaveLength(2);
  });

  it('decodes object identifiers, including multi-byte arcs', () => {
    expect(derOid(parseDer(oid('2.5.29.19')), 'o')).toBe('2.5.29.19');
    expect(derOid(parseDer(oid('1.3.6.1.4.1.11129.2.1.17')), 'o')).toBe('1.3.6.1.4.1.11129.2.1.17');
    expect(derOid(parseDer(oid('1.2.840.113635.100.8.2')), 'o')).toBe('1.2.840.113635.100.8.2');
    expect(derOid(parseDer(oid('1.2.840.10045.4.3.2')), 'o')).toBe('1.2.840.10045.4.3.2');
  });

  it('parses high-tag-number context tags, as Android authorization lists use', () => {
    // [704] EXPLICIT SEQUENCE — tag number 704 needs the high-tag-number form.
    const node = parseDer(seq(explicit(704, seq(boolean(true), enumerated(0)))));
    const children = derSequence(node, 'list');
    const rootOfTrust = derFindContext(children, 704);
    expect(rootOfTrust).toBeDefined();
    expect(rootOfTrust!.tagNumber).toBe(704);
    const inner = derSequence(derExplicit(rootOfTrust!, 'rot'), 'rot');
    expect(derBoolean(inner[0]!, 'locked')).toBe(true);
    expect(derEnumerated(inner[1]!, 'state')).toBe(0);
  });

  it('finds nothing for an absent context tag and rejects duplicates', () => {
    const children = derSequence(parseDer(seq(explicit(702, integer(0)))), 'list');
    expect(derFindContext(children, 704)).toBeUndefined();
    const duplicated = derSequence(parseDer(seq(explicit(702, integer(0)), explicit(702, integer(1)))), 'l');
    expect(() => derFindContext(duplicated, 702)).toThrow(/duplicate context tag/);
  });

  it('parses a long-form length', () => {
    const long = tlv(0x04, Buffer.alloc(300, 0x41));
    expect(derOctetString(parseDer(long), 'o')).toHaveLength(300);
    expect(derLength(300)).toEqual(Buffer.from([0x82, 0x01, 0x2c]));
  });
});

describe('parseDer — hostile input', () => {
  it('rejects indefinite length', () => {
    expect(() => parseDer(hex('308002000000'))).toThrow(/indefinite/);
  });

  it('rejects non-minimal length encodings', () => {
    expect(() => parseDer(hex('028105'))).toThrow(/non-minimal length/); // 1 in long form
    expect(() => parseDer(hex('0282000105'))).toThrow(/non-minimal length/); // leading zero
  });

  it('rejects a length that runs past the buffer', () => {
    expect(() => parseDer(hex('047f01'))).toThrow(/exceeds/);
    expect(() => parseDer(hex('3006020101'))).toThrow(DerError);
  });

  it('rejects an absurd declared length without allocating', () => {
    expectFastRejection(hex('0484ffffffff'), 'octet string of 4 GiB');
    expectFastRejection(hex('3084ffffffff'), 'sequence of 4 GiB');
    expectFastRejection(hex('0488ffffffffffffffff'), 'length field of 8 octets');
  });

  it('rejects trailing bytes after the top-level element', () => {
    expect(() => parseDer(hex('02010100'))).toThrow(/trailing/);
  });

  it('rejects nesting deeper than the limit rather than blowing the stack', () => {
    // 2000 nested SEQUENCEs, each one byte of content longer than the next.
    let node = Buffer.from([0x05, 0x00]);
    for (let i = 0; i < 2000; i++) node = seq(node);
    expectFastRejection(node, '2000 nested sequences');
  });

  it('rejects more elements than the node budget allows', () => {
    const many = seq(...Array.from({ length: 5000 }, () => Buffer.from([0x05, 0x00])));
    expectFastRejection(many, '5000 sibling elements');
  });

  it('rejects a truncated element', () => {
    expect(() => parseDer(hex('30'))).toThrow(DerError);
    expect(() => parseDer(hex('0203'))).toThrow(DerError);
    expect(() => parseDer(new Uint8Array(0))).toThrow(DerError);
  });

  it('rejects non-minimal INTEGER encodings', () => {
    expect(() => derInteger(parseDer(hex('0202007f')), 'i')).toThrow(/non-minimal/);
    expect(() => derInteger(parseDer(hex('0202ff80')), 'i')).toThrow(/non-minimal/);
    expect(() => derInteger(parseDer(hex('0200')), 'i')).toThrow(/empty integer/);
  });

  it('rejects BER-style BOOLEAN and constructed strings', () => {
    expect(() => derBoolean(parseDer(hex('010101')), 'b')).toThrow(/non-DER/);
    // 24 03 (04 01 00): a BER constructed OCTET STRING wrapping one segment.
    expect(() => derOctetString(parseDer(hex('2403040100')), 'o')).toThrow(/constructed/);
  });

  it('rejects a BIT STRING with unused bits', () => {
    expect(() => derBitString(parseDer(hex('03020341')), 'bs')).toThrow(/unused bit/);
    expect(() => derBitString(parseDer(hex('0300')), 'bs')).toThrow(/empty BIT STRING/);
  });

  it('rejects malformed and non-minimal object identifiers', () => {
    expect(() => derOid(parseDer(hex('06022a86')), 'o')).toThrow(/truncated/);
    expect(() => derOid(parseDer(hex('06032a8086')), 'o')).toThrow(DerError);
    expect(() => derOid(parseDer(hex('0600')), 'o')).toThrow(/empty OID/);
  });

  it('rejects a non-minimal high-tag-number form', () => {
    expect(() => parseDer(hex('bf800100'))).toThrow(/non-minimal high tag/);
  });

  it('rejects an EXPLICIT tag that does not wrap exactly one element', () => {
    const twoInside = derSequence(parseDer(seq(explicit(702, Buffer.concat([integer(1), integer(2)])))), 'l');
    expect(() => derExplicit(twoInside[0]!, 'x')).toThrow(/exactly one/);
  });

  it('rejects a type confusion between tags', () => {
    expect(() => derSequence(parseDer(set(integer(1))), 's')).toThrow(/expected universal tag 16/);
    expect(() => derOctetString(parseDer(integer(1)), 'o')).toThrow(/expected universal tag 4/);
  });
});
