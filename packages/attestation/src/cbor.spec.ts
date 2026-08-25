/**
 * CBOR decoder tests, including the hostile inputs the decoder exists to
 * survive. Every rejection case below is a shape an attacker can post to the
 * enrolment endpoint before any signature has been checked.
 */

import { describe, expect, it } from 'vitest';

import { CborError, cborAsBytes, cborAsMap, cborAsText, decodeCbor } from './cbor.js';
import { cborArray, cborBytes, cborMap, cborNegative, cborText, cborUint } from './fixtures.spec.js';

const hex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'));

/** Fails the test if decoding takes long enough to look like a stall. */
function expectFastRejection(bytes: Uint8Array, label: string): void {
  const started = process.hrtime.bigint();
  expect(() => decodeCbor(bytes), label).toThrow(CborError);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  expect(elapsedMs, `${label} should fail fast`).toBeLessThan(250);
}

describe('decodeCbor — well-formed input', () => {
  it('decodes unsigned integers across every head width', () => {
    expect(decodeCbor(hex('00'))).toBe(0);
    expect(decodeCbor(hex('17'))).toBe(23);
    expect(decodeCbor(hex('1818'))).toBe(24);
    expect(decodeCbor(hex('1903e8'))).toBe(1000);
    expect(decodeCbor(hex('1a000f4240'))).toBe(1_000_000);
    // 2^63: beyond a safe integer, so it comes back as a bigint rather than
    // silently losing precision.
    expect(decodeCbor(hex('1b8000000000000000'))).toBe(9223372036854775808n);
  });

  it('decodes negative integers', () => {
    expect(decodeCbor(hex('20'))).toBe(-1);
    expect(decodeCbor(hex('3863'))).toBe(-100);
    expect(decodeCbor(hex('3903e7'))).toBe(-1000);
  });

  it('decodes byte and text strings', () => {
    expect(Buffer.from(cborAsBytes(decodeCbor(hex('4401020304')), 'b')).toString('hex')).toBe('01020304');
    expect(decodeCbor(hex('6449455446'))).toBe('IETF');
    expect(decodeCbor(hex('40')) instanceof Uint8Array).toBe(true);
  });

  it('decodes arrays, maps and simple values', () => {
    expect(decodeCbor(hex('83010203'))).toEqual([1, 2, 3]);
    const map = cborAsMap(decodeCbor(hex('a26161016162820203')), 'm');
    expect(map.get('a')).toBe(1);
    expect(map.get('b')).toEqual([2, 3]);
    expect(decodeCbor(hex('f4'))).toBe(false);
    expect(decodeCbor(hex('f5'))).toBe(true);
    expect(decodeCbor(hex('f6'))).toBe(null);
    expect(decodeCbor(hex('f7'))).toBe(undefined);
  });

  it('decodes negative map keys, as COSE keys use', () => {
    const cose = cborMap([
      [cborUint(1), cborUint(2)],
      [cborNegative(-1), cborUint(1)],
      [cborNegative(-2), cborBytes(Buffer.alloc(32, 1))],
    ]);
    const map = cborAsMap(decodeCbor(cose), 'cose');
    expect(map.get(1)).toBe(2);
    expect(map.get(-1)).toBe(1);
    expect(cborAsBytes(map.get(-2), 'x')).toHaveLength(32);
  });

  it('round-trips a nested structure built by the fixture encoder', () => {
    const encoded = cborMap([
      [cborText('fmt'), cborText('apple-appattest')],
      [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([cborBytes(Buffer.from('ab', 'hex'))])]])],
    ]);
    const root = cborAsMap(decodeCbor(encoded), 'root');
    expect(cborAsText(root.get('fmt'), 'fmt')).toBe('apple-appattest');
  });
});

describe('decodeCbor — hostile input', () => {
  it('rejects every indefinite-length item', () => {
    for (const head of ['5f', '7f', '9f', 'bf']) {
      expect(() => decodeCbor(hex(`${head}ff`))).toThrow(/indefinite/);
    }
  });

  it('rejects trailing bytes after the top-level item', () => {
    expect(() => decodeCbor(hex('0100'))).toThrow(/trailing/);
  });

  it('rejects a truncated buffer instead of reading past its end', () => {
    expect(() => decodeCbor(hex('43ab'))).toThrow(CborError); // 3-byte string, 1 byte present
    expect(() => decodeCbor(hex('19'))).toThrow(CborError); // head with no argument
    expect(() => decodeCbor(new Uint8Array(0))).toThrow(CborError);
  });

  it('rejects an absurd declared byte-string length without allocating', () => {
    // Claims ~4 GiB in a 5-byte buffer. Must fail on the length check.
    expectFastRejection(hex('5affffffff'), 'byte string of 4 GiB');
    expectFastRejection(hex('5bffffffffffffffff'), 'byte string of 2^64');
    expectFastRejection(hex('7affffffff'), 'text string of 4 GiB');
  });

  it('rejects absurd container counts without looping', () => {
    expectFastRejection(hex('9affffffff'), 'array of 4 billion items');
    expectFastRejection(hex('bbffffffffffffffff'), 'map of 2^64 pairs');
    // A count that is merely larger than the bytes available also fails.
    expectFastRejection(hex('98ff0102'), 'array of 255 items in 3 bytes');
  });

  it('rejects nesting deeper than the limit rather than blowing the stack', () => {
    const depth = 5000;
    const deep = Buffer.concat([Buffer.alloc(depth, 0x81), Buffer.from([0x00])]);
    expectFastRejection(deep, `${depth} nested arrays`);
  });

  it('rejects more items than the budget allows', () => {
    // One array of 2000 zero bytes: well-formed, within every length bound,
    // and still refused because the total item budget is the backstop.
    const count = Buffer.alloc(2);
    count.writeUInt16BE(2000);
    const array = Buffer.concat([Buffer.from([0x99]), count, Buffer.alloc(2000, 0x00)]);
    expect(() => decodeCbor(array)).toThrow(/items/);
  });

  it('rejects input larger than the configured maximum', () => {
    expect(() => decodeCbor(new Uint8Array(200 * 1024))).toThrow(/exceeds limit/);
  });

  it('rejects tags, floats and unassigned simple values', () => {
    expect(() => decodeCbor(hex('c11a514b67b0'))).toThrow(/tagged/);
    expect(() => decodeCbor(hex('f93c00'))).toThrow(/simple value/); // half float 1.0
    expect(() => decodeCbor(hex('fa47c35000'))).toThrow(/simple value/);
    expect(() => decodeCbor(hex('fb3ff199999999999a'))).toThrow(/simple value/);
    expect(() => decodeCbor(hex('f0'))).toThrow(/simple value/);
  });

  it('rejects non-canonical integer encodings', () => {
    expect(() => decodeCbor(hex('1817'))).toThrow(/non-canonical/); // 23 in a 1-byte argument
    expect(() => decodeCbor(hex('190017'))).toThrow(/non-canonical/);
  });

  it('rejects duplicate and non-scalar map keys', () => {
    expect(() => decodeCbor(hex('a2616101616102'))).toThrow(/duplicate/);
    expect(() => decodeCbor(hex('a141ab01'))).toThrow(/map keys/); // byte-string key
  });

  it('rejects text that is not valid UTF-8', () => {
    expect(() => decodeCbor(hex('62c328'))).toThrow(/UTF-8/);
  });

  it('reports errors without echoing the payload back', () => {
    try {
      decodeCbor(hex('62c328'));
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain('c328');
    }
  });
});
