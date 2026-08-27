/**
 * Verifies the DER → raw `r‖s` ECDSA signature conversion (CONTRACT.md §1.4)
 * that `SdidKeyStoreModule.kt` and `SdidKeyStore.swift` both implement.
 *
 * This is NOT a test of those files — Kotlin and Swift can't run under
 * vitest, and neither has ever been compiled (see ../android/README.md,
 * ../ios/README.md). It's an independent TypeScript port of the exact same
 * algorithm, checked against real P-256 ECDSA signatures via Node's own
 * `crypto` module, so the shared logic is verified correct before anyone
 * transcribes it onto a device. CONTRACT.md §7 item 1 calls out exactly this
 * case: "signatures where `r` or `s` has a leading zero byte (the case that
 * breaks naive implementations)" — this suite deliberately samples until it
 * has seen both that case and the shorter-than-32-byte case, rather than
 * hoping enough random iterations cover them.
 */
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';

const COORD_LENGTH = 32;

function derLengthSize(der: Buffer, offset: number): number {
  const first = der[offset]!;
  return first < 0x80 ? 1 : 1 + (first & 0x7f);
}

function derLengthValue(der: Buffer, offset: number): number {
  const first = der[offset]!;
  if (first < 0x80) return first;
  let length = 0;
  for (let i = 1; i <= (first & 0x7f); i++) length = (length << 8) | der[offset + i]!;
  return length;
}

function readDerInteger(der: Buffer, offset: number): [Buffer, number] {
  if (der[offset] !== 0x02) throw new Error('expected DER INTEGER');
  const lengthSize = derLengthSize(der, offset + 1);
  const length = derLengthValue(der, offset + 1);
  const valueStart = offset + 1 + lengthSize;
  return [der.subarray(valueStart, valueStart + length), 1 + lengthSize + length];
}

function normalise(value: Buffer): Buffer {
  const trimmed = value.length > COORD_LENGTH && value[0] === 0 ? value.subarray(1) : value;
  const out = Buffer.alloc(COORD_LENGTH);
  trimmed.copy(out, COORD_LENGTH - trimmed.length);
  return out;
}

/**
 * Mirrors `derToRawRs` in SdidKeyStoreModule.kt / SdidKeyStore.swift exactly
 * — same steps, same order — so a bug found here is worth checking for in
 * both of those.
 */
function derToRawRs(der: Buffer): Buffer {
  if (der[0] !== 0x30) throw new Error('not a DER SEQUENCE');
  let offset = 1;
  offset += derLengthSize(der, offset);
  const [r, rConsumed] = readDerInteger(der, offset);
  offset += rConsumed;
  const [s] = readDerInteger(der, offset);
  return Buffer.concat([normalise(r), normalise(s)]);
}

/** Hand-encodes DER from a raw 32-byte coordinate — independent of the
 * decoder under test, used only to build fixtures. */
function encodeDerInteger(raw: Buffer): Buffer {
  let bytes = raw;
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  bytes = bytes.subarray(i);
  if (bytes[0]! & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

function encodeDer(r: Buffer, s: Buffer): Buffer {
  const body = Buffer.concat([encodeDerInteger(r), encodeDerInteger(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function sampleRawSignature(key: KeyObject, message: Buffer): Buffer {
  return cryptoSign('sha256', message, { key, dsaEncoding: 'ieee-p1363' }) as Buffer;
}

describe('DER -> raw r||s conversion (CONTRACT.md §1.4)', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  it('round-trips a large, deliberately curated sample of real signatures', () => {
    const SAMPLE_SIZE = 2000;
    let sawLeadingZeroByte = false;
    let sawShortCoordinate = false;

    for (let i = 0; i < SAMPLE_SIZE; i++) {
      const raw = sampleRawSignature(privateKey, Buffer.from(`message ${i}`));
      const r = raw.subarray(0, COORD_LENGTH);
      const s = raw.subarray(COORD_LENGTH, 2 * COORD_LENGTH);
      if (r[0]! >= 0x80 || s[0]! >= 0x80) sawLeadingZeroByte = true;
      if (r[0] === 0 || s[0] === 0) sawShortCoordinate = true;

      const der = encodeDer(r, s);
      expect(derToRawRs(der)).toEqual(raw);
    }

    // If neither ever occurred, the sample was too small or biased — the
    // whole point of this test is exercising both traps, not just the
    // common case.
    expect(sawLeadingZeroByte).toBe(true);
    expect(sawShortCoordinate).toBe(true);
  });

  it('strips a DER sign byte when the coordinate would look negative', () => {
    // r's top byte >= 0x80, so a correct DER encoder inserts a 0x00 sign
    // byte, making the DER INTEGER 33 bytes for a 32-byte coordinate. The
    // classic naive-implementation bug is forwarding that 33rd byte.
    const r = Buffer.alloc(COORD_LENGTH, 0xff);
    const s = Buffer.alloc(COORD_LENGTH, 0x01);
    const der = encodeDer(r, s);
    expect(der.readUInt8(2)).toBe(0x02); // INTEGER tag
    expect(der.readUInt8(3)).toBe(COORD_LENGTH + 1); // length 33, proving the sign byte is present
    expect(derToRawRs(der)).toEqual(Buffer.concat([r, s]));
  });

  it('left-pads a coordinate shorter than 32 bytes back to fixed width', () => {
    // A coordinate with leading zero bytes encodes shorter in DER (those
    // zeros are dropped) — the conversion must reintroduce them, not leave
    // the result short.
    const r = Buffer.concat([Buffer.alloc(4, 0), Buffer.alloc(COORD_LENGTH - 4, 0x42)]);
    const s = Buffer.alloc(COORD_LENGTH, 0x07);
    const der = encodeDer(r, s);
    expect(der.readUInt8(3)).toBe(COORD_LENGTH - 4); // DER dropped the leading zeros
    const result = derToRawRs(der);
    expect(result).toHaveLength(2 * COORD_LENGTH);
    expect(result.subarray(0, COORD_LENGTH)).toEqual(r);
  });
});
