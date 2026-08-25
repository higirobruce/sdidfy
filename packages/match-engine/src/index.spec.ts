import { describe, expect, it } from 'vitest';
import type { BiometricReference, BiometricSample } from '@sdid/shared';
import { mockBiometricBytes, MOCK_TEST_NIDS } from '@sdid/shared';
import { createMatchEngine, MockMatchEngine, PAD_THRESHOLD } from './index.js';

const GENUINE_NID = MOCK_TEST_NIDS[0];
const IMPOSTOR_NID = MOCK_TEST_NIDS[1];

function makeSample(data: Uint8Array, livenessScore = 0.95, method = 'mock-liveness-v1'): BiometricSample {
  return { modality: 'face', data, liveness: { method, score: livenessScore } };
}

function makeReference(
  data: Uint8Array,
  format: BiometricReference['format'] = 'mock',
): BiometricReference {
  return { modality: 'face', data, format };
}

function allZero(buf: Uint8Array): boolean {
  return buf.every((b) => b === 0);
}

describe('createMatchEngine', () => {
  it('returns a MockMatchEngine implementing the MatchEngine contract', () => {
    const engine = createMatchEngine();
    expect(engine).toBeInstanceOf(MockMatchEngine);
    expect(typeof engine.match).toBe('function');
  });

  it('exports the PAD threshold constant at 0.8', () => {
    expect(PAD_THRESHOLD).toBe(0.8);
  });
});

describe('MockMatchEngine.match', () => {
  const engine = createMatchEngine();

  it('matches a genuine pair (same NID) with band high', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'));
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: true, scoreBand: 'high', padPassed: true });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('rejects an impostor (different NID) with no-match', async () => {
    const sample = makeSample(mockBiometricBytes(IMPOSTOR_NID, 'face'));
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: true });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('fails PAD without comparing bytes: byte-identical pair still returns no-match', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'), 0.5);
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    // A spoofed capture must not leak whether the bytes would have matched.
    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: false });
    // Zeroize discipline holds on the PAD-fail path too.
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('fails PAD when the liveness method is empty, even at a high score', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'), 0.99, '');
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: false });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('tolerates template noise: one flipped byte in 32 gives medium and matches', async () => {
    const bytes = mockBiometricBytes(GENUINE_NID, 'face'); // 32 bytes (sha256)
    expect(bytes.length).toBe(32);
    const noisy = new Uint8Array(bytes);
    noisy[0] = noisy[0]! ^ 0xff;

    const sample = makeSample(noisy);
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: true, scoreBand: 'medium', padPassed: true });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('does not match with 4 flipped bytes in a 32-byte template', async () => {
    const noisy = new Uint8Array(mockBiometricBytes(GENUINE_NID, 'face'));
    for (let i = 0; i < 4; i++) noisy[i] = noisy[i]! ^ 0xff;

    const sample = makeSample(noisy);
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    // 28/32 = 0.875 → 'low' band, below the match bar.
    expect(result.matched).toBe(false);
    expect(result.scoreBand).toBe('low');
    expect(result.padPassed).toBe(true);
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('handles a length mismatch safely: no-match, no throw, buffers zeroized', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face').slice(0, 16));
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: true });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('treats a non-mock reference format as no-match, and still zeroizes', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'));
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'), 'iso-19794');

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: true });
    expect(allZero(sample.data)).toBe(true);
    expect(allZero(reference.data)).toBe(true);
  });

  it('treats empty buffers as no-match rather than a trivial full match', async () => {
    const sample = makeSample(new Uint8Array(0));
    const reference = makeReference(new Uint8Array(0));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: false, scoreBand: 'no-match', padPassed: true });
  });

  it('accepts a liveness score exactly at the PAD threshold', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'), PAD_THRESHOLD);
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    expect(result).toEqual({ matched: true, scoreBand: 'high', padPassed: true });
  });

  it('never includes biometric bytes in the result', async () => {
    const sample = makeSample(mockBiometricBytes(GENUINE_NID, 'face'));
    const reference = makeReference(mockBiometricBytes(GENUINE_NID, 'face'));

    const result = await engine.match(sample, reference);

    // The result carries only the three contract fields — no byte payloads.
    expect(Object.keys(result).sort()).toEqual(['matched', 'padPassed', 'scoreBand']);
  });
});
