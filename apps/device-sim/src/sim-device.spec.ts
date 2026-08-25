import { webcrypto } from 'node:crypto';
import { MOCK_TEST_NIDS, mockBiometricBytes } from '@sdid/shared';
import { describe, expect, it } from 'vitest';
import { SimDevice } from './sim-device.js';

const { subtle } = webcrypto;

const NID = MOCK_TEST_NIDS[0];
const OTHER_NID = MOCK_TEST_NIDS[1];

function newDevice(overrides?: { biometricAvailable?: boolean }): SimDevice {
  return new SimDevice({
    brokerUrl: 'http://broker.invalid',
    nid: NID,
    deviceLabel: 'Test Phone',
    ...(overrides ?? {}),
  });
}

/** Reach into the private keypair — tests only. */
async function keyPairOf(device: SimDevice): Promise<webcrypto.CryptoKeyPair> {
  return (device as unknown as { keyPairPromise: Promise<webcrypto.CryptoKeyPair> })
    .keyPairPromise;
}

describe('SimDevice keys & signing', () => {
  it('sign() produces a base64url ECDSA P-256/SHA-256 signature verifiable with the exported public JWK', async () => {
    const device = newDevice();
    const payload = 'sdid-bridge:v1:activation:chal-1:nonce-1';
    const signature = await device.sign(payload);

    // base64url, no padding
    expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);

    const jwk = await device.publicKeyJwk();
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);

    const publicKey = await subtle.importKey(
      'jwk',
      { ...jwk, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const ok = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      Buffer.from(signature, 'base64url'),
      Buffer.from(payload, 'utf8'),
    );
    expect(ok).toBe(true);

    // a different payload must not verify
    const bad = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      Buffer.from(signature, 'base64url'),
      Buffer.from(payload + 'tampered', 'utf8'),
    );
    expect(bad).toBe(false);
  });

  it('private key is non-extractable (Secure Enclave simulation)', async () => {
    const device = newDevice();
    const { privateKey } = await keyPairOf(device);
    expect(privateKey.extractable).toBe(false);
    await expect(subtle.exportKey('jwk', privateKey)).rejects.toThrow();
  });

  it('biometricAvailable: false gates the key — sign() throws', async () => {
    const device = newDevice({ biometricAvailable: false });
    await expect(device.sign('anything')).rejects.toThrow(/biometric/i);
  });
});

describe('SimDevice.captureBiometric', () => {
  it('genuine capture derives from mockBiometricBytes(nid, face) with high liveness', () => {
    const sample = newDevice().captureBiometric();
    expect(sample.modality).toBe('face');
    expect(sample.liveness).toEqual({ method: 'active-blink', score: 0.97 });
    expect(Buffer.from(sample.data, 'base64')).toEqual(
      Buffer.from(mockBiometricBytes(NID, 'face')),
    );
  });

  it('impostorNid derives the sample from a different NID', () => {
    const genuine = newDevice().captureBiometric();
    const impostor = newDevice().captureBiometric({ impostorNid: OTHER_NID });
    expect(impostor.data).not.toBe(genuine.data);
    expect(Buffer.from(impostor.data, 'base64')).toEqual(
      Buffer.from(mockBiometricBytes(OTHER_NID, 'face')),
    );
  });

  it('spoof drops the liveness score to 0.2', () => {
    const sample = newDevice().captureBiometric({ spoof: true });
    expect(sample.liveness.score).toBe(0.2);
  });

  it('corruptBytes flips exactly n bytes', () => {
    const n = 5;
    const genuine = Buffer.from(newDevice().captureBiometric().data, 'base64');
    const corrupt = Buffer.from(newDevice().captureBiometric({ corruptBytes: n }).data, 'base64');
    expect(corrupt.length).toBe(genuine.length);
    let differing = 0;
    for (let i = 0; i < genuine.length; i++) {
      if (genuine[i] !== corrupt[i]) differing++;
    }
    expect(differing).toBe(n);
  });

  it('corruptBytes: 0 leaves the sample intact', () => {
    const genuine = newDevice().captureBiometric();
    const untouched = newDevice().captureBiometric({ corruptBytes: 0 });
    expect(untouched.data).toBe(genuine.data);
  });
});

describe('SimDevice.mockAttestation', () => {
  it('token round-trips through base64url JSON with default healthy claims', () => {
    const attestation = newDevice().mockAttestation();
    expect(attestation.platform).toBe('sim');
    expect(attestation.keyAttestation).toBe('mock-key-attestation-v1');
    const claims = JSON.parse(Buffer.from(attestation.token, 'base64url').toString('utf8'));
    expect(claims).toEqual({
      mock: true,
      deviceIntegrity: true,
      appIntegrity: true,
      hardwareBackedKey: true,
    });
  });

  it('overrides land in the token (rooted device simulation)', () => {
    const attestation = newDevice().mockAttestation({ deviceIntegrity: false });
    const claims = JSON.parse(Buffer.from(attestation.token, 'base64url').toString('utf8'));
    expect(claims).toEqual({
      mock: true,
      deviceIntegrity: false,
      appIntegrity: true,
      hardwareBackedKey: true,
    });
  });
});
