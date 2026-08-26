import { webcrypto } from 'node:crypto';
import { buildChallengePayload } from '@sdid/shared';
import { describe, expect, it } from 'vitest';
import { MobileError } from './errors.js';
import { WebCryptoKeyStore, verifySignature } from './testing/webcrypto-keystore.js';

const { subtle } = webcrypto;
const ALIAS = 'test.key';

describe('KeyStore contract — key material (05 §3, T3)', () => {
  it('generates a NON-EXPORTABLE private key', async () => {
    const store = new WebCryptoKeyStore();
    await store.generate({ alias: ALIAS });
    const { privateKey } = store.rawPair(ALIAS);
    expect(privateKey.extractable).toBe(false);
    await expect(subtle.exportKey('jwk', privateKey)).rejects.toThrow();
  });

  it('exports the public key in exactly the JWK shape enrolStart accepts', async () => {
    const store = new WebCryptoKeyStore();
    const key = await store.generate({ alias: ALIAS });
    expect(key.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(Object.keys(key.publicJwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
  });

  it('re-generating an alias produces a different key (re-enrolment is a new key)', async () => {
    const store = new WebCryptoKeyStore();
    const first = await store.generate({ alias: ALIAS });
    const second = await store.generate({ alias: ALIAS });
    expect(second.publicJwk.x).not.toBe(first.publicJwk.x);
  });

  it('deletes irreversibly', async () => {
    const store = new WebCryptoKeyStore();
    await store.generate({ alias: ALIAS });
    await store.delete(ALIAS);
    expect(await store.hasKey(ALIAS)).toBe(false);
    await expect(store.sign(ALIAS, 'x', prompt())).rejects.toMatchObject({
      code: 'keystore_failed',
    });
  });

  it('reports `software`, so nothing can mistake the test double for hardware', async () => {
    expect((await new WebCryptoKeyStore().capabilities()).securityLevel).toBe('software');
  });
});

describe('KeyStore contract — signing (protocol.ts wire form)', () => {
  it('produces a base64url ES256 r||s signature that verifies against the public JWK', async () => {
    const store = new WebCryptoKeyStore();
    const key = await store.generate({ alias: ALIAS });
    const payload = buildChallengePayload({ kind: 'activation' }, 'chal-1', 'nonce-1');

    const signature = await store.sign(ALIAS, payload, prompt());
    expect(signature).toMatch(/^[A-Za-z0-9_-]+$/); // base64url, unpadded
    expect(await verifySignature(key.publicJwk, payload, signature)).toBe(true);
  });

  it('a signature does not verify over a different payload', async () => {
    const store = new WebCryptoKeyStore();
    const key = await store.generate({ alias: ALIAS });
    const payload = buildChallengePayload({ kind: 'login' }, 'chal-1', 'nonce-1');
    const signature = await store.sign(ALIAS, payload, prompt());
    expect(await verifySignature(key.publicJwk, `${payload}x`, signature)).toBe(false);
  });

  it('signs the EXACT UTF-8 bytes, including non-ASCII', async () => {
    const store = new WebCryptoKeyStore();
    const key = await store.generate({ alias: ALIAS });
    const payload = 'sdid-bridge:v1:login:c:ñŏñçé';
    const signature = await store.sign(ALIAS, payload, prompt());
    expect(await verifySignature(key.publicJwk, payload, signature)).toBe(true);
  });
});

describe('KeyStore contract — biometric gate (05 §3, T1)', () => {
  it('raises exactly one prompt per signature, carrying the reason', async () => {
    const store = new WebCryptoKeyStore();
    await store.generate({ alias: ALIAS });
    await store.sign(ALIAS, 'a', prompt('Emeza'));
    await store.sign(ALIAS, 'b', prompt('Anga'));
    expect(store.promptLog).toHaveLength(2);
    expect(store.promptLog.map((p) => p.title)).toEqual(['Emeza', 'Anga']);
  });

  it('a cancelled unlock yields no signature at all', async () => {
    const store = new WebCryptoKeyStore();
    await store.generate({ alias: ALIAS });
    store.gate = 'cancel';
    await expect(store.sign(ALIAS, 'a', prompt())).rejects.toMatchObject({
      code: 'biometric_cancelled',
    });
    expect(store.signedPayloads).toEqual([]);
  });

  it('surfaces "no biometric enrolled" distinctly from "not recognised"', async () => {
    const store = new WebCryptoKeyStore();
    await store.generate({ alias: ALIAS });
    store.gate = 'not_enrolled';
    const notEnrolled = await store.sign(ALIAS, 'a', prompt()).catch((e: unknown) => e);
    store.gate = 'fail';
    const failed = await store.sign(ALIAS, 'a', prompt()).catch((e: unknown) => e);

    expect((notEnrolled as MobileError).messageKey).toBe('errors.biometric_not_enrolled');
    expect((failed as MobileError).messageKey).toBe('errors.biometric_failed');
  });
});

describe('KeyStore contract — attestation challenge (runbook §10)', () => {
  it('receives the nonce STRING verbatim at generation time', async () => {
    const store = new WebCryptoKeyStore();
    const nonce = 'Zm9vYmFy_-9Aa';
    await store.generate({ alias: ALIAS, attestationChallenge: nonce });
    // Android bakes this into the certificate chain at keygen; the UTF-8 bytes
    // of THIS string are what setAttestationChallenge() must receive — not the
    // base64url-decoded bytes.
    expect(store.attestationChallenges).toEqual([nonce]);
  });
});

function prompt(title = 'Emeza'): { title: string; cancelLabel: string } {
  return { title, cancelLabel: 'Reka' };
}
