/**
 * Apple App Attest verifier tests.
 *
 * The attestation objects are assembled byte by byte: CBOR encoded by the
 * fixture encoder, authData laid out to Apple's format, and the credCert
 * signed for real with the nonce extension carrying
 * SHA256(authData ‖ SHA256(nonce ‖ enrolledKey)). Each rejection case removes
 * exactly one of
 * those properties, so a passing test says the check is load-bearing rather
 * than incidental.
 */

import type { KeyObject } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { AppAttestVerifier } from './app-attest.js';
import type { AttestationResult } from './types.js';
import {
  AAGUID_DEV,
  AAGUID_PROD,
  cborArray,
  cborBytes,
  cborMap,
  cborText,
  generateEcKeyPair,
  makeAppAttestObject,
  sha256,
  toJwk,
  type AppAttestOptions,
} from './fixtures.spec.js';

const APP_ID = 'ABCDE12345.rw.gov.risa.sdid';
const NONCE = '6ba7b8109dad11d180b400c04fd430c8';
const NOW = Date.UTC(2026, 7, 25, 12, 0, 0);

async function run(
  options: Partial<AppAttestOptions> & {
    production?: boolean;
    expectedNonce?: string;
    now?: number;
    /** Clock used for verification, when it must differ from the build time. */
    verifyNow?: number;
    rootPemOverride?: string;
    tokenOverride?: string;
    enrolDifferentKey?: boolean;
    enrolledPublicKey?: KeyObject;
  } = {},
): Promise<AttestationResult> {
  const device = generateEcKeyPair();
  const other = generateEcKeyPair();
  const fixture = makeAppAttestObject({
    appId: APP_ID,
    nonce: NONCE,
    devicePublicKey: device.publicKey,
    now: NOW,
    includeCoseKey: true,
    receipt: Buffer.alloc(64, 0x5a),
    ...options,
  });
  const verifier = new AppAttestVerifier({
    config: {
      appId: APP_ID,
      production: options.production ?? true,
      rootCertificatesPem: options.rootPemOverride === undefined ? [fixture.rootPem] : [options.rootPemOverride],
    },
  });
  return verifier.verify({
    token: options.tokenOverride ?? fixture.token,
    expectedNonce: options.expectedNonce ?? NONCE,
    devicePublicKeyJwk: toJwk(
      options.enrolDifferentKey
        ? other.publicKey
        : options.enrolledPublicKey ?? options.devicePublicKey ?? device.publicKey,
    ),
    now: options.verifyNow ?? options.now ?? NOW,
  });
}

function expectRejected(result: AttestationResult, code: string): void {
  expect(result.ok, `expected rejection ${code}, got acceptance`).toBe(false);
  if (!result.ok) expect(result.code).toBe(code);
}

describe('AppAttestVerifier — acceptance', () => {
  it('accepts a well-formed production attestation → AL2, Secure Enclave', async () => {
    const result = await run();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.platform).toBe('ios');
    expect(result.appGenuine).toBe(true);
    expect(result.keySecurityLevel).toBe('trusted-environment');
    expect(result.assuranceCap).toBe('AL2');
    expect(result.evidence.environment).toBe('production');
    expect(result.evidence.receiptPresent).toBe(true);
    expect(result.evidence.receiptBytes).toBe(64);
    expect(result.evidence.signCount).toBe(0);
  });

  it('accepts an attestation with no COSE key appended to authData', async () => {
    const result = await run({ includeCoseKey: false });
    expect(result.ok).toBe(true);
  });

  it('accepts a development attestation only when the deployment allows it', async () => {
    const result = await run({ aaguid: AAGUID_DEV, production: false });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.evidence.environment).toBe('development');
  });

  it('keeps the token and nonce out of the evidence', async () => {
    const result = await run();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const serialised = JSON.stringify(result.evidence);
    expect(serialised).not.toContain(NONCE);
    expect(serialised).not.toContain('appattest');
  });
});

describe('AppAttestVerifier — environment and replay', () => {
  it('rejects a development build against a production deployment', async () => {
    const result = await run({ aaguid: AAGUID_DEV, production: true });
    expectRejected(result, 'app_integrity');
  });

  it('rejects an unknown aaguid', async () => {
    const result = await run({ aaguid: Buffer.alloc(16, 0x11) });
    expectRejected(result, 'malformed');
  });

  it('rejects a non-zero signCount: an attestation is minted once', async () => {
    const result = await run({ signCount: 1 });
    expectRejected(result, 'malformed');
  });

  it('rejects an attestation bound to a different nonce (T4)', async () => {
    const result = await run({ expectedNonce: 'a-nonce-we-never-issued' });
    expectRejected(result, 'nonce_mismatch');
  });

  it('rejects a credCert whose nonce extension is not the expected digest', async () => {
    const result = await run({ nonceOverride: Buffer.alloc(32, 0x33) });
    expectRejected(result, 'nonce_mismatch');
  });

  it('rejects a credCert with no nonce extension at all', async () => {
    const result = await run({ omitNonceExtension: true });
    expectRejected(result, 'malformed');
  });

  it('rejects an enrolment with no expected nonce', async () => {
    const result = await run({ expectedNonce: '' });
    expectRejected(result, 'nonce_mismatch');
  });
});

describe('AppAttestVerifier — identity and key binding', () => {
  it('rejects an attestation for another App ID', async () => {
    const result = await run({ rpIdHash: sha256(Buffer.from('OTHER99999.com.attacker.app', 'utf8')) });
    expectRejected(result, 'app_mismatch');
  });

  it('rejects a credentialId that is not SHA256 of the certified key', async () => {
    const result = await run({ credentialId: Buffer.alloc(32, 0x44) });
    expectRejected(result, 'key_mismatch');
  });

  it('accepts the real iOS shape: App Attest key and enrolled signing key are different keys', async () => {
    // The case that actually ships. An App Attest key can only be used via
    // generateAssertion() and cannot be biometry-gated, so the enrolled
    // signing key is always a separate Secure Enclave key (05 §3, T1). The
    // binding comes from clientData, not from the two keys being equal — an
    // earlier version of this verifier demanded equality and would have
    // rejected every genuine iOS enrolment.
    const enrolled = generateEcKeyPair().publicKey;
    const result = await run({ enrolledPublicKey: enrolled });
    expect(result.ok, 'a separate enrolled key must verify').toBe(true);
  });

  it('rejects an attestation whose clientData bound a different enrolled key', async () => {
    // Substituting the enrolled key changes clientDataHash and therefore the
    // digest Apple certified, so this surfaces as nonce_mismatch rather than
    // key_mismatch — indistinguishable by construction (app-attest.ts step 8).
    const result = await run({ enrolDifferentKey: true });
    expectRejected(result, 'nonce_mismatch');
  });

  it('rejects a COSE key in authData that disagrees with the certificate', async () => {
    const result = await run({ includeCoseKey: true, coseKey: generateEcKeyPair().publicKey });
    expectRejected(result, 'key_mismatch');
  });
});

describe('AppAttestVerifier — chain', () => {
  it('rejects a chain whose link does not verify', async () => {
    const result = await run({ breakChain: true });
    expectRejected(result, 'chain_invalid');
  });

  it('rejects a chain that does not reach the configured Apple root', async () => {
    const stranger = makeAppAttestObject({
      appId: APP_ID,
      nonce: NONCE,
      devicePublicKey: generateEcKeyPair().publicKey,
      now: NOW,
    });
    const result = await run({ rootPemOverride: stranger.rootPem });
    expectRejected(result, 'chain_invalid');
  });

  it('rejects a fixture chain against the real pinned Apple root (the default is used)', async () => {
    // No rootCertificatesPem in the config at all → the pinned Apple root from
    // roots.ts applies, and a test-generated chain must not verify under it.
    const device = generateEcKeyPair();
    const fixture = makeAppAttestObject({
      appId: APP_ID,
      nonce: NONCE,
      devicePublicKey: device.publicKey,
      now: NOW,
    });
    const verifier = new AppAttestVerifier({ config: { appId: APP_ID, production: true } });
    const result = await verifier.verify({
      token: fixture.token,
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(device.publicKey),
      now: NOW,
    });
    expectRejected(result, 'chain_invalid');
  });

  it('rejects an expired credCert', async () => {
    // Built now, verified 31 days later: the credCert's 30-day window is over.
    const result = await run({ verifyNow: NOW + 86_400_000 * 31 });
    expectRejected(result, 'chain_invalid');
  });
});

describe('AppAttestVerifier — malformed input', () => {
  it('rejects a token that is not strict base64', async () => {
    expectRejected(await run({ tokenOverride: 'not base64 !!!' }), 'malformed');
    expectRejected(await run({ tokenOverride: '' }), 'malformed');
    expectRejected(await run({ tokenOverride: 'QUJD' + '='.repeat(3) }), 'malformed');
  });

  it('rejects base64 that is not CBOR', async () => {
    expectRejected(await run({ tokenOverride: Buffer.alloc(32, 0xff).toString('base64') }), 'malformed');
  });

  it('rejects a CBOR object with the wrong fmt', async () => {
    expectRejected(await run({ fmt: 'packed' }), 'malformed');
  });

  it('rejects an attestation object missing its members', async () => {
    const noAuthData = cborMap([
      [cborText('fmt'), cborText('apple-appattest')],
      [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([cborBytes(Buffer.from('ab', 'hex'))])]])],
    ]);
    expectRejected(await run({ tokenOverride: noAuthData.toString('base64') }), 'malformed');

    const emptyX5c = cborMap([
      [cborText('fmt'), cborText('apple-appattest')],
      [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([])]])],
      [cborText('authData'), cborBytes(Buffer.alloc(37))],
    ]);
    expectRejected(await run({ tokenOverride: emptyX5c.toString('base64') }), 'malformed');
  });

  it('rejects x5c entries that are not certificates', async () => {
    const badCert = cborMap([
      [cborText('fmt'), cborText('apple-appattest')],
      [cborText('attStmt'), cborMap([[cborText('x5c'), cborArray([cborBytes(Buffer.alloc(48, 3))])]])],
      [cborText('authData'), cborBytes(Buffer.alloc(37))],
    ]);
    expectRejected(await run({ tokenOverride: badCert.toString('base64') }), 'malformed');
  });

  it('rejects authData that lies about its credentialId length', async () => {
    // 0xffff bytes of credentialId claimed, four present. The nonce extension
    // is computed over these very bytes, so the object gets past the nonce
    // check and the length claim is what has to stop it.
    const lying = Buffer.concat([
      sha256(Buffer.from(APP_ID, 'utf8')),
      Buffer.from([0x40]),
      Buffer.alloc(4),
      AAGUID_PROD,
      Buffer.from([0xff, 0xff]),
      Buffer.alloc(4, 1),
    ]);
    expectRejected(await run({ authDataOverride: lying }), 'malformed');
  });

  it('rejects authData with no attested credential data', async () => {
    const headerOnly = Buffer.concat([
      sha256(Buffer.from(APP_ID, 'utf8')),
      Buffer.from([0x00]), // AT flag clear
      Buffer.alloc(4),
    ]);
    expectRejected(await run({ authDataOverride: headerOnly }), 'malformed');
    expectRejected(await run({ authDataOverride: Buffer.alloc(10) }), 'malformed');
  });

  it('rejects trailing bytes after the credential key that are not a COSE key', async () => {
    const device = generateEcKeyPair();
    const credentialId = sha256(
      Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from((device.publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url'),
        Buffer.from((device.publicKey.export({ format: 'jwk' }) as { y: string }).y, 'base64url'),
      ]),
    );
    const authData = Buffer.concat([
      sha256(Buffer.from(APP_ID, 'utf8')),
      Buffer.from([0x40]),
      Buffer.alloc(4),
      AAGUID_PROD,
      Buffer.from([0x00, 0x20]),
      credentialId,
      Buffer.from('ffffff', 'hex'), // not CBOR
    ]);
    expectRejected(await run({ devicePublicKey: device.publicKey, authDataOverride: authData }), 'malformed');
  });

  it('detects a swapped authData through the nonce binding, before parsing it', async () => {
    // The nonce extension covers authData, so substituting authData breaks the
    // binding first — the parser never even sees the substituted bytes.
    const device = generateEcKeyPair();
    const genuine = makeAppAttestObject({
      appId: APP_ID,
      nonce: NONCE,
      devicePublicKey: device.publicKey,
      now: NOW,
    });
    const swapped = Buffer.concat([
      genuine.authData.subarray(0, genuine.authData.length - 1),
      Buffer.from([genuine.authData[genuine.authData.length - 1]! ^ 0xff]),
    ]);
    const token = Buffer.from(genuine.token, 'base64');
    const index = token.indexOf(genuine.authData);
    expect(index).toBeGreaterThan(0);
    const tampered = Buffer.concat([
      token.subarray(0, index),
      swapped,
      token.subarray(index + genuine.authData.length),
    ]);
    const verifier = new AppAttestVerifier({
      config: { appId: APP_ID, production: true, rootCertificatesPem: [genuine.rootPem] },
    });
    const result = await verifier.verify({
      token: tampered.toString('base64'),
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(device.publicKey),
      now: NOW,
    });
    expectRejected(result, 'nonce_mismatch');
  });
});
