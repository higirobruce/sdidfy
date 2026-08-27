/**
 * Android hardware key attestation tests.
 *
 * Every chain here is built and signed for the test with real EC P-256 keys,
 * and the KeyDescription extension is hand-encoded to Google's ASN.1 schema —
 * so a passing test means the parser walked genuine DER, and a `chain_invalid`
 * means a real signature failed to verify.
 */

import { describe, expect, it } from 'vitest';
import { X509Certificate } from 'node:crypto';

import {
  ANDROID_KEY_ATTESTATION_OID,
  verifyAndroidKeyAttestation,
  type AndroidKeyAttestationOutcome,
} from './key-attestation.js';
import { parseTrustAnchors } from './x509.js';
import {
  generateEcKeyPair,
  keyDescription,
  makeAndroidChain,
  makeCertificate,
  extension,
  toJwk,
  toPem,
  type AuthorizationListOptions,
} from './fixtures.spec.js';

const NONCE = 'e3b0c44298fc1c149afbf4c8996fb924';
const PACKAGE = 'rw.gov.risa.sdid';
const DIGEST = Buffer.alloc(32, 0xa1).toString('base64');
const NOW = Date.UTC(2026, 7, 25, 12, 0, 0);

const HARDWARE_DEFAULTS: AuthorizationListOptions = {
  purposes: [2, 3],
  origin: 0,
  rootOfTrust: { deviceLocked: true, verifiedBootState: 0 },
  osVersion: 140000,
  osPatchLevel: 202601,
};

interface Scenario {
  outcome: AndroidKeyAttestationOutcome;
  deviceJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
}

function run(
  options: Partial<Parameters<typeof makeAndroidChain>[0]> & {
    nonce?: string;
    now?: number;
    anchorPem?: string;
    enrolDifferentKey?: boolean;
    chainOverride?: string;
  } = {},
): Scenario {
  const device = generateEcKeyPair();
  const other = generateEcKeyPair();
  const fixture = makeAndroidChain({
    devicePublicKey: device.publicKey,
    challenge: Buffer.from(NONCE, 'utf8'),
    hardwareEnforced: HARDWARE_DEFAULTS,
    now: NOW,
    ...options,
  });
  const deviceJwk = toJwk(options.enrolDifferentKey ? other.publicKey : device.publicKey);
  return {
    deviceJwk,
    outcome: verifyAndroidKeyAttestation({
      keyAttestation: options.chainOverride ?? fixture.chain,
      expectedNonce: options.nonce ?? NONCE,
      devicePublicKeyJwk: deviceJwk,
      packageName: PACKAGE,
      certificateDigests: [DIGEST],
      now: options.now ?? NOW,
      trustAnchors: parseTrustAnchors([options.anchorPem ?? fixture.rootPem]),
    }),
  };
}

function expectRejected(outcome: AndroidKeyAttestationOutcome, code: string): void {
  expect(outcome.ok, `expected rejection ${code}, got acceptance`).toBe(false);
  if (!outcome.ok) expect(outcome.code).toBe(code);
}

describe('verifyAndroidKeyAttestation — security levels', () => {
  it('accepts a TEE-attested key', () => {
    const { outcome } = run({ attestationSecurityLevel: 1, keymasterSecurityLevel: 1 });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.keySecurityLevel).toBe('trusted-environment');
    expect(outcome.evidence.attestationSecurityLevel).toBe('TrustedEnvironment');
    expect(outcome.evidence.deviceLocked).toBe(true);
    expect(outcome.evidence.keyOsPatchLevel).toBe(202601);
  });

  it('accepts a StrongBox-attested key and reports it as strongbox', () => {
    const { outcome } = run({ attestationSecurityLevel: 2, keymasterSecurityLevel: 2 });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.keySecurityLevel).toBe('strongbox');
  });

  it('accepts a software-level key rather than rejecting it (06 §6 degradation)', () => {
    const { outcome } = run({
      attestationSecurityLevel: 0,
      keymasterSecurityLevel: 0,
      hardwareEnforced: {},
      softwareEnforced: { origin: 0, purposes: [2, 3] },
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.keySecurityLevel).toBe('software');
  });

  it('takes the lower of the attestation and keymaster levels', () => {
    // A StrongBox *claim* signed by a software keymaster is not StrongBox.
    const { outcome } = run({ attestationSecurityLevel: 2, keymasterSecurityLevel: 0 });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.keySecurityLevel).toBe('software');
  });

  it('downgrades a hardware claim with an empty hardware-enforced list', () => {
    const { outcome } = run({
      attestationSecurityLevel: 1,
      keymasterSecurityLevel: 1,
      hardwareEnforced: {},
      softwareEnforced: { origin: 0 },
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.keySecurityLevel).toBe('software');
    expect(outcome.evidence.keySecurityDowngrades).toContain('empty hardware-enforced authorization list');
  });

  it('downgrades an imported key: it existed outside the secure world', () => {
    const { outcome } = run({
      hardwareEnforced: { ...HARDWARE_DEFAULTS, origin: 2 },
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.keySecurityLevel).toBe('software');
    expect(outcome.evidence.keyOrigin).toBe(2);
  });

  it('treats an unknown future security level as software', () => {
    const { outcome } = run({ attestationSecurityLevel: 7, keymasterSecurityLevel: 7 });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) expect(outcome.keySecurityLevel).toBe('software');
  });
});

describe('verifyAndroidKeyAttestation — bindings', () => {
  it('rejects a challenge that is not the nonce we issued (T4 replay)', () => {
    const { outcome } = run({ challenge: Buffer.from('a-nonce-from-another-session', 'utf8') });
    expectRejected(outcome, 'nonce_mismatch');
  });

  it('rejects an attestation over a different key (key_mismatch, never a downgrade)', () => {
    const { outcome } = run({ enrolDifferentKey: true });
    expectRejected(outcome, 'key_mismatch');
  });

  it('rejects a chain whose link does not verify', () => {
    const { outcome } = run({ breakChain: true });
    expectRejected(outcome, 'chain_invalid');
  });

  it('rejects a chain that does not reach the pinned root', () => {
    const stranger = makeAndroidChain({ devicePublicKey: generateEcKeyPair().publicKey, now: NOW });
    const { outcome } = run({ anchorPem: stranger.rootPem });
    expectRejected(outcome, 'chain_invalid');
  });

  it('rejects an expired leaf certificate', () => {
    const { outcome } = run({ leafNotAfter: NOW - 1000 });
    expectRejected(outcome, 'chain_invalid');
  });

  it('rejects a leaf that is not yet valid', () => {
    const { outcome } = run({ leafNotBefore: NOW + 3_600_000, leafNotAfter: NOW + 7_200_000 });
    expectRejected(outcome, 'chain_invalid');
  });

  it('rejects an intermediate that is not a CA', () => {
    // A leaf certificate must not be usable to sign another certificate.
    const root = generateEcKeyPair();
    const middle = generateEcKeyPair();
    const device = generateEcKeyPair();
    const rootCert = makeCertificate({
      subject: 'R', issuer: 'R', issuerPrivateKey: root.privateKey, subjectPublicKey: root.publicKey,
      ca: true, notBefore: NOW - 1000, notAfter: NOW + 1_000_000, serial: 1,
    });
    const middleCert = makeCertificate({
      subject: 'M', issuer: 'R', issuerPrivateKey: root.privateKey, subjectPublicKey: middle.publicKey,
      ca: false, notBefore: NOW - 1000, notAfter: NOW + 1_000_000, serial: 2,
    });
    const leafCert = makeCertificate({
      subject: 'L', issuer: 'M', issuerPrivateKey: middle.privateKey, subjectPublicKey: device.publicKey,
      ca: false, notBefore: NOW - 1000, notAfter: NOW + 1_000_000, serial: 3,
      extensions: [
        extension(
          ANDROID_KEY_ATTESTATION_OID,
          keyDescription({
            attestationSecurityLevel: 1,
            keymasterSecurityLevel: 1,
            challenge: Buffer.from(NONCE, 'utf8'),
            hardwareEnforced: HARDWARE_DEFAULTS,
          }),
        ),
      ],
    });
    const outcome = verifyAndroidKeyAttestation({
      keyAttestation: JSON.stringify([leafCert, middleCert, rootCert].map((c) => c.raw.toString('base64'))),
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(device.publicKey),
      packageName: PACKAGE,
      certificateDigests: [DIGEST],
      now: NOW,
      trustAnchors: [new X509Certificate(toPem(rootCert))],
    });
    expectRejected(outcome, 'chain_invalid');
  });

  it('fails closed when no trust anchor is configured', () => {
    const device = generateEcKeyPair();
    const fixture = makeAndroidChain({
      devicePublicKey: device.publicKey,
      challenge: Buffer.from(NONCE, 'utf8'),
      now: NOW,
    });
    const outcome = verifyAndroidKeyAttestation({
      keyAttestation: fixture.chain,
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(device.publicKey),
      packageName: PACKAGE,
      certificateDigests: [DIGEST],
      now: NOW,
      trustAnchors: [],
    });
    expectRejected(outcome, 'chain_invalid');
    if (!outcome.ok) expect(outcome.detail).toMatch(/no trust anchors/);
  });
});

describe('verifyAndroidKeyAttestation — device and app state', () => {
  it('rejects an unlocked bootloader (T2)', () => {
    const { outcome } = run({
      hardwareEnforced: { ...HARDWARE_DEFAULTS, rootOfTrust: { deviceLocked: false, verifiedBootState: 0 } },
    });
    expectRejected(outcome, 'device_integrity');
  });

  it('rejects a device that did not boot verified', () => {
    const { outcome } = run({
      hardwareEnforced: { ...HARDWARE_DEFAULTS, rootOfTrust: { deviceLocked: true, verifiedBootState: 2 } },
    });
    expectRejected(outcome, 'device_integrity');
  });

  it('accepts an attestation whose application id names our package', () => {
    const { outcome } = run({
      softwareEnforced: {
        attestationApplicationId: {
          packageNames: [PACKAGE],
          signatureDigests: [Buffer.from(DIGEST, 'base64')],
        },
      },
    });
    expect(outcome.ok).toBe(true);
  });

  it('rejects an attestation minted for another app', () => {
    const { outcome } = run({
      softwareEnforced: {
        attestationApplicationId: {
          packageNames: ['com.attacker.clone'],
          signatureDigests: [Buffer.from(DIGEST, 'base64')],
        },
      },
    });
    expectRejected(outcome, 'app_mismatch');
  });

  it('rejects an attestation signed by a certificate that is not ours', () => {
    const { outcome } = run({
      softwareEnforced: {
        attestationApplicationId: {
          packageNames: [PACKAGE],
          signatureDigests: [Buffer.alloc(32, 0xbb)],
        },
      },
    });
    expectRejected(outcome, 'app_mismatch');
  });
});

describe('verifyAndroidKeyAttestation — malformed input', () => {
  it('rejects a chain that is not base64', () => {
    const { outcome } = run({ chainOverride: '["not base64!!"]' });
    expectRejected(outcome, 'malformed');
  });

  it('rejects base64 that is not a certificate', () => {
    const { outcome } = run({ chainOverride: JSON.stringify([Buffer.alloc(64, 7).toString('base64')]) });
    expectRejected(outcome, 'malformed');
  });

  it('rejects an oversized chain string before scanning it', () => {
    const started = process.hrtime.bigint();
    expectRejected(run({ chainOverride: 'A'.repeat(2_000_000) }).outcome, 'malformed');
    expect(Number(process.hrtime.bigint() - started) / 1e6).toBeLessThan(500);
  });

  it('rejects an empty or absurd chain container', () => {
    expectRejected(run({ chainOverride: '   ' }).outcome, 'malformed');
    expectRejected(run({ chainOverride: '[' }).outcome, 'malformed');
    expectRejected(run({ chainOverride: '[1,2,3]' }).outcome, 'malformed');
    expectRejected(
      run({ chainOverride: JSON.stringify(Array.from({ length: 20 }, () => 'QUJD')) }).outcome,
      'malformed',
    );
  });

  it('rejects a leaf with no key attestation extension', () => {
    const { outcome } = run({ omitExtension: true });
    expectRejected(outcome, 'malformed');
  });

  it('rejects a truncated KeyDescription', () => {
    const { outcome } = run({
      keyDescriptionOverride: keyDescription({
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
        challenge: Buffer.from(NONCE, 'utf8'),
        truncate: true,
      }),
    });
    expectRejected(outcome, 'malformed');
  });

  it('rejects a KeyDescription that is not DER at all', () => {
    const { outcome } = run({ keyDescriptionOverride: Buffer.from('ffffffff', 'hex') });
    expectRejected(outcome, 'malformed');
  });
});

describe('parseCertificateChainInput — accepted containers', () => {
  it('accepts a PEM bundle and a whitespace-separated list', () => {
    const device = generateEcKeyPair();
    const fixture = makeAndroidChain({
      devicePublicKey: device.publicKey,
      challenge: Buffer.from(NONCE, 'utf8'),
      hardwareEnforced: HARDWARE_DEFAULTS,
      now: NOW,
    });
    const anchors = parseTrustAnchors([fixture.rootPem]);
    const base = {
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(device.publicKey),
      packageName: PACKAGE,
      certificateDigests: [DIGEST],
      now: NOW,
      trustAnchors: anchors,
    };
    const pemBundle = fixture.certificates.map((cert) => toPem(cert)).join('\n');
    const spaceSeparated = fixture.certificates.map((cert) => cert.raw.toString('base64')).join(' ');

    expect(verifyAndroidKeyAttestation({ ...base, keyAttestation: pemBundle }).ok).toBe(true);
    expect(verifyAndroidKeyAttestation({ ...base, keyAttestation: spaceSeparated }).ok).toBe(true);
  });
});
