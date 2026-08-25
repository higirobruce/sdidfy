/**
 * Factory, configuration and assurance-derivation tests, plus pin checks on
 * the embedded platform roots.
 */

import { describe, expect, it } from 'vitest';
import { X509Certificate, createHash } from 'node:crypto';

import {
  APPLE_APP_ATTEST_ROOT_PEM,
  AttestationConfigurationError,
  GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM,
  createAttestationVerifiers,
  deriveAssuranceCap,
} from './index.js';
import type { AttestationVerifierConfig } from './types.js';

const baseConfig = (): AttestationVerifierConfig => ({
  android: {
    packageName: 'rw.gov.risa.sdid',
    certificateDigests: [Buffer.alloc(32, 0xa1).toString('base64')],
    decodeToken: async () => ({}),
  },
  ios: { appId: 'ABCDE12345.rw.gov.risa.sdid', production: true },
});

describe('createAttestationVerifiers — configuration', () => {
  it('builds a verifier for each platform', () => {
    const verifiers = createAttestationVerifiers(baseConfig());
    expect(verifiers.android.platform).toBe('android');
    expect(verifiers.ios.platform).toBe('ios');
  });

  it('refuses an empty certificateDigests list rather than accepting any signer', () => {
    const config = baseConfig();
    config.android.certificateDigests = [];
    expect(() => createAttestationVerifiers(config)).toThrow(AttestationConfigurationError);
    expect(() => createAttestationVerifiers(config)).toThrow(/certificateDigests/);
  });

  it('refuses an empty digest entry', () => {
    const config = baseConfig();
    config.android.certificateDigests = [''];
    expect(() => createAttestationVerifiers(config)).toThrow(/empty entry/);
  });

  it('refuses a missing package name or decoder', () => {
    const noPackage = baseConfig();
    noPackage.android.packageName = '   ';
    expect(() => createAttestationVerifiers(noPackage)).toThrow(/packageName/);

    const noDecoder = baseConfig();
    (noDecoder.android as { decodeToken?: unknown }).decodeToken = undefined;
    expect(() => createAttestationVerifiers(noDecoder)).toThrow(/decodeToken/);
  });

  it('refuses an App ID that is not <teamId>.<bundleId>', () => {
    for (const appId of ['', 'no-dot', '.leading', 'ABCDE12345.']) {
      const config = baseConfig();
      config.ios.appId = appId;
      expect(() => createAttestationVerifiers(config), appId).toThrow(/appId/);
    }
  });

  it('refuses an unset production flag rather than guessing', () => {
    const config = baseConfig();
    (config.ios as { production?: unknown }).production = undefined;
    expect(() => createAttestationVerifiers(config)).toThrow(/production/);
  });

  it('refuses a nonsensical token age', () => {
    for (const maxTokenAgeMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const config = { ...baseConfig(), maxTokenAgeMs };
      expect(() => createAttestationVerifiers(config)).toThrow(/maxTokenAgeMs/);
    }
  });

  it('refuses trust anchors that are not certificates', () => {
    expect(() =>
      createAttestationVerifiers(baseConfig(), { androidRootCertificatesPem: ['not a certificate'] }),
    ).toThrow(/android trust anchors/);

    const config = baseConfig();
    config.ios.rootCertificatesPem = ['also not a certificate'];
    expect(() => createAttestationVerifiers(config)).toThrow(/ios trust anchors/);
  });

  it('accepts an explicitly empty android anchor list at construction but fails closed at verify', async () => {
    // An operator who supplies no pins gets a verifier that cannot accept a
    // key attestation — never one that accepts an unverified chain.
    const verifiers = createAttestationVerifiers(baseConfig(), { androidRootCertificatesPem: [] });
    const result = await verifiers.android.verify({
      token: 'token',
      keyAttestation: 'QUJD',
      expectedNonce: 'n',
      devicePublicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      now: Date.now(),
    });
    expect(result.ok).toBe(false);
  });
});

describe('deriveAssuranceCap', () => {
  it('grants AL2 only for a genuine app with a hardware-backed key', () => {
    expect(deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'strongbox' })).toBe('AL2');
    expect(deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'trusted-environment' })).toBe('AL2');
    expect(deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'software' })).toBe('AL1');
    expect(deriveAssuranceCap({ appGenuine: false, keySecurityLevel: 'strongbox' })).toBe('AL1');
  });

  it('requires StrongBox specifically when the deployment says so', () => {
    const requireStrongBox = true;
    expect(deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'strongbox', requireStrongBox })).toBe('AL2');
    expect(
      deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'trusted-environment', requireStrongBox }),
    ).toBe('AL1');
    expect(deriveAssuranceCap({ appGenuine: true, keySecurityLevel: 'software', requireStrongBox })).toBe('AL1');
  });

  it('never returns AL3 — that needs SDID re-assertion (03 §6)', () => {
    const levels = ['software', 'trusted-environment', 'strongbox'] as const;
    for (const keySecurityLevel of levels) {
      for (const appGenuine of [true, false]) {
        for (const requireStrongBox of [true, false]) {
          expect(['AL1', 'AL2']).toContain(
            deriveAssuranceCap({ appGenuine, keySecurityLevel, requireStrongBox }),
          );
        }
      }
    }
  });
});

describe('pinned platform roots', () => {
  const fingerprint = (pem: string): string =>
    createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');

  it('are the certificates documented in roots.ts, byte for byte', () => {
    // These digests are the deployment gate: if a pin ever changes, this test
    // fails and the change has to be justified against the vendor's own
    // publication (see the provenance header in roots.ts).
    expect(GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM.map(fingerprint)).toEqual([
      'cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc',
      '6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0',
    ]);
    expect(fingerprint(APPLE_APP_ATTEST_ROOT_PEM)).toBe(
      '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932',
    );
  });

  it('are self-signed CAs naming the vendors we expect', () => {
    const apple = new X509Certificate(APPLE_APP_ATTEST_ROOT_PEM);
    expect(apple.subject).toContain('Apple App Attestation Root CA');
    expect(apple.ca).toBe(true);
    expect(apple.verify(apple.publicKey)).toBe(true);

    const [googleRsa, googleEc] = GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM.map(
      (pem) => new X509Certificate(pem),
    );
    expect(googleRsa!.subject).toContain('f92009e853b6b045');
    expect(googleRsa!.ca).toBe(true);
    expect(googleRsa!.verify(googleRsa!.publicKey)).toBe(true);
    expect(googleEc!.subject).toContain('Key Attestation CA1');
    expect(googleEc!.ca).toBe(true);
    expect(googleEc!.verify(googleEc!.publicKey)).toBe(true);
  });

  it('are still inside their validity windows', () => {
    const now = Date.now();
    for (const pem of [...GOOGLE_HARDWARE_ATTESTATION_ROOTS_PEM, APPLE_APP_ATTEST_ROOT_PEM]) {
      const cert = new X509Certificate(pem);
      expect(cert.validFromDate.getTime(), cert.subject).toBeLessThan(now);
      expect(cert.validToDate.getTime(), cert.subject).toBeGreaterThan(now);
    }
  });
});

describe('fail-closed behaviour', () => {
  it('turns an unexpected verifier fault into verifier_unavailable, never an acceptance', async () => {
    const config = baseConfig();
    // A payload whose property access throws: nothing in the verifier should
    // let that escape as an exception, and it must not be read as a verdict.
    config.android.decodeToken = async () =>
      new Proxy(
        {},
        {
          get() {
            throw new Error('exploding payload');
          },
          has() {
            return true;
          },
        },
      );
    const verifiers = createAttestationVerifiers(config);
    const result = await verifiers.android.verify({
      token: 'token',
      expectedNonce: 'nonce',
      devicePublicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      now: Date.now(),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(['verifier_unavailable', 'malformed']).toContain(result.code);
  });
});
