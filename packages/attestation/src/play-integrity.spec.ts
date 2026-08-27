/**
 * Play Integrity verifier tests, driven through the public
 * `createAttestationVerifiers` factory so the assurance derivation and the
 * key-attestation hand-off are exercised together, exactly as the broker will
 * use them.
 */

import { describe, expect, it } from 'vitest';

import { createAttestationVerifiers } from './index.js';
import type { AttestationResult, PlayIntegrityTokenDecoder } from './types.js';
import { generateEcKeyPair, makeAndroidChain, toJwk, type AuthorizationListOptions } from './fixtures.spec.js';

const PACKAGE = 'rw.gov.risa.sdid';
const DIGEST = Buffer.alloc(32, 0xa1).toString('base64');
const NONCE = 'f47ac10b58cc4372a5670e02b2c3d479';
const NOW = Date.UTC(2026, 7, 25, 12, 0, 0);
const TOKEN = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.play-integrity-token';

const HARDWARE_TEE: AuthorizationListOptions = {
  purposes: [2, 3],
  origin: 0,
  rootOfTrust: { deviceLocked: true, verifiedBootState: 0 },
};

interface PayloadOverrides {
  requestPackageName?: string;
  nonce?: string;
  timestampMillis?: unknown;
  appRecognitionVerdict?: string;
  appPackageName?: string;
  certificateDigests?: string[] | null;
  deviceVerdicts?: string[] | null;
  wrap?: boolean;
}

function payload(overrides: PayloadOverrides = {}): unknown {
  const appIntegrity: Record<string, unknown> = {
    appRecognitionVerdict: overrides.appRecognitionVerdict ?? 'PLAY_RECOGNIZED',
    packageName: overrides.appPackageName ?? PACKAGE,
    versionCode: '1201',
  };
  if (overrides.certificateDigests !== null) {
    appIntegrity.certificateSha256Digest = overrides.certificateDigests ?? [DIGEST];
  }
  const deviceIntegrity: Record<string, unknown> = {};
  if (overrides.deviceVerdicts !== null) {
    deviceIntegrity.deviceRecognitionVerdict = overrides.deviceVerdicts ?? [
      'MEETS_BASIC_INTEGRITY',
      'MEETS_DEVICE_INTEGRITY',
    ];
  }
  const body = {
    requestDetails: {
      requestPackageName: overrides.requestPackageName ?? PACKAGE,
      nonce: overrides.nonce ?? NONCE,
      timestampMillis:
        'timestampMillis' in overrides ? overrides.timestampMillis : String(NOW - 1000),
    },
    appIntegrity,
    deviceIntegrity,
    accountDetails: { appLicensingVerdict: 'LICENSED' },
  };
  return overrides.wrap ? { tokenPayloadExternal: body } : body;
}

interface Harness {
  verify: (options?: {
    decoded?: unknown;
    decodeToken?: PlayIntegrityTokenDecoder;
    keyAttestation?: string | null;
    nonce?: string;
    now?: number;
    requireStrongBox?: boolean;
    attestationSecurityLevel?: number;
    keymasterSecurityLevel?: number;
    enrolDifferentKey?: boolean;
  }) => Promise<AttestationResult>;
}

const harness: Harness = {
  async verify(options = {}) {
    const device = generateEcKeyPair();
    const other = generateEcKeyPair();
    const fixture = makeAndroidChain({
      devicePublicKey: device.publicKey,
      challenge: Buffer.from(NONCE, 'utf8'),
      attestationSecurityLevel: options.attestationSecurityLevel ?? 1,
      keymasterSecurityLevel: options.keymasterSecurityLevel ?? 1,
      hardwareEnforced: HARDWARE_TEE,
      now: NOW,
    });
    // `in`, not `??`: a test that decodes to `null` must reach the verifier as
    // null, not quietly fall back to a valid payload.
    const decoded = 'decoded' in options ? options.decoded : payload();
    const decodeToken: PlayIntegrityTokenDecoder = options.decodeToken ?? (async () => decoded);

    const verifiers = createAttestationVerifiers(
      {
        android: {
          packageName: PACKAGE,
          certificateDigests: [DIGEST],
          decodeToken,
          ...(options.requireStrongBox === undefined ? {} : { requireStrongBox: options.requireStrongBox }),
        },
        ios: { appId: 'ABCDE12345.rw.gov.risa.sdid', production: true },
      },
      { androidRootCertificatesPem: [fixture.rootPem] },
    );

    const request = {
      token: TOKEN,
      expectedNonce: options.nonce ?? NONCE,
      devicePublicKeyJwk: toJwk(options.enrolDifferentKey ? other.publicKey : device.publicKey),
      now: options.now ?? NOW,
      ...(options.keyAttestation === null ? {} : { keyAttestation: options.keyAttestation ?? fixture.chain }),
    };
    return verifiers.android.verify(request);
  },
};

function expectRejected(result: AttestationResult, code: string): void {
  expect(result.ok, `expected rejection ${code}, got acceptance`).toBe(false);
  if (!result.ok) expect(result.code).toBe(code);
}

describe('PlayIntegrityVerifier — acceptance and assurance', () => {
  it('accepts a genuine app on a sound device with a TEE key → AL2', async () => {
    const result = await harness.verify();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.platform).toBe('android');
    expect(result.appGenuine).toBe(true);
    expect(result.keySecurityLevel).toBe('trusted-environment');
    expect(result.assuranceCap).toBe('AL2');
    expect(result.evidence.appRecognitionVerdict).toBe('PLAY_RECOGNIZED');
    expect(result.evidence.deviceRecognitionVerdict).toEqual([
      'MEETS_BASIC_INTEGRITY',
      'MEETS_DEVICE_INTEGRITY',
    ]);
    expect(result.evidence.appVersionCode).toBe('1201');
  });

  it('accepts a StrongBox key and reports the stronger level', async () => {
    const result = await harness.verify({ attestationSecurityLevel: 2, keymasterSecurityLevel: 2 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.keySecurityLevel).toBe('strongbox');
    expect(result.assuranceCap).toBe('AL2');
  });

  it('caps a TEE key at AL1 when the deployment requires StrongBox', async () => {
    const result = await harness.verify({ requireStrongBox: true });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.assuranceCap).toBe('AL1');
  });

  it('accepts a sound device with no key attestation at all, capped at AL1', async () => {
    const result = await harness.verify({ keyAttestation: null });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.keySecurityLevel).toBe('software');
    expect(result.assuranceCap).toBe('AL1');
    expect(result.evidence.keyAttestationPresent).toBe(false);
  });

  it('accepts MEETS_STRONG_INTEGRITY as satisfying device integrity', async () => {
    const result = await harness.verify({
      decoded: payload({ deviceVerdicts: ['MEETS_STRONG_INTEGRITY', 'MEETS_DEVICE_INTEGRITY'] }),
    });
    expect(result.ok).toBe(true);
  });

  it('accepts the tokenPayloadExternal wrapper Google actually returns', async () => {
    const result = await harness.verify({ decoded: payload({ wrap: true }) });
    expect(result.ok).toBe(true);
  });

  it('never puts the token, chain or an identifier into the evidence', async () => {
    const result = await harness.verify();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const serialised = JSON.stringify(result.evidence);
    expect(serialised).not.toContain(TOKEN);
    expect(serialised).not.toContain(NONCE);
    expect(serialised).not.toContain('BEGIN CERTIFICATE');
  });
});

describe('PlayIntegrityVerifier — device and app integrity', () => {
  it('rejects MEETS_BASIC_INTEGRITY on its own — the rooted-device hole', async () => {
    const result = await harness.verify({ decoded: payload({ deviceVerdicts: ['MEETS_BASIC_INTEGRITY'] }) });
    expectRejected(result, 'device_integrity');
  });

  it('rejects a device that meets nothing (verdict list absent, as Google sends it)', async () => {
    const result = await harness.verify({ decoded: payload({ deviceVerdicts: null }) });
    expectRejected(result, 'device_integrity');
  });

  it('rejects an emulator-style verdict list', async () => {
    const result = await harness.verify({
      decoded: payload({ deviceVerdicts: ['MEETS_VIRTUAL_INTEGRITY'] }),
    });
    expectRejected(result, 'device_integrity');
  });

  it('rejects a build Play does not recognise', async () => {
    const result = await harness.verify({
      decoded: payload({ appRecognitionVerdict: 'UNRECOGNIZED_VERSION' }),
    });
    expectRejected(result, 'app_integrity');
  });
});

describe('PlayIntegrityVerifier — identity and freshness binding', () => {
  it('rejects a token issued for another package', async () => {
    const result = await harness.verify({ decoded: payload({ requestPackageName: 'com.attacker.app' }) });
    expectRejected(result, 'app_mismatch');
  });

  it('rejects a mismatch between requestDetails and appIntegrity package names', async () => {
    const result = await harness.verify({ decoded: payload({ appPackageName: 'com.attacker.app' }) });
    expectRejected(result, 'app_mismatch');
  });

  it('rejects a repackaged clone signed with another certificate', async () => {
    const result = await harness.verify({
      decoded: payload({ certificateDigests: [Buffer.alloc(32, 0xbb).toString('base64')] }),
    });
    expectRejected(result, 'app_mismatch');
  });

  it('rejects a token with no signing digest at all', async () => {
    const result = await harness.verify({ decoded: payload({ certificateDigests: null }) });
    expectRejected(result, 'app_mismatch');
  });

  it('rejects a token carrying someone else’s nonce (T4 replay)', async () => {
    const result = await harness.verify({ decoded: payload({ nonce: 'a-harvested-nonce' }) });
    expectRejected(result, 'nonce_mismatch');
  });

  it('rejects an enrolment with no expected nonce rather than comparing nothing', async () => {
    const result = await harness.verify({ nonce: '' });
    expectRejected(result, 'nonce_mismatch');
  });

  it('rejects a token older than the freshness window', async () => {
    const result = await harness.verify({ now: NOW + 6 * 60 * 1000 });
    expectRejected(result, 'stale');
  });

  it('rejects a token timestamped in the future beyond clock skew', async () => {
    const result = await harness.verify({
      decoded: payload({ timestampMillis: String(NOW + 10 * 60 * 1000) }),
    });
    expectRejected(result, 'stale');
  });

  it('tolerates a small clock skew', async () => {
    const result = await harness.verify({ decoded: payload({ timestampMillis: String(NOW + 30_000) }) });
    expect(result.ok).toBe(true);
  });

  it('propagates a key-attestation key mismatch rather than downgrading', async () => {
    const result = await harness.verify({ enrolDifferentKey: true });
    expectRejected(result, 'key_mismatch');
  });
});

describe('PlayIntegrityVerifier — decoder failures and malformed payloads', () => {
  it('fails closed when the decoder throws', async () => {
    const result = await harness.verify({
      decodeToken: () => {
        throw new Error('service account credentials rejected');
      },
    });
    expectRejected(result, 'verifier_unavailable');
  });

  it('fails closed when the decoder rejects', async () => {
    const result = await harness.verify({
      decodeToken: async () => {
        throw new Error('deadline exceeded');
      },
    });
    expectRejected(result, 'verifier_unavailable');
  });

  it('rejects payloads that are not objects', async () => {
    for (const decoded of [null, 'PLAY_RECOGNIZED', 42, ['a']]) {
      expectRejected(await harness.verify({ decoded }), 'malformed');
    }
  });

  it('rejects payloads missing the sections we depend on', async () => {
    expectRejected(await harness.verify({ decoded: {} }), 'malformed');
    expectRejected(await harness.verify({ decoded: { requestDetails: {} } }), 'malformed');
    expectRejected(
      await harness.verify({ decoded: { requestDetails: { requestPackageName: PACKAGE, nonce: NONCE } } }),
      'malformed',
    );
  });

  it('rejects a timestamp that is not an int64', async () => {
    for (const timestampMillis of ['not-a-number', '-1', '', 0, 1.5, {}, null]) {
      expectRejected(await harness.verify({ decoded: payload({ timestampMillis }) }), 'malformed');
    }
  });

  it('rejects a verdict list that is not a list of strings', async () => {
    expectRejected(
      await harness.verify({ decoded: payload({ deviceVerdicts: [1 as unknown as string] }) }),
      'malformed',
    );
  });

  it('rejects an empty or oversized token before calling the decoder', async () => {
    let called = false;
    const verifiers = createAttestationVerifiers(
      {
        android: {
          packageName: PACKAGE,
          certificateDigests: [DIGEST],
          decodeToken: async () => {
            called = true;
            return payload();
          },
        },
        ios: { appId: 'ABCDE12345.rw.gov.risa.sdid', production: true },
      },
      { androidRootCertificatesPem: [] },
    );
    const base = {
      expectedNonce: NONCE,
      devicePublicKeyJwk: toJwk(generateEcKeyPair().publicKey),
      now: NOW,
    };
    expectRejected(await verifiers.android.verify({ ...base, token: '' }), 'malformed');
    expectRejected(await verifiers.android.verify({ ...base, token: 'x'.repeat(70_000) }), 'malformed');
    expect(called).toBe(false);
  });
});
