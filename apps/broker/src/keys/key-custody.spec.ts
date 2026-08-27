import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import type { Pool } from 'pg';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AdapterBackedKeyCustody,
  createUnconfiguredCustody,
  type RemoteCustodyAdapter,
  type RemoteKeyDescriptor,
} from './adapter-custody.js';
import {
  ALG_COORDINATE_BYTES,
  KeyCustodyNotConfiguredError,
  KeyCustodyRotationUnsupportedError,
  assertJwsSignatureShape,
  derEcdsaToJoseSignature,
  normalizeEcdsaSignature,
} from './key-custody.js';
import { createHsmPkcs11Custody, registerHsmAdapterFactory, resetHsmAdapterFactory } from './hsm-pkcs11.custody.js';
import { createKmsCustody, registerKmsAdapterFactory, resetKmsAdapterFactory } from './kms.custody.js';
import { PostgresDevKeyCustody } from './postgres-dev.custody.js';

/**
 * Unit tests for the custody boundary itself (06 §3, T13, decision #5) — no
 * Postgres, no Nest. The integration side (JWKS verification through the whole
 * signing path, rotation overlap, readiness, the usage audit) lives in
 * `keys.service.spec.ts`.
 */

// ---------------------------------------------------------------------------
// DER → JWS r||s
// ---------------------------------------------------------------------------

describe('ECDSA signature encoding (RFC 7515 §3.4)', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const message = Buffer.from('sdid-bridge:v1:signing-input', 'utf8');

  it('converts a real DER signature into a verifiable 64-byte r||s', () => {
    // `dsaEncoding: 'der'` is what a KMS or PKCS#11 backend typically hands
    // back; the JWS form is what a relying party will accept.
    const der = cryptoSign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const jws = derEcdsaToJoseSignature(der, ALG_COORDINATE_BYTES.ES256);
    expect(jws.length).toBe(64);
    expect(
      cryptoVerify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, jws),
    ).toBe(true);
  });

  it('survives many signatures, including the ones with short or sign-padded integers', () => {
    // A DER INTEGER is minimally encoded and signed: r or s can be shorter
    // than 32 bytes, or carry a leading 0x00. Both shapes appear naturally,
    // just not often — so hammer it rather than hoping one turns up.
    for (let i = 0; i < 200; i += 1) {
      const der = cryptoSign('sha256', Buffer.from(`msg-${i}`), {
        key: privateKey,
        dsaEncoding: 'der',
      });
      const jws = derEcdsaToJoseSignature(der, 32);
      expect(jws.length).toBe(64);
      expect(
        cryptoVerify('sha256', Buffer.from(`msg-${i}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, jws),
      ).toBe(true);
    }
  });

  it('left-pads a short r and strips the DER sign byte from s', () => {
    // Hand-built: r = 0x01 (one byte), s = 0x00FF…  (sign byte + 32 bytes).
    const r = Buffer.from([0x01]);
    const s = Buffer.concat([Buffer.from([0x00]), Buffer.alloc(32, 0xff)]);
    const der = Buffer.concat([
      Buffer.from([0x30, 2 + r.length + 2 + s.length]),
      Buffer.from([0x02, r.length]),
      r,
      Buffer.from([0x02, s.length]),
      s,
    ]);
    const jws = derEcdsaToJoseSignature(der, 32);
    expect(jws.length).toBe(64);
    expect(Buffer.from(jws.subarray(0, 32)).toString('hex')).toBe('00'.repeat(31) + '01');
    expect(Buffer.from(jws.subarray(32)).toString('hex')).toBe('ff'.repeat(32));
  });

  it('passes a raw r||s signature through untouched', () => {
    const raw = cryptoSign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    expect(normalizeEcdsaSignature(raw)).toBe(raw);
  });

  it('autodetects DER without being told', () => {
    const der = cryptoSign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const jws = normalizeEcdsaSignature(der);
    expect(jws.length).toBe(64);
  });

  it('rejects garbage rather than producing a plausible-looking signature', () => {
    expect(() => normalizeEcdsaSignature(new Uint8Array(31))).toThrow(/neither raw/);
    expect(() => derEcdsaToJoseSignature(new Uint8Array([0x31, 0x02]), 32)).toThrow(/SEQUENCE/);
  });

  it('refuses a wrong-length signature before it becomes a token', () => {
    expect(() => assertJwsSignatureShape(new Uint8Array(70), 'ES256')).toThrow(/requires exactly 64/);
    expect(() => assertJwsSignatureShape(new Uint8Array(64), 'ES256')).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// The dev store refuses production
// ---------------------------------------------------------------------------

describe('postgres-dev custody in production', () => {
  it('refuses to construct, naming decision #5 and the alternatives', () => {
    // The pool is never touched: the constructor throws first.
    expect(() => new PostgresDevKeyCustody({} as Pool, 'production')).toThrow(/decision #5/);
    expect(() => new PostgresDevKeyCustody({} as Pool, 'production')).toThrow(
      /KEY_CUSTODY=kms|kms\.custody\.ts/,
    );
  });

  it('constructs anywhere else', () => {
    expect(() => new PostgresDevKeyCustody({} as Pool, 'development')).not.toThrow();
    expect(() => new PostgresDevKeyCustody({} as Pool, 'test')).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Declared seams: unconfigured is loud, and is never "no key"
// ---------------------------------------------------------------------------

describe('unconfigured KMS / HSM custody (declared seams)', () => {
  afterEach(() => {
    resetKmsAdapterFactory();
    resetHsmAdapterFactory();
  });

  const blankKms = { endpoint: '', keyGroup: '', credentials: '' };
  const blankHsm = { libraryPath: '', slot: '', keyLabel: '', pin: '' };

  it('names the missing KMS settings', async () => {
    const custody = createKmsCustody(blankKms);
    await expect(custody.init()).rejects.toThrow(
      /missing KMS_ENDPOINT, KMS_KEY_GROUP, KMS_CREDENTIALS/,
    );
  });

  it('names the missing HSM settings and never echoes the PIN', async () => {
    const custody = createHsmPkcs11Custody({ ...blankHsm, pin: 'super-secret-pin' });
    const err = await custody.init().then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/missing HSM_PKCS11_LIBRARY, HSM_SLOT, HSM_KEY_LABEL/);
    expect(err?.message).not.toContain('super-secret-pin');
  });

  it('says "configured but no adapter" once the settings are there', async () => {
    const custody = createKmsCustody({
      endpoint: 'https://kms.gov.rw',
      keyGroup: 'broker-signing',
      credentials: '/run/secrets/kms',
    });
    await expect(custody.init()).rejects.toThrow(/registerKmsAdapterFactory/);
  });

  it('tells an HSM operator that PKCS#11 needs an FFI binding chosen with the device', async () => {
    const custody = createHsmPkcs11Custody({
      libraryPath: '/usr/lib/softhsm/libsofthsm2.so',
      slot: '0',
      keyLabel: 'broker-signing',
      pin: 'pin',
    });
    await expect(custody.init()).rejects.toThrow(/registerHsmAdapterFactory/);
  });

  it('THROWS from every key operation — an unconfigured seam is never "no key"', async () => {
    const custody = createKmsCustody(blankKms);
    // The distinction is the whole point: "we have no custody backend" and
    // "the backend has no keys" lead an operator to opposite actions, and only
    // the first is true here. An empty JWKS would read as the second.
    for (const call of [
      () => custody.activeKid(),
      () => custody.listPublicJwks(),
      () => custody.listKeys(),
      () => custody.sign('any-kid', new Uint8Array([1, 2, 3])),
      () => custody.rotate(),
    ]) {
      const err = await call().then(
        () => null,
        (e: unknown) => e as Error,
      );
      expect(err).toBeInstanceOf(KeyCustodyNotConfiguredError);
      expect(err?.message).toMatch(/not configured/);
    }
  });

  it('REPORTS unhealthy from healthCheck instead of throwing, so /readyz can answer', async () => {
    const custody = createKmsCustody(blankKms);
    const health = await custody.healthCheck();
    expect(health.healthy).toBe(false);
    expect(health.provider).toBe('kms');
    expect(health.activeKid).toBeNull();
    expect(health.detail).toMatch(/not configured/);
  });

  it('claims no capabilities it cannot deliver', () => {
    expect(createKmsCustody(blankKms).capabilities).toEqual({
      rotate: false,
      generateOnDemand: false,
    });
  });

  it('createUnconfiguredCustody carries the caller\'s own message through', async () => {
    const custody = createUnconfiguredCustody('hsm', 'the vault is on fire');
    await expect(custody.sign('k', new Uint8Array())).rejects.toThrow('the vault is on fire');
    expect((await custody.healthCheck()).detail).toBe('the vault is on fire');
  });
});

// ---------------------------------------------------------------------------
// The adapter seam, exercised with an in-memory backend
// ---------------------------------------------------------------------------

/**
 * A deployment-supplied adapter, behaving the way a real KMS does in the two
 * ways that matter: it returns the public key as SPKI DER, and it returns
 * DER-encoded ECDSA signatures. If the engine handles this it handles the
 * common case, and it proves the seam is a genuine boundary rather than a
 * Postgres-shaped hole with a different name.
 */
function inMemoryKmsAdapter(): RemoteCustodyAdapter & { rotations: number } {
  interface Slot {
    descriptor: RemoteKeyDescriptor;
    publicKey: KeyObject;
    privateKey: KeyObject;
  }
  const slots: Slot[] = [];
  let counter = 0;
  const mint = (status: 'active' | 'retired'): Slot => {
    counter += 1;
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const slot: Slot = {
      descriptor: {
        keyRef: `vault://keys/broker-signing/${counter}`,
        kid: `inmem-kid-${counter}`,
        alg: 'ES256',
        status,
        createdAt: new Date(1_700_000_000_000 + counter),
      },
      publicKey,
      privateKey,
    };
    slots.push(slot);
    return slot;
  };
  mint('active');

  const adapter: RemoteCustodyAdapter & { rotations: number } = {
    name: 'in-memory-kms',
    rotations: 0,
    async listKeys() {
      return slots.map((s) => s.descriptor);
    },
    async getPublicKey(key) {
      const slot = slots.find((s) => s.descriptor.kid === key.kid);
      if (!slot) throw new Error(`unknown key ${key.kid}`);
      // SPKI DER, exactly as a KMS GetPublicKey would return it.
      return new Uint8Array(slot.publicKey.export({ format: 'der', type: 'spki' }));
    },
    async sign({ key, data }) {
      const slot = slots.find((s) => s.descriptor.kid === key.kid);
      if (!slot) throw new Error(`unknown key ${key.kid}`);
      // DER, exactly as most KMS and PKCS#11 CKM_ECDSA implementations do.
      return new Uint8Array(cryptoSign('sha256', data, { key: slot.privateKey, dsaEncoding: 'der' }));
    },
    async rotate() {
      adapter.rotations += 1;
      const retiredKids: string[] = [];
      for (const slot of slots) {
        if (slot.descriptor.status === 'active') {
          slot.descriptor.status = 'retired';
          retiredKids.push(slot.descriptor.kid);
        }
      }
      const promoted = mint('active');
      return { promotedKid: promoted.descriptor.kid, retiredKids };
    },
  };
  return adapter;
}

describe('adapter-backed custody (the KMS/HSM engine)', () => {
  afterEach(() => {
    resetKmsAdapterFactory();
  });

  it('signs through a registered adapter and publishes a JWKS the signature verifies against', async () => {
    const adapter = inMemoryKmsAdapter();
    registerKmsAdapterFactory(() => adapter);
    const custody = createKmsCustody({
      endpoint: 'https://kms.gov.rw',
      keyGroup: 'broker-signing',
      credentials: '/run/secrets/kms',
    });
    await custody.init();

    const kid = await custody.activeKid();
    expect(kid).toBe('inmem-kid-1');
    const data = Buffer.from('header.payload', 'utf8');
    const signature = await custody.sign(kid, data);
    // The adapter returned DER; the engine handed back the JWS form.
    expect(signature.length).toBe(64);

    const jwks = await custody.listPublicJwks();
    const jwk = jwks.keys.find((k) => k.kid === kid);
    expect(jwk).toBeDefined();
    expect(jwk?.kty).toBe('EC');
    expect(jwk?.use).toBe('sig');
    // SPKI DER became a JWK, and the JWK verifies the signature.
    const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
    expect(cryptoVerify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)).toBe(
      true,
    );
  });

  it('never publishes a private component even if a backend hands one back', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const leaky = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;
    expect(leaky.d).toBeTypeOf('string'); // the fixture really is private
    const custody = new AdapterBackedKeyCustody('kms', () => ({
      name: 'leaky-backend',
      async listKeys() {
        return [{ keyRef: 'r', kid: 'leaky', alg: 'ES256' as const, status: 'active' as const }];
      },
      async getPublicKey() {
        return leaky as never;
      },
      async sign() {
        return new Uint8Array(64);
      },
    }));
    await custody.init();
    const jwks = await custody.listPublicJwks();
    expect(jwks.keys[0]?.d).toBeUndefined();
  });

  it('rotates, and keeps the retired key in the JWKS for overlap (06 §3)', async () => {
    const adapter = inMemoryKmsAdapter();
    const custody = new AdapterBackedKeyCustody('kms', () => adapter);
    await custody.init();
    const first = await custody.activeKid();

    const result = await custody.rotate();
    expect(result.retiredKids).toEqual([first]);
    expect(result.promotedKid).not.toBe(first);
    expect(await custody.activeKid()).toBe(result.promotedKid);

    const jwks = await custody.listPublicJwks();
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual([first, result.promotedKid].sort());
    // …and the retired key can still be used to verify, which is the point.
    expect(await custody.sign(first, Buffer.from('x'))).toHaveLength(64);
  });

  it('THROWS on rotate when the adapter cannot rotate — never a silent no-op', async () => {
    const adapter = inMemoryKmsAdapter();
    const noRotate: RemoteCustodyAdapter = {
      name: adapter.name,
      listKeys: adapter.listKeys.bind(adapter),
      getPublicKey: adapter.getPublicKey.bind(adapter),
      sign: adapter.sign.bind(adapter),
    };
    const custody = new AdapterBackedKeyCustody('hsm', () => noRotate);
    await custody.init();
    expect(custody.capabilities.rotate).toBe(false);
    await expect(custody.rotate()).rejects.toBeInstanceOf(KeyCustodyRotationUnsupportedError);
    await expect(custody.rotate()).rejects.toThrow(/custodian ceremony/);
  });

  it('refuses to come up against a backend with no active key', async () => {
    const custody = new AdapterBackedKeyCustody('kms', () => ({
      name: 'empty-vault',
      async listKeys() {
        return [{ keyRef: 'r', kid: 'k', alg: 'ES256' as const, status: 'retired' as const }];
      },
      async getPublicKey() {
        return new Uint8Array(
          generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
            format: 'der',
            type: 'spki',
          }),
        );
      },
      async sign() {
        return new Uint8Array(64);
      },
    }));
    await expect(custody.init()).rejects.toThrow(/none is active/);
  });

  it('reports a backend failure as unhealthy, with the backend named', async () => {
    let failing = false;
    const custody = new AdapterBackedKeyCustody('hsm', () => ({
      name: 'flaky-hsm',
      async listKeys() {
        if (failing) throw new Error('CKR_DEVICE_ERROR');
        return [{ keyRef: 'r', kid: 'k', alg: 'ES256' as const, status: 'active' as const }];
      },
      async getPublicKey() {
        return new Uint8Array(
          generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
            format: 'der',
            type: 'spki',
          }),
        );
      },
      async sign() {
        return new Uint8Array(64);
      },
    }));
    await custody.init();
    expect((await custody.healthCheck()).healthy).toBe(true);
    failing = true;
    const health = await custody.healthCheck();
    expect(health.healthy).toBe(false);
    expect(health.detail).toContain('flaky-hsm');
    expect(health.detail).toContain('CKR_DEVICE_ERROR');
  });

  it('wraps a backend signing refusal as a custody signing error', async () => {
    const custody = new AdapterBackedKeyCustody('kms', () => ({
      name: 'refusing-kms',
      async listKeys() {
        return [{ keyRef: 'r', kid: 'k', alg: 'ES256' as const, status: 'active' as const }];
      },
      async getPublicKey() {
        return new Uint8Array(
          generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
            format: 'der',
            type: 'spki',
          }),
        );
      },
      async sign() {
        throw new Error('AccessDeniedException: credential expired');
      },
    }));
    await custody.init();
    await expect(custody.sign('k', new Uint8Array([1]))).rejects.toThrow(
      /refusing-kms refused the signature: AccessDeniedException/,
    );
  });
});
