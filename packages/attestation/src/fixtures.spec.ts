/**
 * Fixture builders for the attestation tests, plus self-tests proving the
 * builders produce structures the platform itself accepts.
 *
 * Why the `.spec.ts` name for a helper file: `tsconfig.json` excludes
 * `src/**\/*.spec.ts` from the published build, so test-only code — including
 * these encoders — stays out of `dist`. The self-tests at the bottom keep the
 * file honest as a test file in its own right.
 *
 * Everything here encodes bytes *by hand* to the relevant specification:
 * X.690 DER for certificates and extensions, RFC 8949 CBOR for App Attest
 * objects. The parsers under test are therefore exercised against bytes built
 * independently of them, not against their own output. Certificates are signed
 * with real EC P-256 keys via `node:crypto`, so `X509Certificate.verify()` and
 * `checkIssued()` do genuine cryptographic work.
 */

import { describe, expect, it } from 'vitest';
import { X509Certificate, createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import { ANDROID_KEY_ATTESTATION_OID } from './key-attestation.js';
import { APPLE_APP_ATTEST_NONCE_OID } from './app-attest.js';

/* -------------------------------------------------------------------------- */
/* DER encoding                                                                */
/* -------------------------------------------------------------------------- */

export function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let value = n;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, content: Buffer | Buffer[]): Buffer {
  const body = Array.isArray(content) ? Buffer.concat(content) : content;
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

export const seq = (...items: Buffer[]): Buffer => tlv(0x30, items);
export const set = (...items: Buffer[]): Buffer => tlv(0x31, items);
export const octetString = (value: Buffer): Buffer => tlv(0x04, value);
export const bitString = (value: Buffer): Buffer => tlv(0x03, Buffer.concat([Buffer.from([0]), value]));
export const derNull = (): Buffer => tlv(0x05, Buffer.alloc(0));
export const boolean = (value: boolean): Buffer => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
export const utf8String = (value: string): Buffer => tlv(0x0c, Buffer.from(value, 'utf8'));

export function integer(value: number | bigint): Buffer {
  let big = BigInt(value);
  const negative = big < 0n;
  if (negative) throw new Error('fixtures only encode non-negative integers');
  let hex = big.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  let bytes = Buffer.from(hex, 'hex');
  if (bytes.length === 0) bytes = Buffer.from([0]);
  if ((bytes[0]! & 0x80) !== 0) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  big = 0n;
  return tlv(0x02, bytes);
}

export function enumerated(value: number): Buffer {
  return tlv(0x0a, Buffer.from([value]));
}

export function oid(dotted: string): Buffer {
  const arcs = dotted.split('.').map(Number);
  const out: number[] = [40 * arcs[0]! + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const encoded: number[] = [];
    let value = arc;
    do {
      encoded.unshift(value & 0x7f);
      value = Math.floor(value / 128);
    } while (value > 0);
    for (let i = 0; i < encoded.length - 1; i++) encoded[i]! |= 0x80;
    out.push(...encoded);
  }
  return tlv(0x06, Buffer.from(out));
}

/** Base-128 tag number with continuation bits, for the high-tag-number form. */
export function base128(value: number): Buffer {
  const out: number[] = [];
  let v = value;
  do {
    out.unshift(v & 0x7f);
    v = Math.floor(v / 128);
  } while (v > 0);
  for (let i = 0; i < out.length - 1; i++) out[i]! |= 0x80;
  return Buffer.from(out);
}

/**
 * `[n] EXPLICIT` wrapper. Android AuthorizationList tags run to 709, well past
 * the 30 the short form can hold, so the high-tag-number form is required —
 * exactly the encoding the reader under test has to handle.
 */
export function explicit(tag: number, content: Buffer): Buffer {
  const identifier =
    tag < 0x1f ? Buffer.from([0xa0 | tag]) : Buffer.concat([Buffer.from([0xbf]), base128(tag)]);
  return Buffer.concat([identifier, derLength(content.length), content]);
}

export function utcTime(epochMs: number): Buffer {
  const d = new Date(epochMs);
  const p = (n: number) => String(n).padStart(2, '0');
  const text =
    `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(text, 'ascii'));
}

const OID_COMMON_NAME = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';

const distinguishedName = (cn: string): Buffer => seq(set(seq(oid(OID_COMMON_NAME), utf8String(cn))));
const ecdsaSha256 = (): Buffer => seq(oid(OID_ECDSA_SHA256));

export function extension(id: string, value: Buffer, critical = false): Buffer {
  return critical
    ? seq(oid(id), boolean(true), octetString(value))
    : seq(oid(id), octetString(value));
}

export interface CertificateOptions {
  subject: string;
  issuer: string;
  issuerPrivateKey: KeyObject;
  subjectPublicKey: KeyObject;
  ca: boolean;
  notBefore: number;
  notAfter: number;
  serial: number;
  extensions?: Buffer[];
  /** Corrupt the signature to simulate a tampered certificate. */
  breakSignature?: boolean;
}

/** Builds and signs a real X.509 v3 certificate. */
export function makeCertificate(options: CertificateOptions): X509Certificate {
  const extensions = [
    extension(OID_BASIC_CONSTRAINTS, options.ca ? seq(boolean(true)) : seq(), true),
    ...(options.extensions ?? []),
  ];
  const tbs = seq(
    explicit(0, integer(2)), // version v3
    integer(options.serial),
    ecdsaSha256(),
    distinguishedName(options.issuer),
    seq(utcTime(options.notBefore), utcTime(options.notAfter)),
    distinguishedName(options.subject),
    options.subjectPublicKey.export({ type: 'spki', format: 'der' }),
    explicit(3, seq(...extensions)),
  );
  const signature = sign('sha256', tbs, options.issuerPrivateKey);
  if (options.breakSignature) signature[signature.length - 1] ^= 0xff;
  return new X509Certificate(seq(tbs, ecdsaSha256(), bitString(signature)));
}

export function generateEcKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

export function toJwk(key: KeyObject): { kty: 'EC'; crv: 'P-256'; x: string; y: string } {
  const jwk = key.export({ format: 'jwk' }) as { x: string; y: string };
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

export function rawPoint(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' }) as { x: string; y: string };
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

export function toPem(cert: X509Certificate): string {
  return cert.toString();
}

export const sha256 = (...parts: Buffer[]): Buffer => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

/* -------------------------------------------------------------------------- */
/* Android key attestation fixtures                                            */
/* -------------------------------------------------------------------------- */

/** Keymaster/KeyMint AuthorizationList tags used by the fixtures. */
export const TAG = {
  purpose: 1,
  allApplications: 600,
  origin: 702,
  rootOfTrust: 704,
  osVersion: 705,
  osPatchLevel: 706,
  attestationApplicationId: 709,
} as const;

export interface AuthorizationListOptions {
  purposes?: number[];
  origin?: number;
  allApplications?: boolean;
  rootOfTrust?: { deviceLocked: boolean; verifiedBootState: number };
  osVersion?: number;
  osPatchLevel?: number;
  attestationApplicationId?: { packageNames: string[]; signatureDigests: Buffer[] };
}

export function authorizationList(options: AuthorizationListOptions): Buffer {
  const entries: Buffer[] = [];
  if (options.purposes) {
    entries.push(explicit(TAG.purpose, set(...options.purposes.map((p) => integer(p)))));
  }
  if (options.allApplications) entries.push(explicit(TAG.allApplications, derNull()));
  if (options.origin !== undefined) entries.push(explicit(TAG.origin, integer(options.origin)));
  if (options.rootOfTrust) {
    entries.push(
      explicit(
        TAG.rootOfTrust,
        seq(
          octetString(Buffer.alloc(32, 7)), // verifiedBootKey
          boolean(options.rootOfTrust.deviceLocked),
          enumerated(options.rootOfTrust.verifiedBootState),
          octetString(Buffer.alloc(32, 9)), // verifiedBootHash
        ),
      ),
    );
  }
  if (options.osVersion !== undefined) entries.push(explicit(TAG.osVersion, integer(options.osVersion)));
  if (options.osPatchLevel !== undefined) {
    entries.push(explicit(TAG.osPatchLevel, integer(options.osPatchLevel)));
  }
  if (options.attestationApplicationId) {
    const { packageNames, signatureDigests } = options.attestationApplicationId;
    entries.push(
      explicit(
        TAG.attestationApplicationId,
        octetString(
          seq(
            set(...packageNames.map((name) => seq(octetString(Buffer.from(name, 'utf8')), integer(1)))),
            set(...signatureDigests.map((digest) => octetString(digest))),
          ),
        ),
      ),
    );
  }
  // NB: entries must appear in ascending tag order in real DER SETs; an
  // AuthorizationList is a SEQUENCE, and Keystore emits ascending tags, which
  // the callers below preserve.
  return seq(...entries);
}

export interface KeyDescriptionOptions {
  attestationVersion?: number;
  attestationSecurityLevel: number;
  keymasterVersion?: number;
  keymasterSecurityLevel: number;
  challenge: Buffer;
  softwareEnforced?: AuthorizationListOptions;
  hardwareEnforced?: AuthorizationListOptions;
  /** Emit a truncated KeyDescription (fewer than 8 fields). */
  truncate?: boolean;
}

export function keyDescription(options: KeyDescriptionOptions): Buffer {
  const fields = [
    integer(options.attestationVersion ?? 4),
    enumerated(options.attestationSecurityLevel),
    integer(options.keymasterVersion ?? 41),
    enumerated(options.keymasterSecurityLevel),
    octetString(options.challenge),
    octetString(Buffer.alloc(0)), // uniqueId
    authorizationList(options.softwareEnforced ?? {}),
    authorizationList(options.hardwareEnforced ?? {}),
  ];
  return seq(...(options.truncate ? fields.slice(0, 5) : fields));
}

export interface AndroidChainOptions {
  challenge?: Buffer;
  devicePublicKey: KeyObject;
  attestationSecurityLevel?: number;
  keymasterSecurityLevel?: number;
  softwareEnforced?: AuthorizationListOptions;
  hardwareEnforced?: AuthorizationListOptions;
  now?: number;
  /** Sign the leaf with a key that is not the intermediate's (broken link). */
  breakChain?: boolean;
  /** Omit the KeyDescription extension entirely. */
  omitExtension?: boolean;
  /** Leaf validity window overrides. */
  leafNotBefore?: number;
  leafNotAfter?: number;
  keyDescriptionOverride?: Buffer;
}

export interface AndroidChainFixture {
  /** JSON array of base64 DER, leaf first — the shape the client sends. */
  chain: string;
  /** PEM of the fixture root, to be pinned as a trust anchor in the test. */
  rootPem: string;
  certificates: X509Certificate[];
}

/**
 * Builds a three-certificate Android attestation chain: leaf (carrying the
 * KeyDescription over `devicePublicKey`) → intermediate CA → root CA.
 */
export function makeAndroidChain(options: AndroidChainOptions): AndroidChainFixture {
  const now = options.now ?? Date.now();
  const root = generateEcKeyPair();
  const intermediate = generateEcKeyPair();
  const impostor = generateEcKeyPair();

  const rootCert = makeCertificate({
    subject: 'Fixture Android Root',
    issuer: 'Fixture Android Root',
    issuerPrivateKey: root.privateKey,
    subjectPublicKey: root.publicKey,
    ca: true,
    notBefore: now - 86_400_000,
    notAfter: now + 86_400_000 * 365,
    serial: 1,
  });
  const intermediateCert = makeCertificate({
    subject: 'Fixture Attestation CA',
    issuer: 'Fixture Android Root',
    issuerPrivateKey: root.privateKey,
    subjectPublicKey: intermediate.publicKey,
    ca: true,
    notBefore: now - 86_400_000,
    notAfter: now + 86_400_000 * 180,
    serial: 2,
  });

  const description =
    options.keyDescriptionOverride ??
    keyDescription({
      attestationSecurityLevel: options.attestationSecurityLevel ?? 1,
      keymasterSecurityLevel: options.keymasterSecurityLevel ?? 1,
      challenge: options.challenge ?? Buffer.from('nonce', 'utf8'),
      softwareEnforced: options.softwareEnforced ?? {},
      hardwareEnforced:
        options.hardwareEnforced ?? {
          purposes: [2, 3],
          origin: 0,
          rootOfTrust: { deviceLocked: true, verifiedBootState: 0 },
          osVersion: 140000,
          osPatchLevel: 202601,
        },
    });

  const leafCert = makeCertificate({
    subject: 'Fixture Attested Key',
    issuer: 'Fixture Attestation CA',
    issuerPrivateKey: options.breakChain ? impostor.privateKey : intermediate.privateKey,
    subjectPublicKey: options.devicePublicKey,
    ca: false,
    notBefore: options.leafNotBefore ?? now - 3_600_000,
    notAfter: options.leafNotAfter ?? now + 86_400_000 * 30,
    serial: 3,
    extensions: options.omitExtension
      ? []
      : [extension(ANDROID_KEY_ATTESTATION_OID, description)],
  });

  const certificates = [leafCert, intermediateCert, rootCert];
  return {
    chain: JSON.stringify(certificates.map((cert) => cert.raw.toString('base64'))),
    rootPem: toPem(rootCert),
    certificates,
  };
}

/* -------------------------------------------------------------------------- */
/* CBOR encoding                                                               */
/* -------------------------------------------------------------------------- */

export function cborHead(major: number, argument: number): Buffer {
  if (argument < 24) return Buffer.from([(major << 5) | argument]);
  if (argument < 0x100) return Buffer.from([(major << 5) | 24, argument]);
  if (argument < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(argument, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(argument, 1);
  return b;
}

export const cborUint = (value: number): Buffer => cborHead(0, value);
export const cborNegative = (value: number): Buffer => cborHead(1, -1 - value);
export const cborBytes = (value: Buffer): Buffer => Buffer.concat([cborHead(2, value.length), value]);
export const cborText = (value: string): Buffer => {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([cborHead(3, bytes.length), bytes]);
};
export const cborArray = (items: Buffer[]): Buffer => Buffer.concat([cborHead(4, items.length), ...items]);
export const cborMap = (entries: [Buffer, Buffer][]): Buffer =>
  Buffer.concat([cborHead(5, entries.length), ...entries.flat()]);

/* -------------------------------------------------------------------------- */
/* Apple App Attest fixtures                                                   */
/* -------------------------------------------------------------------------- */

export const AAGUID_PROD = Buffer.concat([Buffer.from('appattest', 'ascii'), Buffer.alloc(7)]);
export const AAGUID_DEV = Buffer.from('appattestdevelop', 'ascii');

export interface AppAttestOptions {
  appId: string;
  nonce: string;
  devicePrivateKey?: KeyObject;
  /** The App Attest key Apple certifies — NOT the enrolled signing key. */
  devicePublicKey: KeyObject;
  /**
   * The separate Secure Enclave signing key being enrolled, folded into
   * clientData. On a real device this is always a different key from the App
   * Attest key (see app-attest.ts step 8). Defaults to `devicePublicKey` so
   * tests that do not care about the distinction stay readable.
   */
  enrolledPublicKey?: KeyObject;
  aaguid?: Buffer;
  signCount?: number;
  now?: number;
  /** Override the credentialId (defaults to SHA256 of the certified key). */
  credentialId?: Buffer;
  /** Append the COSE encoding of the credential public key to authData. */
  includeCoseKey?: boolean;
  /** Encode a different key in the COSE blob than the one being certified. */
  coseKey?: KeyObject;
  /** Override the rpIdHash (defaults to SHA256(appId)). */
  rpIdHash?: Buffer;
  /** Put a different nonce in the credCert extension. */
  nonceOverride?: Buffer;
  /** Omit the credCert nonce extension. */
  omitNonceExtension?: boolean;
  /** Sign the credCert with a key unrelated to the chain. */
  breakChain?: boolean;
  /** Emit `fmt` other than apple-appattest. */
  fmt?: string;
  /** Include an opaque receipt. */
  receipt?: Buffer;
  /**
   * Replace authData wholesale. The credCert nonce is still computed over
   * these bytes, so the object reaches the authData parser with its nonce
   * binding intact — the only way to test authData parsing in isolation.
   */
  authDataOverride?: Buffer;
}

export interface AppAttestFixture {
  /** base64 CBOR — the shape the client sends. */
  token: string;
  rootPem: string;
  authData: Buffer;
}

export function makeAppAttestObject(options: AppAttestOptions): AppAttestFixture {
  const now = options.now ?? Date.now();
  const root = generateEcKeyPair();
  const intermediate = generateEcKeyPair();
  const impostor = generateEcKeyPair();

  const rootCert = makeCertificate({
    subject: 'Fixture Apple Root',
    issuer: 'Fixture Apple Root',
    issuerPrivateKey: root.privateKey,
    subjectPublicKey: root.publicKey,
    ca: true,
    notBefore: now - 86_400_000,
    notAfter: now + 86_400_000 * 365,
    serial: 11,
  });
  const intermediateCert = makeCertificate({
    subject: 'Fixture Apple App Attestation CA 1',
    issuer: 'Fixture Apple Root',
    issuerPrivateKey: root.privateKey,
    subjectPublicKey: intermediate.publicKey,
    ca: true,
    notBefore: now - 86_400_000,
    notAfter: now + 86_400_000 * 180,
    serial: 12,
  });

  const credentialId = options.credentialId ?? sha256(rawPoint(options.devicePublicKey));
  const authDataParts: Buffer[] = [
    options.rpIdHash ?? sha256(Buffer.from(options.appId, 'utf8')),
    Buffer.from([0x40]), // AT flag
    (() => {
      const counter = Buffer.alloc(4);
      counter.writeUInt32BE(options.signCount ?? 0);
      return counter;
    })(),
    options.aaguid ?? AAGUID_PROD,
    (() => {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credentialId.length);
      return length;
    })(),
    credentialId,
  ];
  if (options.includeCoseKey) {
    const jwk = (options.coseKey ?? options.devicePublicKey).export({ format: 'jwk' }) as {
      x: string;
      y: string;
    };
    authDataParts.push(
      cborMap([
        [cborUint(1), cborUint(2)], // kty: EC2
        [cborNegative(-1), cborUint(1)], // crv: P-256
        [cborNegative(-2), cborBytes(Buffer.from(jwk.x, 'base64url'))],
        [cborNegative(-3), cborBytes(Buffer.from(jwk.y, 'base64url'))],
      ]),
    );
  }
  const authData = options.authDataOverride ?? Buffer.concat(authDataParts);

  // clientData = utf8(nonce) ‖ rawPoint(enrolled signing key): this is what
  // welds BOTH the one-time nonce and the enrolled key into Apple's certified
  // digest (app-attest.ts step 2).
  const clientDataHash = sha256(
    Buffer.from(options.nonce, 'utf8'),
    rawPoint(options.enrolledPublicKey ?? options.devicePublicKey),
  );
  const certifiedNonce = options.nonceOverride ?? sha256(authData, clientDataHash);

  const credCert = makeCertificate({
    subject: 'Fixture credCert',
    issuer: 'Fixture Apple App Attestation CA 1',
    issuerPrivateKey: options.breakChain ? impostor.privateKey : intermediate.privateKey,
    subjectPublicKey: options.devicePublicKey,
    ca: false,
    notBefore: now - 3_600_000,
    notAfter: now + 86_400_000 * 30,
    serial: 13,
    extensions: options.omitNonceExtension
      ? []
      : [extension(APPLE_APP_ATTEST_NONCE_OID, seq(explicit(1, octetString(certifiedNonce))))],
  });

  const attStmtEntries: [Buffer, Buffer][] = [
    [cborText('x5c'), cborArray([cborBytes(credCert.raw), cborBytes(intermediateCert.raw)])],
  ];
  if (options.receipt) attStmtEntries.push([cborText('receipt'), cborBytes(options.receipt)]);

  const object = cborMap([
    [cborText('fmt'), cborText(options.fmt ?? 'apple-appattest')],
    [cborText('attStmt'), cborMap(attStmtEntries)],
    [cborText('authData'), cborBytes(authData)],
  ]);

  return { token: object.toString('base64'), rootPem: toPem(rootCert), authData };
}

/* -------------------------------------------------------------------------- */
/* Self-tests — the fixtures must be real, or every test below them is theatre */
/* -------------------------------------------------------------------------- */

describe('fixture builders', () => {
  it('produces certificates OpenSSL accepts, verifies and chains', () => {
    const device = generateEcKeyPair();
    const fixture = makeAndroidChain({ devicePublicKey: device.publicKey });
    const [leaf, intermediate, root] = fixture.certificates as [
      X509Certificate,
      X509Certificate,
      X509Certificate,
    ];

    expect(leaf.checkIssued(intermediate)).toBe(true);
    expect(leaf.verify(intermediate.publicKey)).toBe(true);
    expect(intermediate.verify(root.publicKey)).toBe(true);
    expect(root.verify(root.publicKey)).toBe(true);
    expect(intermediate.ca).toBe(true);
    expect(leaf.ca).toBe(false);
    // The leaf really certifies the device key.
    expect(rawPoint(leaf.publicKey).equals(rawPoint(device.publicKey))).toBe(true);
  });

  it('produces a broken link when asked to', () => {
    const device = generateEcKeyPair();
    const fixture = makeAndroidChain({ devicePublicKey: device.publicKey, breakChain: true });
    const [leaf, intermediate] = fixture.certificates as [X509Certificate, X509Certificate];
    expect(leaf.verify(intermediate.publicKey)).toBe(false);
  });

  it('produces a corrupt signature when asked to', () => {
    const ca = generateEcKeyPair();
    const leafKey = generateEcKeyPair();
    const now = Date.now();
    const cert = makeCertificate({
      subject: 'leaf',
      issuer: 'leaf',
      issuerPrivateKey: ca.privateKey,
      subjectPublicKey: leafKey.publicKey,
      ca: false,
      notBefore: now - 1000,
      notAfter: now + 1000,
      serial: 5,
      breakSignature: true,
    });
    expect(cert.verify(ca.publicKey)).toBe(false);
  });

  it('encodes CBOR heads the way RFC 8949 says', () => {
    expect(cborUint(0).equals(Buffer.from([0x00]))).toBe(true);
    expect(cborUint(23).equals(Buffer.from([0x17]))).toBe(true);
    expect(cborUint(24).equals(Buffer.from([0x18, 0x18]))).toBe(true);
    expect(cborUint(300).equals(Buffer.from([0x19, 0x01, 0x2c]))).toBe(true);
    expect(cborNegative(-1).equals(Buffer.from([0x20]))).toBe(true);
    expect(cborText('a').equals(Buffer.from([0x61, 0x61]))).toBe(true);
  });

  it('encodes DER lengths the way X.690 says', () => {
    expect(derLength(5).equals(Buffer.from([0x05]))).toBe(true);
    expect(derLength(200).equals(Buffer.from([0x81, 0xc8]))).toBe(true);
    expect(derLength(300).equals(Buffer.from([0x82, 0x01, 0x2c]))).toBe(true);
    // 1.2.840.113635.100.8.2 → 06 09 2a 86 48 86 f7 63 64 08 02
    expect(oid('1.2.840.113635.100.8.2').toString('hex')).toBe('06092a864886f763640802');
  });
});
