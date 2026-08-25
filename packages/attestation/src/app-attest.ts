/**
 * Apple App Attest verification for iOS (spec 05 §3–§4, 06 T2/T3/T4).
 *
 * On iOS the two questions the contract separates — genuine app, hardware key
 * — are answered by one object, because the App Attest key IS the key we
 * enrol: it is generated in the Secure Enclave, is non-exportable, and Apple
 * certifies it only for a genuine build of the App ID named in the
 * attestation. So a successful verification proves both, and the key security
 * level is `trusted-environment` (Secure Enclave; iOS exposes no StrongBox
 * equivalent, so the Android-only `requireStrongBox` knob does not apply).
 *
 * The procedure below follows Apple's documented steps ("Validating Apps That
 * Connect to Your Server") in order. Each step is load-bearing:
 *
 *   1. verify the x5c chain to the Apple App Attest root — otherwise anyone
 *      with a self-signed cert can mint attestations;
 *   2. clientDataHash = SHA256(nonce we issued) and
 *      nonce = SHA256(authData ‖ clientDataHash), which must equal the value
 *      inside the credCert's `1.2.840.113635.100.8.2` extension. This is the
 *      whole of the freshness/replay defence on iOS (T4) — the attestation is
 *      cryptographically welded to our one-time challenge AND to the authData
 *      we are about to trust;
 *   3. SHA256(credCert public key) must equal the credentialId in authData —
 *      binds the certificate to the credential;
 *   4. rpIdHash must be SHA256(appId) — identity binding; without it any
 *      app's valid attestation is accepted;
 *   5. signCount must be 0 — an attestation object is produced exactly once,
 *      at key creation; a non-zero counter means this is not a fresh
 *      attestation;
 *   6. aaguid must be the production `appattest` unless the deployment has
 *      explicitly opted into development builds;
 *   7. the certified key must be the key being enrolled (key binding).
 *
 * The receipt is NOT verified here: validating it requires an online call to
 * Apple, and these verifiers are offline by construction (types.ts). Its
 * presence and size are recorded as evidence so the broker can post-validate
 * or age-out receipts later (05 §4 follow-up).
 */

import { X509Certificate } from 'node:crypto';

import { deriveAssuranceCap } from './assurance.js';
import {
  bytesEqual,
  decodeBase64Strict,
  jwkToRawPoint,
  keyObjectToRawPoint,
  reject,
  sha256,
} from './common.js';
import {
  cborAsArray,
  cborAsBytes,
  cborAsMap,
  cborAsText,
  decodeCbor,
  type CborMap,
} from './cbor.js';
import { derExplicit, derOctetString, derSequence, parseDer } from './der.js';
import { APPLE_APP_ATTEST_ROOT_PEM } from './roots.js';
import type {
  AttestationRequest,
  AttestationResult,
  AttestationVerifier,
  IosVerifierConfig,
} from './types.js';
import { findCertificateExtension, parseTrustAnchors, verifyCertificateChain } from './x509.js';

/** Apple's attestation format identifier. */
export const APP_ATTEST_FMT = 'apple-appattest';
/** credCert extension holding SHA256(authData ‖ clientDataHash). */
export const APPLE_APP_ATTEST_NONCE_OID = '1.2.840.113635.100.8.2';

/** aaguid for App Attest keys created against Apple's production environment. */
export const AAGUID_PRODUCTION = Buffer.concat([Buffer.from('appattest', 'ascii'), Buffer.alloc(7)]);
/** aaguid for the development environment — exactly 16 ASCII bytes. */
export const AAGUID_DEVELOPMENT = Buffer.from('appattestdevelop', 'ascii');

/** authData layout: rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ attestedCredentialData. */
const RP_ID_HASH_LENGTH = 32;
const AUTH_DATA_HEADER_LENGTH = 37;
const AAGUID_LENGTH = 16;
/** Attested-credential-data-present flag. */
const FLAG_AT = 0x40;

/** Longest base64 token we will decode; App Attest objects are a few KB. */
const MAX_TOKEN_CHARS = 64 * 1024;

export interface AppAttestVerifierOptions {
  config: IosVerifierConfig;
}

interface AuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKey?: Uint8Array;
}

export class AppAttestVerifier implements AttestationVerifier {
  readonly platform = 'ios' as const;

  private readonly anchors: readonly X509Certificate[];

  constructor(private readonly options: AppAttestVerifierOptions) {
    const pems = options.config.rootCertificatesPem ?? [APPLE_APP_ATTEST_ROOT_PEM];
    // Parsed once, at construction: a bad root is a deployment error that
    // should surface at boot, not on a citizen's first enrolment.
    this.anchors = parseTrustAnchors(pems);
  }

  async verify(request: AttestationRequest): Promise<AttestationResult> {
    try {
      return this.verifyInner(request);
    } catch (error) {
      // Fail closed (types.ts): never let a fault become an acceptance.
      return reject('verifier_unavailable', `ios verifier fault: ${describe(error)}`);
    }
  }

  private verifyInner(request: AttestationRequest): AttestationResult {
    const { config } = this.options;

    if (typeof request.token !== 'string' || request.token.length === 0) {
      return reject('malformed', 'app attest object is missing');
    }
    if (request.token.length > MAX_TOKEN_CHARS) {
      return reject('malformed', 'app attest object is implausibly large');
    }
    if (typeof request.expectedNonce !== 'string' || request.expectedNonce.length === 0) {
      return reject('nonce_mismatch', 'no expected nonce was supplied');
    }

    // 0. Decode base64 → CBOR → the three documented members.
    let attestation: { x5c: Uint8Array[]; receipt?: Uint8Array; authData: Uint8Array };
    try {
      attestation = decodeAttestationObject(decodeBase64Strict(request.token, 'app attest object'));
    } catch (error) {
      return reject('malformed', `app attest object: ${describe(error)}`);
    }

    // 1. Chain to Apple's root. x5c is credCert first, then intermediates.
    let chain: X509Certificate[];
    try {
      chain = attestation.x5c.map((der) => new X509Certificate(Buffer.from(der)));
    } catch (error) {
      return reject('malformed', `app attest x5c: ${describe(error)}`);
    }
    const chainResult = verifyCertificateChain(chain, this.anchors, request.now);
    if (!chainResult.ok) return reject('chain_invalid', `app attest ${chainResult.detail}`);
    const credCert = chain[0]!;

    // 2. Nonce binding (T4).
    const clientDataHash = sha256(Buffer.from(request.expectedNonce, 'utf8'));
    const expectedNonceDigest = sha256(attestation.authData, clientDataHash);
    let certifiedNonce: Uint8Array;
    try {
      const extension = findCertificateExtension(credCert, APPLE_APP_ATTEST_NONCE_OID);
      if (!extension) return reject('malformed', 'credCert carries no app attest nonce extension');
      certifiedNonce = parseNonceExtension(extension);
    } catch (error) {
      return reject('malformed', `app attest nonce extension: ${describe(error)}`);
    }
    if (!bytesEqual(certifiedNonce, expectedNonceDigest)) {
      return reject('nonce_mismatch', 'credCert nonce is not SHA256(authData ‖ SHA256(nonce))');
    }

    // 3. Parse authData now that its bytes are covered by the nonce above.
    let authData: AuthenticatorData;
    try {
      authData = parseAuthenticatorData(attestation.authData);
    } catch (error) {
      return reject('malformed', `app attest authData: ${describe(error)}`);
    }

    // 4. credCert key ↔ credentialId binding.
    const credCertPoint = keyObjectToRawPoint(credCert.publicKey);
    if (!credCertPoint) return reject('key_mismatch', 'credCert key is not an EC P-256 key');
    if (!bytesEqual(authData.credentialId, sha256(credCertPoint))) {
      return reject('key_mismatch', 'credentialId is not SHA256 of the certified public key');
    }

    // 5. Identity binding: the attestation must name OUR App ID.
    if (!bytesEqual(authData.rpIdHash, sha256(Buffer.from(config.appId, 'utf8')))) {
      return reject('app_mismatch', 'rpIdHash does not match SHA256(appId)');
    }

    // 6. An attestation object is minted once, at key creation.
    if (authData.signCount !== 0) {
      return reject('malformed', `signCount is ${authData.signCount}, expected 0 for an attestation`);
    }

    // 7. Environment. A development-provisioned build must never attest
    //    successfully against a production deployment.
    const aaguid = Buffer.from(authData.aaguid);
    const isProductionAaguid = aaguid.equals(AAGUID_PRODUCTION);
    const isDevelopmentAaguid = aaguid.equals(AAGUID_DEVELOPMENT);
    if (!isProductionAaguid && !isDevelopmentAaguid) {
      return reject('malformed', 'aaguid is not an App Attest aaguid');
    }
    if (isDevelopmentAaguid && config.production) {
      return reject('app_integrity', 'development aaguid presented to a production deployment');
    }

    // 8. Key binding: on iOS the attested key is the key we enrol, so this is
    //    the same check Android does against its leaf certificate.
    let expectedPoint: Buffer;
    try {
      expectedPoint = jwkToRawPoint(request.devicePublicKeyJwk, 'devicePublicKeyJwk');
    } catch (error) {
      return reject('malformed', `device public key: ${describe(error)}`);
    }
    if (!bytesEqual(credCertPoint, expectedPoint)) {
      return reject('key_mismatch', 'app attest key is not the key being enrolled');
    }
    if (authData.credentialPublicKey) {
      // authData may carry the COSE encoding of the same key. If present it
      // must agree — a disagreement means the two halves of the object
      // describe different keys.
      let cosePoint: Buffer;
      try {
        cosePoint = coseKeyToRawPoint(authData.credentialPublicKey);
      } catch (error) {
        return reject('malformed', `app attest credential public key: ${describe(error)}`);
      }
      if (!bytesEqual(cosePoint, expectedPoint)) {
        return reject('key_mismatch', 'authData credential key differs from the key being enrolled');
      }
    }

    const keySecurityLevel = 'trusted-environment' as const;
    return {
      ok: true,
      platform: 'ios',
      appGenuine: true,
      keySecurityLevel,
      assuranceCap: deriveAssuranceCap({ appGenuine: true, keySecurityLevel }),
      evidence: {
        appId: config.appId,
        environment: isProductionAaguid ? 'production' : 'development',
        keySecurityLevel,
        credentialIdLength: authData.credentialId.length,
        signCount: authData.signCount,
        chainLength: chain.length,
        // Presence only: the receipt is Apple-specific opaque data and is not
        // persisted (07 §3).
        receiptPresent: attestation.receipt !== undefined,
        receiptBytes: attestation.receipt?.length ?? 0,
      },
    };
  }
}

/** `{ fmt: 'apple-appattest', attStmt: { x5c: [...], receipt }, authData }`. */
function decodeAttestationObject(bytes: Uint8Array): {
  x5c: Uint8Array[];
  receipt?: Uint8Array;
  authData: Uint8Array;
} {
  const root = cborAsMap(decodeCbor(bytes), 'attestation object');
  const fmt = cborAsText(root.get('fmt'), 'fmt');
  if (fmt !== APP_ATTEST_FMT) throw new Error(`unexpected fmt ${JSON.stringify(fmt)}`);

  const attStmt: CborMap = cborAsMap(root.get('attStmt'), 'attStmt');
  const x5cRaw = cborAsArray(attStmt.get('x5c'), 'x5c');
  if (x5cRaw.length === 0) throw new Error('x5c is empty');
  const x5c = x5cRaw.map((entry, index) => cborAsBytes(entry, `x5c[${index}]`));

  const authData = cborAsBytes(root.get('authData'), 'authData');

  const receiptValue = attStmt.get('receipt');
  const result: { x5c: Uint8Array[]; receipt?: Uint8Array; authData: Uint8Array } = { x5c, authData };
  if (receiptValue !== undefined) result.receipt = cborAsBytes(receiptValue, 'receipt');
  return result;
}

/** `SEQUENCE { [1] EXPLICIT OCTET STRING nonce }`. */
function parseNonceExtension(der: Uint8Array): Uint8Array {
  const fields = derSequence(parseDer(der), 'app attest nonce extension');
  const first = fields[0];
  if (!first) throw new Error('nonce extension is empty');
  return derOctetString(derExplicit(first, 'nonce'), 'nonce');
}

function parseAuthenticatorData(bytes: Uint8Array): AuthenticatorData {
  if (bytes.length < AUTH_DATA_HEADER_LENGTH) throw new Error('authData is too short');
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const flags = view[RP_ID_HASH_LENGTH]!;
  if ((flags & FLAG_AT) === 0) throw new Error('authData has no attested credential data');

  let offset = AUTH_DATA_HEADER_LENGTH;
  if (bytes.length < offset + AAGUID_LENGTH + 2) throw new Error('authData is truncated');
  const aaguid = bytes.subarray(offset, offset + AAGUID_LENGTH);
  offset += AAGUID_LENGTH;

  const credentialIdLength = view.readUInt16BE(offset);
  offset += 2;
  // The length is attacker-controlled: check it against the bytes actually
  // present before slicing.
  if (credentialIdLength === 0 || offset + credentialIdLength > bytes.length) {
    throw new Error('credentialId length is out of range');
  }
  const credentialId = bytes.subarray(offset, offset + credentialIdLength);
  offset += credentialIdLength;

  const result: AuthenticatorData = {
    rpIdHash: bytes.subarray(0, RP_ID_HASH_LENGTH),
    flags,
    signCount: view.readUInt32BE(RP_ID_HASH_LENGTH + 1),
    aaguid,
    credentialId,
  };
  if (offset < bytes.length) result.credentialPublicKey = bytes.subarray(offset);
  return result;
}

/** COSE_Key (RFC 8152) for an EC2 P-256 public key → raw uncompressed point. */
function coseKeyToRawPoint(bytes: Uint8Array): Buffer {
  const key = cborAsMap(decodeCbor(bytes), 'COSE key');
  const kty = key.get(1);
  if (kty !== 2) throw new Error('COSE key is not EC2');
  const crv = key.get(-1);
  if (crv !== 1) throw new Error('COSE key is not P-256');
  const x = cborAsBytes(key.get(-2), 'COSE key x');
  const y = cborAsBytes(key.get(-3), 'COSE key y');
  if (x.length !== 32 || y.length !== 32) throw new Error('COSE key coordinates must be 32 bytes');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
