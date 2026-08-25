/**
 * Android hardware key attestation (spec 05 §3–§4, 06 T2/T3, 03 §2 step 7).
 *
 * Play Integrity answers "is this a genuine app on a sound device". It says
 * nothing about where the enrolled private key lives. This file answers the
 * second, independent question: does the keypair we are about to bind to a
 * citizen's identity actually sit in a TEE or StrongBox, and is the attestation
 * over *that* key?
 *
 * The evidence is an X.509 chain minted by the device's Keystore: the leaf
 * certifies the newly generated public key and carries a Google-private
 * extension (`1.3.6.1.4.1.11129.2.1.17`, KeyDescription) stating the security
 * level, the challenge the key was generated with, and the enforcement lists.
 * The chain runs up to a batch/intermediate certificate to a Google root
 * (roots.ts).
 *
 * Three properties matter, and all three are checked here:
 *   1. the chain really is Google's (chain_invalid otherwise);
 *   2. the attestation challenge is the nonce this broker issued — otherwise a
 *      chain captured from any device replays forever (T4, nonce_mismatch);
 *   3. the certified key is the key being enrolled — otherwise an attacker
 *      attests a genuine hardware key and enrols a software one they control
 *      (key_mismatch).
 *
 * Failure philosophy: an *absent* or *weak* attestation is a downgrade to
 * `software` (AL1 — 06 §6 assurance degradation), because much of Rwanda's
 * install base cannot do better and excluding those citizens is its own harm
 * (08 inclusion). A *contradictory* attestation — wrong key, wrong nonce,
 * broken chain, unlocked bootloader — is a rejection. Never the other way
 * round.
 */

import { X509Certificate } from 'node:crypto';

import { bytesEqual, decodeBase64Strict, jwkToRawPoint, keyObjectToRawPoint, MalformedInputError } from './common.js';
import {
  derBoolean,
  derEnumerated,
  derExplicit,
  derFindContext,
  derOctetString,
  derSequence,
  derSet,
  derSmallInteger,
  DerError,
  parseDer,
  type DerNode,
} from './der.js';
import type { AttestationRejectionCode, KeySecurityLevel } from './types.js';
import { findCertificateExtension, MAX_CHAIN_LENGTH, verifyCertificateChain } from './x509.js';

/** Google's KeyDescription extension (Android Keystore attestation v1–v300). */
export const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

/** `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }`. */
export const SECURITY_LEVEL_SOFTWARE = 0;
export const SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
export const SECURITY_LEVEL_STRONGBOX = 2;

/** AuthorizationList tag numbers used here (Keymaster/KeyMint tag ids). */
const TAG_PURPOSE = 1;
const TAG_ALL_APPLICATIONS = 600;
const TAG_ORIGIN = 702;
const TAG_ROOT_OF_TRUST = 704;
const TAG_OS_VERSION = 705;
const TAG_OS_PATCH_LEVEL = 706;
const TAG_ATTESTATION_APPLICATION_ID = 709;

/** `KM_ORIGIN_GENERATED` — key material was created inside the secure world. */
const ORIGIN_GENERATED = 0;
/** `VerifiedBootState ::= ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) }`. */
const VERIFIED_BOOT_VERIFIED = 0;

/** Largest base64 blob we will even look at, per certificate. */
const MAX_ENCODED_CERT_CHARS = 16 * 1024;

export interface AndroidAuthorizationList {
  /** True when the list carries at least one entry. */
  present: boolean;
  purposes?: number[];
  origin?: number;
  allApplications: boolean;
  rootOfTrust?: { deviceLocked: boolean; verifiedBootState: number };
  attestationApplicationId?: Uint8Array;
  osVersion?: number;
  osPatchLevel?: number;
}

export interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  softwareEnforced: AndroidAuthorizationList;
  hardwareEnforced: AndroidAuthorizationList;
}

export interface AndroidKeyAttestationInput {
  /** The chain as supplied by the client (see {@link parseCertificateChainInput}). */
  keyAttestation: string;
  /** Server-issued single-use nonce; must equal the attestation challenge. */
  expectedNonce: string;
  /** The key being enrolled — the attestation must cover exactly this key. */
  devicePublicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  /** Our package name, for the (software-enforced) application-id cross-check. */
  packageName: string;
  /** base64 SHA-256 digests of our signing certificates, same cross-check. */
  certificateDigests: readonly string[];
  now: number;
  trustAnchors: readonly X509Certificate[];
}

export type AndroidKeyAttestationOutcome =
  | { ok: true; keySecurityLevel: KeySecurityLevel; evidence: Record<string, unknown> }
  | { ok: false; code: AttestationRejectionCode; detail: string };

/**
 * Accepts the chain in any of the shapes a mobile client might reasonably send
 * it: a JSON array of base64 DER strings, a PEM bundle, or a
 * comma/whitespace-separated list of base64 DER. Leaf first in every case.
 *
 * Being liberal about the *container* is safe; being liberal about the base64
 * inside it is not, so each element goes through the strict decoder.
 */
export function parseCertificateChainInput(value: string): Buffer[] {
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new MalformedInputError('key attestation chain is empty');

  let encoded: string[];
  if (trimmed.startsWith('[')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new MalformedInputError('key attestation chain is not valid JSON');
    }
    if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== 'string')) {
      throw new MalformedInputError('key attestation chain must be an array of base64 strings');
    }
    encoded = (parsed as string[]).map((item) => item.trim());
  } else if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
    encoded = [];
    const blocks = trimmed.split('-----BEGIN CERTIFICATE-----').slice(1);
    for (const block of blocks) {
      const end = block.indexOf('-----END CERTIFICATE-----');
      if (end < 0) throw new MalformedInputError('unterminated PEM block');
      encoded.push(block.slice(0, end).replace(/\s+/g, ''));
    }
  } else {
    encoded = trimmed.split(/[\s,]+/).filter((part) => part.length > 0);
  }

  if (encoded.length === 0) throw new MalformedInputError('key attestation chain is empty');
  if (encoded.length > MAX_CHAIN_LENGTH) {
    throw new MalformedInputError(`key attestation chain has more than ${MAX_CHAIN_LENGTH} certificates`);
  }
  return encoded.map((item, index) => {
    if (item.length > MAX_ENCODED_CERT_CHARS) {
      throw new MalformedInputError(`certificate #${index} is implausibly large`);
    }
    return decodeBase64Strict(item, `certificate #${index}`);
  });
}

/** Parses the KeyDescription payload of the attestation extension. */
export function parseKeyDescription(der: Uint8Array): KeyDescription {
  const fields = derSequence(parseDer(der), 'KeyDescription');
  if (fields.length < 8) {
    throw new DerError(`KeyDescription: expected 8 fields, got ${fields.length}`);
  }
  return {
    attestationVersion: derSmallInteger(fields[0]!, 'attestationVersion'),
    attestationSecurityLevel: derEnumerated(fields[1]!, 'attestationSecurityLevel'),
    keymasterVersion: derSmallInteger(fields[2]!, 'keymasterVersion'),
    keymasterSecurityLevel: derEnumerated(fields[3]!, 'keymasterSecurityLevel'),
    attestationChallenge: derOctetString(fields[4]!, 'attestationChallenge'),
    // fields[5] is uniqueId — deliberately ignored and never persisted: it is a
    // device-scoped identifier and we have no purpose for it (07 §3, 08 §2).
    softwareEnforced: parseAuthorizationList(fields[6]!, 'softwareEnforced'),
    hardwareEnforced: parseAuthorizationList(fields[7]!, 'hardwareEnforced'),
  };
}

function parseAuthorizationList(node: DerNode, what: string): AndroidAuthorizationList {
  const children = derSequence(node, what);
  const list: AndroidAuthorizationList = { present: children.length > 0, allApplications: false };

  const purposeTag = derFindContext(children, TAG_PURPOSE);
  if (purposeTag) {
    list.purposes = derSet(derExplicit(purposeTag, `${what}.purpose`), `${what}.purpose`).map(
      (entry) => derSmallInteger(entry, `${what}.purpose`),
    );
  }

  const originTag = derFindContext(children, TAG_ORIGIN);
  if (originTag) list.origin = derSmallInteger(derExplicit(originTag, `${what}.origin`), `${what}.origin`);

  // `allApplications` is a NULL-valued marker: its mere presence means the key
  // is not bound to one app.
  list.allApplications = derFindContext(children, TAG_ALL_APPLICATIONS) !== undefined;

  const rootOfTrustTag = derFindContext(children, TAG_ROOT_OF_TRUST);
  if (rootOfTrustTag) {
    const rot = derSequence(derExplicit(rootOfTrustTag, `${what}.rootOfTrust`), `${what}.rootOfTrust`);
    if (rot.length < 3) throw new DerError(`${what}.rootOfTrust: too few fields`);
    list.rootOfTrust = {
      // rot[0] is verifiedBootKey (the OEM/user boot key hash) — not needed.
      deviceLocked: derBoolean(rot[1]!, `${what}.deviceLocked`),
      verifiedBootState: derEnumerated(rot[2]!, `${what}.verifiedBootState`),
    };
  }

  const appIdTag = derFindContext(children, TAG_ATTESTATION_APPLICATION_ID);
  if (appIdTag) {
    list.attestationApplicationId = derOctetString(
      derExplicit(appIdTag, `${what}.attestationApplicationId`),
      `${what}.attestationApplicationId`,
    );
  }

  const osVersionTag = derFindContext(children, TAG_OS_VERSION);
  if (osVersionTag) {
    list.osVersion = derSmallInteger(derExplicit(osVersionTag, `${what}.osVersion`), `${what}.osVersion`);
  }
  const patchTag = derFindContext(children, TAG_OS_PATCH_LEVEL);
  if (patchTag) {
    list.osPatchLevel = derSmallInteger(derExplicit(patchTag, `${what}.osPatchLevel`), `${what}.osPatchLevel`);
  }

  return list;
}

/** Verifies an Android key attestation chain end to end. Never throws. */
export function verifyAndroidKeyAttestation(
  input: AndroidKeyAttestationInput,
): AndroidKeyAttestationOutcome {
  // 1. Decode and parse. Everything here is attacker-controlled bytes.
  let chain: X509Certificate[];
  try {
    chain = parseCertificateChainInput(input.keyAttestation).map((der) => new X509Certificate(der));
  } catch (error) {
    return fail('malformed', `key attestation chain: ${describe(error)}`);
  }

  // 2. The chain must be Google's, valid now, and CA-clean.
  const chainResult = verifyCertificateChain(chain, input.trustAnchors, input.now);
  if (!chainResult.ok) return fail('chain_invalid', `key attestation ${chainResult.detail}`);

  const leaf = chain[0]!;

  // 3. Pull and parse the KeyDescription.
  let description: KeyDescription;
  try {
    const extension = findCertificateExtension(leaf, ANDROID_KEY_ATTESTATION_OID);
    if (!extension) {
      return fail('malformed', 'leaf certificate carries no key attestation extension');
    }
    description = parseKeyDescription(extension);
  } catch (error) {
    return fail('malformed', `key attestation extension: ${describe(error)}`);
  }

  // 4. Nonce binding (T4). The client sets the attestation challenge to the
  //    ASCII bytes of the nonce this broker issued; anything else is a replay
  //    or a chain minted for someone else's session.
  if (!bytesEqual(description.attestationChallenge, Buffer.from(input.expectedNonce, 'utf8'))) {
    return fail('nonce_mismatch', 'attestation challenge is not the issued nonce');
  }

  // 5. Key binding. Without this the whole chain proves only that *some*
  //    hardware key exists on *some* device.
  let expectedPoint: Buffer;
  try {
    expectedPoint = jwkToRawPoint(input.devicePublicKeyJwk, 'devicePublicKeyJwk');
  } catch (error) {
    return fail('malformed', `device public key: ${describe(error)}`);
  }
  const attestedPoint = keyObjectToRawPoint(leaf.publicKey);
  if (!attestedPoint) {
    return fail('key_mismatch', 'attested key is not an EC P-256 key');
  }
  if (!bytesEqual(attestedPoint, expectedPoint)) {
    return fail('key_mismatch', 'key attestation does not cover the key being enrolled');
  }

  // 6. Boot state (T2). A hardware-enforced root of trust that says the
  //    bootloader is unlocked or boot was not verified describes a device that
  //    can be modified underneath us — refuse it for enrolment.
  const rootOfTrust = description.hardwareEnforced.rootOfTrust ?? description.softwareEnforced.rootOfTrust;
  if (rootOfTrust) {
    if (!rootOfTrust.deviceLocked) {
      return fail('device_integrity', 'attested root of trust reports an unlocked bootloader');
    }
    if (rootOfTrust.verifiedBootState !== VERIFIED_BOOT_VERIFIED) {
      return fail(
        'device_integrity',
        `attested verified-boot state is ${rootOfTrust.verifiedBootState}, expected Verified`,
      );
    }
  }

  // 7. Identity cross-check against the software-enforced application id. It is
  //    software-enforced, so it is corroboration, not proof — but a chain that
  //    names a different app is not ours. Parse failures are ignored: the field
  //    is optional and its encoding varies across Android versions.
  const appIdBytes =
    description.softwareEnforced.attestationApplicationId ??
    description.hardwareEnforced.attestationApplicationId;
  const appId = appIdBytes ? tryParseAttestationApplicationId(appIdBytes) : undefined;
  if (appId && appId.packageNames.length > 0 && !appId.packageNames.includes(input.packageName)) {
    return fail(
      'app_mismatch',
      `key attestation names package(s) ${appId.packageNames.join(', ')}, expected ${input.packageName}`,
    );
  }
  if (
    appId &&
    appId.signatureDigests.length > 0 &&
    input.certificateDigests.length > 0 &&
    !appId.signatureDigests.some((digest) => input.certificateDigests.includes(digest))
  ) {
    return fail('app_mismatch', 'key attestation signing digest is not one of ours');
  }

  // 8. Security level. Take the *lower* of the two levels the extension
  //    reports: a StrongBox claim signed by a software keymaster is not
  //    StrongBox evidence.
  const rawLevel = Math.min(description.attestationSecurityLevel, description.keymasterSecurityLevel);
  let level = toKeySecurityLevel(rawLevel);
  const downgrades: string[] = [];

  // A hardware claim with an empty hardware-enforced list is a claim with no
  // hardware behind it.
  if (level !== 'software' && !description.hardwareEnforced.present) {
    level = 'software';
    downgrades.push('empty hardware-enforced authorization list');
  }

  // Origin must be GENERATED: an IMPORTED key existed outside the secure world
  // before it got there, so "non-exportable" says nothing about who else holds
  // it. Absent origin (older keymaster) is tolerated.
  const origin = description.hardwareEnforced.origin ?? description.softwareEnforced.origin;
  if (origin !== undefined && origin !== ORIGIN_GENERATED) {
    level = 'software';
    downgrades.push(`key origin ${origin} is not hardware-generated`);
  }

  return {
    ok: true,
    keySecurityLevel: level,
    evidence: {
      keyAttestationVersion: description.attestationVersion,
      keymasterVersion: description.keymasterVersion,
      attestationSecurityLevel: securityLevelName(description.attestationSecurityLevel),
      keymasterSecurityLevel: securityLevelName(description.keymasterSecurityLevel),
      keyChainLength: chain.length,
      keyOrigin: origin ?? null,
      deviceLocked: rootOfTrust?.deviceLocked ?? null,
      verifiedBootState: rootOfTrust?.verifiedBootState ?? null,
      keyOsVersion: description.hardwareEnforced.osVersion ?? null,
      keyOsPatchLevel: description.hardwareEnforced.osPatchLevel ?? null,
      // Recorded rather than enforced: a key usable by every application is a
      // weaker binding and worth reviewing (07 audit), but rejecting on it
      // would exclude legitimate OEM configurations.
      keyAllApplications: description.hardwareEnforced.allApplications,
      keyPurposes: description.hardwareEnforced.purposes ?? description.softwareEnforced.purposes ?? null,
      ...(downgrades.length > 0 ? { keySecurityDowngrades: downgrades } : {}),
    },
  };
}

/**
 * `AttestationApplicationId ::= SEQUENCE {
 *    packageInfos SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
 *    signatureDigests SET OF OCTET STRING }`
 */
function tryParseAttestationApplicationId(
  der: Uint8Array,
): { packageNames: string[]; signatureDigests: string[] } | undefined {
  try {
    const fields = derSequence(parseDer(der), 'AttestationApplicationId');
    if (fields.length < 2) return undefined;
    const packageNames = derSet(fields[0]!, 'packageInfos').map((info) => {
      const parts = derSequence(info, 'AttestationPackageInfo');
      return Buffer.from(derOctetString(parts[0]!, 'packageName')).toString('utf8');
    });
    const signatureDigests = derSet(fields[1]!, 'signatureDigests').map((digest) =>
      Buffer.from(derOctetString(digest, 'signatureDigest')).toString('base64'),
    );
    return { packageNames, signatureDigests };
  } catch {
    return undefined;
  }
}

function toKeySecurityLevel(level: number): KeySecurityLevel {
  if (level === SECURITY_LEVEL_STRONGBOX) return 'strongbox';
  if (level === SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return 'trusted-environment';
  // Unknown future levels are treated as software: we do not grant trust to a
  // value we do not understand.
  return 'software';
}

function securityLevelName(level: number): string {
  switch (level) {
    case SECURITY_LEVEL_SOFTWARE:
      return 'Software';
    case SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
      return 'TrustedEnvironment';
    case SECURITY_LEVEL_STRONGBOX:
      return 'StrongBox';
    default:
      return `Unknown(${level})`;
  }
}

function fail(code: AttestationRejectionCode, detail: string): AndroidKeyAttestationOutcome {
  return { ok: false, code, detail };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
