/**
 * X.509 chain work shared by the Android key-attestation and iOS App Attest
 * verifiers (spec 05 §4, 06 T2/T3).
 *
 * Certificate parsing and signature verification are delegated to Node's
 * `crypto.X509Certificate` (OpenSSL). The hand-rolled DER reader is used for
 * exactly one thing OpenSSL will not hand us: the raw bytes of a custom
 * extension.
 *
 * The chain rules below are deliberately stricter than "OpenSSL said ok":
 *   - the anchor set is a *pin*, not a system trust store. The host's CA
 *     bundle is irrelevant to whether a key lives in Google's or Apple's
 *     hardware, and trusting it would let any public CA mint attestations;
 *   - every presented certificate must be inside its validity window at the
 *     injected `now` — an expired batch certificate is not evidence;
 *   - every issuing certificate must actually be a CA, so a leaf cannot be
 *     bent into signing a sibling leaf;
 *   - chain length is capped.
 */

import { X509Certificate } from 'node:crypto';

import {
  DER_OCTET_STRING,
  derExplicit,
  derFindContext,
  derOid,
  derSequence,
  parseDer,
  type DerNode,
} from './der.js';

/** Longest chain we will walk. Real Android chains are 3–4, Apple's is 2–3. */
export const MAX_CHAIN_LENGTH = 8;

export interface ChainVerificationResult {
  ok: boolean;
  /** Operator-facing reason when `ok` is false. */
  detail: string;
}

/** Parses PEM trust anchors; throws on the first unusable one (a config error). */
export function parseTrustAnchors(pems: readonly string[]): X509Certificate[] {
  return pems.map((pem, index) => {
    try {
      return new X509Certificate(pem);
    } catch (error) {
      throw new Error(`trust anchor #${index} is not a valid certificate: ${describe(error)}`);
    }
  });
}

/**
 * Verifies `chain` (leaf first) links up to one of `anchors`.
 *
 * An anchor matches either because the presented top certificate IS the anchor
 * (identical DER) or because the presented top certificate is signed by it.
 * The second case covers a vendor re-issuing a root over the same key — which
 * Google has done — without us silently widening trust: the signature still
 * has to verify under the pinned key.
 */
export function verifyCertificateChain(
  chain: readonly X509Certificate[],
  anchors: readonly X509Certificate[],
  now: number,
): ChainVerificationResult {
  if (chain.length === 0) return { ok: false, detail: 'empty certificate chain' };
  if (chain.length > MAX_CHAIN_LENGTH) {
    return { ok: false, detail: `chain of ${chain.length} exceeds max ${MAX_CHAIN_LENGTH}` };
  }
  if (anchors.length === 0) {
    // Fail closed: with no pin, "verified" would mean nothing at all. This is
    // a deployment error, not a device problem (see roots.ts).
    return { ok: false, detail: 'no trust anchors configured for this platform' };
  }

  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i]!;
    const from = cert.validFromDate.getTime();
    const to = cert.validToDate.getTime();
    if (!Number.isFinite(from) || !Number.isFinite(to)) {
      return { ok: false, detail: `certificate #${i} has an unreadable validity period` };
    }
    if (now < from) return { ok: false, detail: `certificate #${i} is not yet valid` };
    if (now > to) return { ok: false, detail: `certificate #${i} has expired` };
    if (i > 0 && !cert.ca) {
      return { ok: false, detail: `certificate #${i} signs others but is not a CA` };
    }
  }

  for (let i = 0; i + 1 < chain.length; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;
    if (!safeCheckIssued(child, parent)) {
      return { ok: false, detail: `certificate #${i} is not issued by certificate #${i + 1}` };
    }
    if (!safeVerify(child, parent)) {
      return { ok: false, detail: `certificate #${i} signature does not verify under #${i + 1}` };
    }
  }

  const top = chain[chain.length - 1]!;
  for (const anchor of anchors) {
    if (top.raw.equals(anchor.raw)) return { ok: true, detail: 'chain terminates at a pinned root' };
    if (!anchor.ca) continue;
    if (safeCheckIssued(top, anchor) && safeVerify(top, anchor)) {
      return { ok: true, detail: 'chain verifies under a pinned root' };
    }
  }
  return { ok: false, detail: 'chain does not terminate at a pinned platform root' };
}

function safeCheckIssued(child: X509Certificate, parent: X509Certificate): boolean {
  try {
    return child.checkIssued(parent);
  } catch {
    return false;
  }
}

function safeVerify(child: X509Certificate, parent: X509Certificate): boolean {
  try {
    return child.verify(parent.publicKey);
  } catch {
    // A key type OpenSSL cannot use for this signature lands here. Treat any
    // failure to *prove* the link as an unverified link.
    return false;
  }
}

/**
 * Returns the DER content of the extension identified by `oid`, or undefined
 * when the certificate does not carry it.
 *
 * Walks the certificate with our own reader because Node exposes only a fixed
 * handful of extensions, and the two extensions this package depends on are
 * vendor-private. Throws `DerError` on a structurally broken certificate —
 * which cannot normally happen here, since the certificate already parsed as
 * X.509, but is handled by callers as `malformed` regardless.
 */
export function findCertificateExtension(
  cert: X509Certificate,
  oid: string,
): Uint8Array | undefined {
  const certificate = derSequence(parseDer(cert.raw), 'Certificate');
  const tbs = certificate[0];
  if (!tbs) return undefined;
  const tbsChildren = derSequence(tbs, 'TBSCertificate');

  // TBSCertificate: extensions are `[3] EXPLICIT Extensions`.
  const extensionsTag = derFindContext(tbsChildren, 3);
  if (!extensionsTag) return undefined;
  const extensions = derSequence(derExplicit(extensionsTag, 'extensions'), 'Extensions');

  for (const extension of extensions) {
    const parts = derSequence(extension, 'Extension');
    const idNode = parts[0];
    if (!idNode) continue;
    if (derOid(idNode, 'extnID') !== oid) continue;
    // extnValue is the last element; `critical` may sit between it and the OID.
    const valueNode = parts[parts.length - 1] as DerNode | undefined;
    if (!valueNode || valueNode.tagClass !== 'universal' || valueNode.tagNumber !== DER_OCTET_STRING) {
      return undefined;
    }
    return valueNode.content;
  }
  return undefined;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
