import { createSign, sign as cryptoSign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

/**
 * Shared credential/JWT helpers for the FCM and APNs transports.
 *
 * Both providers authenticate with a signed JWT, so the signing lives here
 * rather than twice. Node built-ins only — no third-party JWT or SDK on the
 * push path (06 §8: every dependency is supply-chain surface, and this one
 * would hold a private key).
 */

/**
 * Config values that hold key material accept EITHER a filesystem path OR the
 * material inline. Both are real deployment shapes: a Kubernetes secret mount
 * gives a path, a systemd `EnvironmentFile` or a KMS-injected env var gives
 * the blob. Guessing between them by "does this file exist" is the only
 * option that does not force a second flag per credential.
 */
export function readCredentialMaterial(value: string): string {
  const trimmed = value.trim();
  if (trimmed === '') return '';
  // A path never contains a newline or a JSON/PEM opener.
  const looksInline = trimmed.includes('\n') || trimmed.startsWith('{') || trimmed.startsWith('-----');
  if (looksInline) return trimmed;
  return existsSync(trimmed) ? readFileSync(trimmed, 'utf8') : trimmed;
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function encodeSegments(header: Record<string, unknown>, claims: Record<string, unknown>): string {
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
}

/** RS256 JWT — Google service-account assertion (FCM OAuth exchange). */
export function signRs256Jwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateKeyPem: string,
): string {
  const signingInput = encodeSegments({ ...header, alg: 'RS256', typ: 'JWT' }, claims);
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(privateKeyPem, 'base64url')}`;
}

/** ES256 JWT — Apple provider token. JOSE requires raw r‖s, not DER. */
export function signEs256Jwt(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  privateKeyPem: string,
): string {
  const signingInput = encodeSegments({ ...header, alg: 'ES256', typ: 'JWT' }, claims);
  const signature = cryptoSign('sha256', Buffer.from(signingInput, 'utf8'), {
    key: privateKeyPem,
    // Node defaults to DER; JOSE/APNs require the fixed-width IEEE P1363
    // concatenation. Getting this wrong yields a valid-looking token that
    // Apple rejects with 403 InvalidProviderToken.
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${base64url(signature)}`;
}

/** Shape of the fields we use out of a Google service-account JSON. */
export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  project_id?: string;
}

export function parseServiceAccount(raw: string): ServiceAccountKey | null {
  try {
    const parsed = JSON.parse(raw) as Partial<ServiceAccountKey>;
    if (typeof parsed.client_email !== 'string' || typeof parsed.private_key !== 'string') return null;
    return {
      client_email: parsed.client_email,
      // Env vars commonly carry the PEM with literal \n escapes.
      private_key: parsed.private_key.replace(/\\n/g, '\n'),
      ...(typeof parsed.project_id === 'string' ? { project_id: parsed.project_id } : {}),
    };
  } catch {
    return null;
  }
}
