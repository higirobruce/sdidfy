import { createPrivateKey, randomUUID, sign as cryptoSign } from 'node:crypto';
import { z } from 'zod';
import { SdidUnavailableError } from './errors.js';
import {
  parseJsonBody,
  sendWithDeadline,
  type SdidHttpRequest,
  type SdidHttpTransport,
} from './http-transport.js';

/**
 * OAuth2 client authentication + client-credentials token acquisition for the
 * OIDC/eSignet strategy.
 *
 * Decided (Q3): we authenticate to SDID with OAuth2 / API keys. The exact
 * client-auth method, scopes, and the credential ROTATION POLICY + GRACE
 * PERIOD are A3 — so the method is configuration, not a default, and the
 * token cache is written so a rotated credential recovers on the next call
 * rather than after a redeploy.
 */
export type OidcClientAuth =
  | { method: 'client_secret_basic'; clientSecret: string }
  | { method: 'client_secret_post'; clientSecret: string }
  | {
      method: 'private_key_jwt';
      /** PKCS#8 PEM. Custody per C2 (GoR KMS vs on-prem HSM) — never in the DB (07 §5). */
      privateKeyPem: string;
      alg: 'RS256' | 'ES256';
      /** Key id published in our JWKS; needed for rotation with overlap (A3). */
      kid?: string;
      /** Assertion lifetime. Short by default — it is a single-use credential. */
      assertionLifetimeSec?: number;
    };

const b64url = (buf: Buffer | Uint8Array): string => Buffer.from(buf).toString('base64url');

/**
 * RFC 7523 client assertion. Signed with node:crypto only — no third-party JOSE
 * library reaches the module that holds SDID credentials (02 §4).
 */
export function signClientAssertion(args: {
  auth: Extract<OidcClientAuth, { method: 'private_key_jwt' }>;
  clientId: string;
  audience: string;
  nowMs: number;
}): string {
  const { auth, clientId, audience, nowMs } = args;
  const iat = Math.floor(nowMs / 1000);
  const header: Record<string, unknown> = { alg: auth.alg, typ: 'JWT' };
  if (auth.kid) header.kid = auth.kid;
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: audience, // the token endpoint — binds the assertion to one recipient
    jti: randomUUID(), // single-use; replay of a captured assertion is rejected
    iat,
    exp: iat + (auth.assertionLifetimeSec ?? 60),
  };
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(payload)),
  )}`;
  const key = createPrivateKey(auth.privateKeyPem);
  const signature =
    auth.alg === 'ES256'
      ? cryptoSign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' })
      : cryptoSign('sha256', Buffer.from(signingInput), key);
  return `${signingInput}.${b64url(signature)}`;
}

/** Token endpoint response (RFC 6749 §5.1), validated at the boundary (02 §4). */
const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().min(1),
  expires_in: z.number().positive().optional(),
  scope: z.string().optional(),
});

export interface ClientCredentialsTokenSourceOptions {
  clientId: string;
  clientAuth: OidcClientAuth;
  /** Scopes requested at the token endpoint (A3 — the scope names are SDID's). */
  scopes?: readonly string[];
  transport: SdidHttpTransport;
  httpTimeoutMs: number;
  /** Injectable for tests. */
  clock?: () => number;
  /**
   * Refresh this long before expiry so an in-flight call never presents a
   * token that expires mid-request.
   */
  expirySkewMs?: number;
  /**
   * Assumed lifetime when the token response omits `expires_in`. Short by
   * design: guessing long would keep presenting a dead token after rotation.
   */
  fallbackLifetimeMs?: number;
}

/**
 * Caches one client-credentials access token, refreshing it before expiry and
 * de-duplicating concurrent refreshes (a token-endpoint stampede would burn
 * quota — A5). `invalidate()` is called whenever SDID answers 401/403, so a
 * rotated credential (A3) recovers on the very next attempt.
 */
export class ClientCredentialsTokenSource {
  private cached: { token: string; expiresAtMs: number } | undefined;
  private inFlight: Promise<string> | undefined;
  private readonly clock: () => number;
  private readonly expirySkewMs: number;
  private readonly fallbackLifetimeMs: number;

  constructor(private readonly opts: ClientCredentialsTokenSourceOptions) {
    this.clock = opts.clock ?? Date.now;
    this.expirySkewMs = opts.expirySkewMs ?? 30_000;
    this.fallbackLifetimeMs = opts.fallbackLifetimeMs ?? 60_000;
  }

  /** Test/health visibility only — never log the token itself. */
  get hasCachedToken(): boolean {
    return this.cached !== undefined && this.clock() < this.cached.expiresAtMs;
  }

  invalidate(): void {
    this.cached = undefined;
  }

  async getToken(tokenEndpoint: string): Promise<string> {
    const cached = this.cached;
    if (cached && this.clock() < cached.expiresAtMs) return cached.token;
    if (this.inFlight) return await this.inFlight;
    const request = this.acquire(tokenEndpoint).finally(() => {
      this.inFlight = undefined;
    });
    this.inFlight = request;
    return await request;
  }

  private async acquire(tokenEndpoint: string): Promise<string> {
    const params = new URLSearchParams({ grant_type: 'client_credentials' });
    if (this.opts.scopes?.length) params.set('scope', this.opts.scopes.join(' '));
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    };

    const auth = this.opts.clientAuth;
    switch (auth.method) {
      case 'client_secret_basic': {
        // RFC 6749 §2.3.1 — form-encode both halves before base64.
        const credential = `${encodeURIComponent(this.opts.clientId)}:${encodeURIComponent(
          auth.clientSecret,
        )}`;
        headers.authorization = `Basic ${Buffer.from(credential).toString('base64')}`;
        break;
      }
      case 'client_secret_post':
        params.set('client_id', this.opts.clientId);
        params.set('client_secret', auth.clientSecret);
        break;
      case 'private_key_jwt':
        params.set('client_id', this.opts.clientId);
        params.set(
          'client_assertion_type',
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        );
        params.set(
          'client_assertion',
          signClientAssertion({
            auth,
            clientId: this.opts.clientId,
            audience: tokenEndpoint,
            nowMs: this.clock(),
          }),
        );
        break;
    }

    const req: SdidHttpRequest = {
      method: 'POST',
      url: tokenEndpoint,
      headers,
      body: params.toString(),
    };
    const res = await sendWithDeadline(this.opts.transport, req, this.opts.httpTimeoutMs);

    if (res.status < 200 || res.status >= 300) {
      // Never echo the response body: an OAuth error body can contain the
      // client_id and, from a misbehaving server, echoed credentials.
      throw new SdidUnavailableError(
        `SDID token endpoint returned HTTP ${res.status} (client-credentials)`,
      );
    }

    const body = parseJsonBody(res, tokenResponseSchema, 'token endpoint');
    if (body.token_type.toLowerCase() !== 'bearer') {
      // Fail closed: we only know how to present a bearer token. A different
      // token type (A3) needs an explicit implementation, not a coerced header.
      throw new SdidUnavailableError(
        `SDID token endpoint returned unsupported token_type (expected bearer)`,
      );
    }
    const lifetimeMs = body.expires_in ? body.expires_in * 1000 : this.fallbackLifetimeMs;
    this.cached = {
      token: body.access_token,
      expiresAtMs: this.clock() + Math.max(0, lifetimeMs - this.expirySkewMs),
    };
    return body.access_token;
  }
}
