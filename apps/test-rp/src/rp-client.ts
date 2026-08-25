/**
 * RpClient — pilot relying-party client (SPEC 04): CIBA initiation against
 * /oidc/bc-authorize, /oidc/token polling with authorization_pending handling,
 * and ID-token verification against the broker JWKS + discovery document.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import {
  CIBA_GRANT_TYPE,
  bcAuthorizeResponseSchema,
  registerRpResponseSchema,
  type AssuranceLevel,
  type RegisterRpRequest,
  type TokenResponse,
  tokenResponseSchema,
} from '@sdid/shared';

export interface RpClientOptions {
  brokerUrl: string;
  clientId: string;
  clientSecret: string;
}

export interface InitiateCibaParams {
  /** Pairwise subject the RP holds for this citizen — never a raw NID (04 §3). */
  loginHint: string;
  scope?: string;
  /** Shown on both the RP screen and the phone (anti consent-fatigue, 04 §3). */
  bindingMessage?: string;
  /** Minimum assurance level the RP requires (03 §3). */
  requestedAl?: AssuranceLevel;
}

export interface InitiateCibaResult {
  authReqId: string;
  expiresIn: number;
  interval: number;
}

export interface PollOptions {
  timeoutMs?: number;
  /** Poll interval; defaults to 1000ms (the broker's `interval` is in seconds). */
  intervalMs?: number;
}

export interface CibaTokens {
  idToken: string;
  accessToken: string;
  raw: TokenResponse;
}

export interface RegisterViaAdminResult {
  rpId: string;
  clientId: string;
  clientSecret: string;
  client: RpClient;
}

export type RegisterRpParams = Pick<RegisterRpRequest, 'name'> & Partial<RegisterRpRequest>;

interface DiscoveryDocument {
  issuer: string;
  [key: string]: unknown;
}

export class RpClient {
  readonly brokerUrl: string;
  readonly clientId: string;
  private readonly clientSecret: string;

  private jwks?: ReturnType<typeof createRemoteJWKSet>;
  private discoveryPromise?: Promise<DiscoveryDocument>;

  constructor(options: RpClientOptions) {
    this.brokerUrl = options.brokerUrl.replace(/\/+$/, '');
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
  }

  /** client_secret_basic: Basic base64(client_id:client_secret). */
  private basicAuthHeader(): string {
    return `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`, 'utf8').toString('base64')}`;
  }

  /** POST /oidc/bc-authorize (form-encoded, client_secret_basic) — 04 §3 step 1. */
  async initiateCiba(params: InitiateCibaParams): Promise<InitiateCibaResult> {
    const form = new URLSearchParams();
    form.set('scope', params.scope ?? 'openid profile');
    form.set('login_hint', params.loginHint);
    if (params.bindingMessage !== undefined) form.set('binding_message', params.bindingMessage);
    if (params.requestedAl !== undefined) form.set('requested_al', params.requestedAl);

    const body = bcAuthorizeResponseSchema.parse(
      await this.postForm('/oidc/bc-authorize', form),
    );
    return {
      authReqId: body.auth_req_id,
      expiresIn: body.expires_in,
      interval: body.interval,
    };
  }

  /**
   * Poll POST /oidc/token with the CIBA grant until the citizen decides
   * (04 §3 steps 6–9). Keeps polling on authorization_pending, backs off on
   * slow_down, throws on access_denied / expired_token / other errors, and
   * throws when timeoutMs elapses without a decision.
   */
  async pollForTokens(authReqId: string, options?: PollOptions): Promise<CibaTokens> {
    const timeoutMs = options?.timeoutMs ?? 60_000;
    let intervalMs = options?.intervalMs ?? 1_000;
    const deadline = Date.now() + timeoutMs;

    const form = new URLSearchParams();
    form.set('grant_type', CIBA_GRANT_TYPE);
    form.set('auth_req_id', authReqId);

    for (;;) {
      const res = await fetch(`${this.brokerUrl}/oidc/token`, {
        method: 'POST',
        headers: {
          authorization: this.basicAuthHeader(),
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: form.toString(),
      });
      const text = await res.text();

      if (res.ok) {
        const raw = tokenResponseSchema.parse(JSON.parse(text));
        return { idToken: raw.id_token, accessToken: raw.access_token, raw };
      }

      let error: string | undefined;
      let errorDescription: string | undefined;
      try {
        const parsed = JSON.parse(text) as { error?: string; error_description?: string };
        error = parsed.error;
        errorDescription = parsed.error_description;
      } catch {
        // non-JSON error body — fall through to the generic throw below
      }

      if (error === 'authorization_pending' || error === 'slow_down') {
        if (error === 'slow_down') intervalMs += 1_000;
        if (Date.now() + intervalMs > deadline) {
          throw new Error(`CIBA polling timed out after ${timeoutMs}ms (auth_req_id ${authReqId})`);
        }
        await sleep(intervalMs);
        continue;
      }

      throw new Error(
        `CIBA token request failed (HTTP ${res.status}): ${error ?? text}${
          errorDescription ? ` — ${errorDescription}` : ''
        }`,
      );
    }
  }

  /**
   * Verify an ID token against the broker JWKS (jose remote JWK set), with
   * issuer from the discovery document (fetched once, cached) and audience
   * = this clientId (04 §4).
   */
  async verifyIdToken(idToken: string): Promise<JWTPayload> {
    const { issuer } = await this.discovery();
    this.jwks ??= createRemoteJWKSet(new URL(`${this.brokerUrl}/oidc/jwks`));
    const { payload } = await jwtVerify(idToken, this.jwks, {
      issuer,
      audience: this.clientId,
    });
    return payload;
  }

  async userinfo(accessToken: string): Promise<unknown> {
    const res = await fetch(`${this.brokerUrl}/oidc/userinfo`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    return this.parseOrThrow(res, 'GET /oidc/userinfo');
  }

  async introspect(token: string): Promise<unknown> {
    const form = new URLSearchParams();
    form.set('token', token);
    return this.postForm('/oidc/introspect', form);
  }

  async revoke(token: string): Promise<unknown> {
    const form = new URLSearchParams();
    form.set('token', token);
    return this.postForm('/oidc/revoke', form);
  }

  /** Register an RP through the admin API (04 §6) and hand back a ready client. */
  static async registerViaAdmin(
    brokerUrl: string,
    adminToken: string,
    params: RegisterRpParams,
  ): Promise<RegisterViaAdminResult> {
    const request: RegisterRpRequest = {
      name: params.name,
      authMethod: params.authMethod ?? 'secret',
      allowedScopes: params.allowedScopes ?? ['openid', 'profile'],
      maxAssurance: params.maxAssurance ?? 'AL2',
      allowedFlows: params.allowedFlows ?? ['ciba'],
      redirectUris: params.redirectUris ?? [],
      ...(params.logoUri !== undefined ? { logoUri: params.logoUri } : {}),
    };
    const base = brokerUrl.replace(/\/+$/, '');
    const res = await fetch(`${base}/admin/rps`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(request),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} POST /admin/rps: ${text}`);
    }
    const body = registerRpResponseSchema.parse(JSON.parse(text));
    if (!body.clientSecret) {
      throw new Error('admin registration returned no clientSecret (returned exactly once at registration)');
    }
    return {
      rpId: body.rpId,
      clientId: body.clientId,
      clientSecret: body.clientSecret,
      client: new RpClient({ brokerUrl: base, clientId: body.clientId, clientSecret: body.clientSecret }),
    };
  }

  /** Provision the pairwise subject (login_hint) this RP holds for a citizen. */
  static async provisionLoginHint(
    brokerUrl: string,
    adminToken: string,
    rpId: string,
    pseudoNid: string,
  ): Promise<string> {
    const base = brokerUrl.replace(/\/+$/, '');
    const res = await fetch(`${base}/admin/rps/${encodeURIComponent(rpId)}/pairwise`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ pseudoNid }),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} POST /admin/rps/${rpId}/pairwise: ${text}`);
    }
    const body = JSON.parse(text) as { subject: string };
    return body.subject;
  }

  private discovery(): Promise<DiscoveryDocument> {
    this.discoveryPromise ??= (async () => {
      const res = await fetch(`${this.brokerUrl}/.well-known/openid-configuration`);
      return (await this.parseOrThrow(res, 'GET /.well-known/openid-configuration')) as DiscoveryDocument;
    })();
    return this.discoveryPromise;
  }

  private async postForm(path: string, form: URLSearchParams): Promise<unknown> {
    const res = await fetch(this.brokerUrl + path, {
      method: 'POST',
      headers: {
        authorization: this.basicAuthHeader(),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
    return this.parseOrThrow(res, `POST ${path}`);
  }

  private async parseOrThrow(res: Response, what: string): Promise<unknown> {
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${what}: ${text}`);
    }
    return text ? (JSON.parse(text) as unknown) : {};
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
