import { Body, Controller, Get, HttpCode, Inject, Post, Query, Req, Res } from '@nestjs/common';
import {
  ASSURANCE_LEVELS,
  BridgeError,
  CIBA_GRANT_TYPE,
  SUPPORTED_SCOPES,
  alMeets,
  authorizeRequestSchema,
  tokenRequestSchema,
  uuidv7,
  type AssuranceLevel,
  type SdidProvider,
  type TokenRequest,
  type TokenResponse,
} from '@sdid/shared';
import { SdidUnknownIdentityError } from '@sdid/sdid-adapter';
import { and, eq, isNull } from 'drizzle-orm';
import type { Request, Response } from 'express';
import { decodeJwt } from 'jose';
import { createHash, randomBytes } from 'node:crypto';
import { AuditService } from '../../audit/audit.service.js';
import { ZodPipe } from '../../common/zod.pipe.js';
import { loadConfig } from '../../config.js';
import { DbService } from '../../db/db.module.js';
import {
  authTransactions,
  authorizationCodes,
  citizens,
  consentGrants,
  deviceBindings,
} from '../../db/schema.js';
import { KeysService } from '../../keys/keys.service.js';
import { PushService } from '../../push/push.service.js';
import { RedisService } from '../../redis/redis.module.js';
import { SDID_PROVIDER } from '../../sdid/sdid.module.js';
import { PairwiseService } from '../../trust/pairwise.service.js';
import { RpService, sha256Hex, type RelyingPartyRow } from '../rp/rp.service.js';
import { TokenService } from './token.service.js';

function base64urlSha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

interface CodeFlowStash {
  codeChallenge: string;
  nonce: string | null;
  redirectUri: string;
  state: string | null;
}

/**
 * RP-facing OIDC surface (spec 04): discovery, JWKS, token (auth-code + CIBA
 * grants), userinfo, introspection, revocation, and the v1 authorize page.
 * v1 has no browser-session login at the broker — /oidc/authorize requires a
 * login_hint (the RP's pairwise subject) and completes via the citizen's
 * phone, exactly like CIBA, then redirects with an authorization code.
 */
@Controller()
export class OidcController {
  constructor(
    private readonly dbService: DbService,
    private readonly redis: RedisService,
    private readonly keys: KeysService,
    private readonly audit: AuditService,
    private readonly rpService: RpService,
    private readonly tokens: TokenService,
    private readonly pairwise: PairwiseService,
    private readonly push: PushService,
    @Inject(SDID_PROVIDER) private readonly sdid: SdidProvider,
  ) {}

  @Get('.well-known/openid-configuration')
  discovery(): Record<string, unknown> {
    const issuer = loadConfig().BROKER_ISSUER;
    return {
      issuer,
      authorization_endpoint: `${issuer}/oidc/authorize`,
      token_endpoint: `${issuer}/oidc/token`,
      jwks_uri: `${issuer}/oidc/jwks`,
      userinfo_endpoint: `${issuer}/oidc/userinfo`,
      backchannel_authentication_endpoint: `${issuer}/oidc/bc-authorize`,
      introspection_endpoint: `${issuer}/oidc/introspect`,
      revocation_endpoint: `${issuer}/oidc/revoke`,
      grant_types_supported: ['authorization_code', CIBA_GRANT_TYPE],
      backchannel_token_delivery_modes_supported: ['poll'],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: [...SUPPORTED_SCOPES],
      acr_values_supported: [...ASSURANCE_LEVELS],
      subject_types_supported: ['pairwise'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    };
  }

  @Get('oidc/jwks')
  jwks(): unknown {
    return this.keys.jwks();
  }

  // ---------------------------------------------------------------- /token

  @Post('oidc/token')
  @HttpCode(200)
  async token(
    @Req() req: Request,
    @Body(new ZodPipe(tokenRequestSchema)) body: TokenRequest,
  ): Promise<TokenResponse> {
    const rp = await this.rpService.authenticateClient(req);
    if (body.grant_type === CIBA_GRANT_TYPE) return this.cibaGrant(rp, body);
    if (body.grant_type === 'authorization_code') return this.codeGrant(rp, body);
    throw new BridgeError('invalid_request', 'Unsupported grant_type', 400);
  }

  private async cibaGrant(rp: RelyingPartyRow, body: TokenRequest): Promise<TokenResponse> {
    if (!body.auth_req_id) throw new BridgeError('invalid_request', 'auth_req_id is required', 400);
    const db = this.dbService.db;
    const rows = await db
      .select()
      .from(authTransactions)
      .where(eq(authTransactions.authReqId, body.auth_req_id));
    const txn = rows[0];
    // A txn from another client is indistinguishable from an unknown one (T9).
    if (!txn || txn.rpId !== rp.id) {
      throw new BridgeError('invalid_grant', 'Unknown auth_req_id', 400);
    }
    const now = new Date();
    if (txn.status === 'pending' && txn.expiresAt.getTime() <= now.getTime()) {
      const marked = await db
        .update(authTransactions)
        .set({ status: 'expired' })
        .where(and(eq(authTransactions.id, txn.id), eq(authTransactions.status, 'pending')))
        .returning({ id: authTransactions.id });
      if (marked.length > 0) {
        await this.audit.append({
          actor: { type: 'rp', id: rp.id },
          action: 'ciba.request_expired',
          subjectRef: txn.citizenId,
          rpId: rp.id,
          result: 'failure',
          context: { flow: txn.flow },
        });
      }
      throw new BridgeError('expired_token', 'Authentication request expired', 400);
    }
    if (txn.status === 'pending') {
      throw new BridgeError('authorization_pending', 'Citizen has not yet approved', 400);
    }
    if (txn.status === 'expired') {
      throw new BridgeError('expired_token', 'Authentication request expired', 400);
    }
    if (txn.status === 'denied') {
      throw new BridgeError('access_denied', 'Citizen denied the request', 400);
    }
    if (txn.status !== 'approved') {
      throw new BridgeError('invalid_grant', 'Authentication request already used', 400);
    }

    // Approved: the acr is the APPROVING binding's live assurance level.
    const bindingRows = txn.deviceBindingId
      ? await db.select().from(deviceBindings).where(eq(deviceBindings.id, txn.deviceBindingId))
      : [];
    const binding = bindingRows[0];
    if (!binding) throw new BridgeError('invalid_grant', 'Approval binding missing', 400);
    const acr = binding.assuranceLevel as AssuranceLevel;
    const authTime = txn.resolvedAt ?? now;

    // Single-use: consume atomically before minting so a concurrent poll loses.
    const consumed = await db
      .update(authTransactions)
      .set({ status: 'consumed' })
      .where(and(eq(authTransactions.id, txn.id), eq(authTransactions.status, 'approved')))
      .returning({ id: authTransactions.id });
    if (consumed.length === 0) {
      throw new BridgeError('invalid_grant', 'Authentication request already used', 400);
    }

    const response = await this.tokens.mint({
      rp,
      citizenId: txn.citizenId,
      scopes: txn.scopes,
      acr,
      authTime,
    });

    // The CIBA approval IS the consent event (04 §5) — record the grant.
    await db.insert(consentGrants).values({
      id: uuidv7(),
      citizenId: txn.citizenId,
      rpId: rp.id,
      scopes: txn.scopes,
      source: 'ciba-approval',
    });
    await this.audit.append({
      actor: { type: 'citizen', id: txn.citizenId },
      action: 'consent.granted',
      subjectRef: txn.citizenId,
      rpId: rp.id,
      result: 'success',
      context: { scopes: txn.scopes, source: 'ciba-approval' },
    });
    await this.audit.append({
      actor: { type: 'rp', id: rp.id },
      action: 'ciba.tokens_issued',
      subjectRef: txn.citizenId,
      rpId: rp.id,
      deviceBindingId: binding.id,
      assurance: acr,
      result: 'success',
      context: { scopes: txn.scopes, flow: txn.flow },
    });
    return response;
  }

  private async codeGrant(rp: RelyingPartyRow, body: TokenRequest): Promise<TokenResponse> {
    if (!body.code || !body.redirect_uri || !body.code_verifier) {
      throw new BridgeError('invalid_request', 'code, redirect_uri and code_verifier are required', 400);
    }
    const db = this.dbService.db;
    const rows = await db
      .select()
      .from(authorizationCodes)
      .where(eq(authorizationCodes.codeHash, sha256Hex(body.code)));
    const row = rows[0];
    const now = new Date();
    if (
      !row ||
      row.rpId !== rp.id ||
      row.consumedAt !== null ||
      row.expiresAt.getTime() <= now.getTime() ||
      row.redirectUri !== body.redirect_uri ||
      base64urlSha256(body.code_verifier) !== row.codeChallenge // PKCE S256
    ) {
      throw new BridgeError('invalid_grant', 'Invalid authorization code', 400);
    }
    // Single-use: consume atomically.
    const consumed = await db
      .update(authorizationCodes)
      .set({ consumedAt: now })
      .where(and(eq(authorizationCodes.codeHash, row.codeHash), isNull(authorizationCodes.consumedAt)))
      .returning({ codeHash: authorizationCodes.codeHash });
    if (consumed.length === 0) {
      throw new BridgeError('invalid_grant', 'Invalid authorization code', 400);
    }
    const response = await this.tokens.mint({
      rp,
      citizenId: row.citizenId,
      scopes: row.scopes,
      acr: row.assurance as AssuranceLevel,
      authTime: row.authTime,
      nonce: row.nonce,
    });
    await this.audit.append({
      actor: { type: 'rp', id: rp.id },
      action: 'oidc.tokens_issued',
      subjectRef: row.citizenId,
      rpId: rp.id,
      assurance: row.assurance as AssuranceLevel,
      result: 'success',
      context: { scopes: row.scopes, flow: 'code' },
    });
    return response;
  }

  // ------------------------------------------------------------- /userinfo

  @Get('oidc/userinfo')
  async userinfo(@Req() req: Request): Promise<Record<string, unknown>> {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw new BridgeError('access_denied', 'Bearer access token required', 401);
    let payload;
    try {
      payload = await this.keys.verifyJwt(token);
    } catch {
      throw new BridgeError('access_denied', 'Invalid access token', 401);
    }
    if (payload['token_use'] !== 'access') {
      throw new BridgeError('access_denied', 'Invalid access token', 401);
    }
    if (typeof payload.jti === 'string' && (await this.redis.client.get(`revoked:${payload.jti}`))) {
      throw new BridgeError('access_denied', 'Token revoked', 401);
    }
    const cid = payload['cid'];
    const clientId = payload['client_id'];
    if (typeof cid !== 'string' || typeof clientId !== 'string' || typeof payload.sub !== 'string') {
      throw new BridgeError('access_denied', 'Invalid access token', 401);
    }
    const citizenRows = await this.dbService.db.select().from(citizens).where(eq(citizens.id, cid));
    const citizen = citizenRows[0];
    const rp = await this.rpService.loadByClientId(clientId);
    if (!citizen || !rp) throw new BridgeError('access_denied', 'Invalid access token', 401);

    const scopes = String(payload['scope'] ?? '')
      .split(' ')
      .filter(Boolean);

    // Attribute release requires a live consent grant covering the token
    // scopes (04 §5) — revoked consent shuts the door even on a live token.
    const grants = await this.dbService.db
      .select()
      .from(consentGrants)
      .where(
        and(
          eq(consentGrants.citizenId, citizen.id),
          eq(consentGrants.rpId, rp.id),
          isNull(consentGrants.revokedAt),
        ),
      );
    const covered = grants.some((g) => scopes.every((s) => g.scopes.includes(s)));
    if (!covered) throw new BridgeError('access_denied', 'No active consent for requested scopes', 403);

    const claims: Record<string, unknown> = { sub: payload.sub, acr: payload['acr'] };
    const wantsProfile = scopes.includes('profile');
    const wantsAddress = scopes.includes('address');
    if ((wantsProfile || wantsAddress) && citizen.sdidSubject) {
      try {
        // Attributes are fetched on demand under consent — never warehoused (07 §3).
        const attrs = await this.sdid.getAttributes(citizen.sdidSubject, scopes);
        if (wantsProfile) {
          if (attrs.name !== undefined) claims['name'] = attrs.name;
          if (attrs.dateOfBirth !== undefined) claims['dateOfBirth'] = attrs.dateOfBirth;
        }
        if (wantsAddress && attrs.address !== undefined) claims['address'] = attrs.address;
      } catch (err) {
        if (!(err instanceof SdidUnknownIdentityError)) {
          throw new BridgeError('sdid_unavailable', 'Attribute source unavailable', 503);
        }
        // Unknown at SDID: omit attributes, still return the identity claims.
      }
    }
    return claims;
  }

  // ----------------------------------------------------------- /introspect

  @Post('oidc/introspect')
  @HttpCode(200)
  async introspect(
    @Req() req: Request,
    @Body() body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    await this.rpService.authenticateClient(req);
    const token = body?.['token'];
    if (typeof token !== 'string' || token.length === 0) return { active: false };
    try {
      const payload = await this.keys.verifyJwt(token);
      if (typeof payload.jti === 'string' && (await this.redis.client.get(`revoked:${payload.jti}`))) {
        return { active: false };
      }
      return {
        active: true,
        sub: payload.sub,
        scope: payload['scope'],
        client_id: payload['client_id'],
        exp: payload.exp,
        acr: payload['acr'],
        token_use: payload['token_use'],
      };
    } catch {
      return { active: false };
    }
  }

  // --------------------------------------------------------------- /revoke

  @Post('oidc/revoke')
  @HttpCode(200)
  async revoke(@Req() req: Request, @Body() body: Record<string, unknown>): Promise<void> {
    const rp = await this.rpService.authenticateClient(req);
    const token = body?.['token'];
    if (typeof token !== 'string' || token.length === 0) return; // RFC 7009: 200 regardless
    try {
      // Decode WITHOUT verifying — even an expired token must be revocable.
      const payload = decodeJwt(token);
      const aud = payload.aud;
      const audienceIsCaller =
        aud === rp.clientId || (Array.isArray(aud) && aud.includes(rp.clientId));
      if (!audienceIsCaller || typeof payload.jti !== 'string') return;
      const exp = typeof payload.exp === 'number' ? payload.exp : 0;
      const ttl = Math.max(exp - Math.floor(Date.now() / 1000), 1);
      await this.redis.client.set(`revoked:${payload.jti}`, '1', 'EX', ttl);
      await this.audit.append({
        actor: { type: 'rp', id: rp.id },
        action: 'token.revoked',
        rpId: rp.id,
        result: 'success',
        context: { jti: payload.jti, tokenUse: payload['token_use'] ?? 'unknown' },
      });
    } catch {
      // Unknown/undecodable token: still 200 (RFC 7009 §2.2).
    }
  }

  // ------------------------------------------------------------ /authorize

  @Get('oidc/authorize')
  async authorize(@Query() query: Record<string, string>, @Res() res: Response): Promise<void> {
    const parsed = authorizeRequestSchema.safeParse(query);
    if (!parsed.success) throw new BridgeError('invalid_request', 'Invalid authorize request', 400);
    const q = parsed.data;
    // v1 has no broker browser session — the RP must supply the pairwise
    // subject it holds for the citizen, exactly as it would for CIBA.
    const loginHint = query['login_hint'];
    if (!loginHint) throw new BridgeError('invalid_request', 'login_hint is required', 400);

    const rp = await this.rpService.loadByClientId(q.client_id);
    if (!rp || rp.status !== 'active') {
      throw new BridgeError('invalid_client', 'Unknown or suspended client', 401);
    }
    if (!rp.allowedFlows.includes('code')) {
      throw new BridgeError('unauthorized_client', 'Client may not use the code flow', 400);
    }
    if (!rp.redirectUris.includes(q.redirect_uri)) {
      throw new BridgeError('invalid_request', 'redirect_uri is not registered', 400);
    }
    const scopes = q.scope.split(' ').filter(Boolean);
    if (scopes.length === 0 || !scopes.every((s) => rp.allowedScopes.includes(s))) {
      throw new BridgeError('invalid_scope', 'Requested scopes exceed the client grant', 400);
    }
    let requestedAl: AssuranceLevel = 'AL2';
    if (q.acr_values !== undefined) {
      if (!(ASSURANCE_LEVELS as readonly string[]).includes(q.acr_values)) {
        throw new BridgeError('invalid_request', 'Unsupported acr_values', 400);
      }
      requestedAl = q.acr_values as AssuranceLevel;
      if (!alMeets(rp.maxAssurance as AssuranceLevel, requestedAl)) {
        throw new BridgeError('invalid_request', 'Requested assurance exceeds client maximum', 400);
      }
    }

    const citizenId = await this.pairwise.citizenForSubject(rp.id, loginHint);
    if (!citizenId) {
      res.status(200).type('html').send(this.accessDeniedHtml());
      return;
    }

    const config = loadConfig();
    const ttlSeconds = config.CIBA_REQUEST_TTL_SECONDS;
    const authReqId = randomBytes(32).toString('base64url');
    const now = Date.now();
    await this.dbService.db.insert(authTransactions).values({
      id: uuidv7(),
      authReqId,
      citizenId,
      rpId: rp.id,
      flow: 'code',
      scopes,
      requestedAl,
      bindingMessage: null,
      status: 'pending',
      expiresAt: new Date(now + ttlSeconds * 1000),
    });
    const stash: CodeFlowStash = {
      codeChallenge: q.code_challenge,
      nonce: q.nonce ?? null,
      redirectUri: q.redirect_uri,
      state: q.state ?? null,
    };
    await this.redis.client.set(`codeflow:${authReqId}`, JSON.stringify(stash), 'EX', ttlSeconds);
    await this.push.wake(citizenId); // wake-only, no auth data (T6)
    await this.audit.append({
      actor: { type: 'rp', id: rp.id },
      action: 'ciba.request_created',
      subjectRef: citizenId,
      rpId: rp.id,
      result: 'success',
      context: { flow: 'code', scopes, requestedAl },
    });
    res.status(200).type('html').send(this.approvalPageHtml(rp.name, authReqId));
  }

  @Get('oidc/authorize/poll')
  async authorizePoll(
    @Query('txn') txn?: string,
  ): Promise<{ status: 'pending' | 'denied' } | { status: 'approved'; redirect: string }> {
    if (!txn) return { status: 'denied' };
    const db = this.dbService.db;
    const rows = await db.select().from(authTransactions).where(eq(authTransactions.authReqId, txn));
    const row = rows[0];
    if (!row || row.flow !== 'code') return { status: 'denied' };
    const now = Date.now();
    if (row.status === 'pending') {
      return row.expiresAt.getTime() > now ? { status: 'pending' } : { status: 'denied' };
    }
    if (row.status !== 'approved') return { status: 'denied' };

    const stashRaw = await this.redis.client.get(`codeflow:${txn}`);
    if (!stashRaw) return { status: 'denied' };
    const stash = JSON.parse(stashRaw) as CodeFlowStash;

    const bindingRows = row.deviceBindingId
      ? await db.select().from(deviceBindings).where(eq(deviceBindings.id, row.deviceBindingId))
      : [];
    const binding = bindingRows[0];
    if (!binding) return { status: 'denied' };

    // Consume the transaction atomically so concurrent polls mint one code.
    const consumed = await db
      .update(authTransactions)
      .set({ status: 'consumed' })
      .where(and(eq(authTransactions.id, row.id), eq(authTransactions.status, 'approved')))
      .returning({ id: authTransactions.id });
    if (consumed.length === 0) return { status: 'denied' };

    const config = loadConfig();
    const code = randomBytes(32).toString('base64url');
    await db.insert(authorizationCodes).values({
      codeHash: sha256Hex(code),
      citizenId: row.citizenId,
      rpId: row.rpId,
      scopes: row.scopes,
      redirectUri: stash.redirectUri,
      codeChallenge: stash.codeChallenge,
      nonce: stash.nonce,
      assurance: binding.assuranceLevel,
      authTime: row.resolvedAt ?? new Date(),
      expiresAt: new Date(now + config.AUTH_CODE_TTL_SECONDS * 1000),
    });
    await this.redis.client.del(`codeflow:${txn}`);
    await this.audit.append({
      actor: { type: 'citizen', id: row.citizenId },
      action: 'oidc.code_issued',
      subjectRef: row.citizenId,
      rpId: row.rpId,
      deviceBindingId: binding.id,
      assurance: binding.assuranceLevel as AssuranceLevel,
      result: 'success',
      context: { flow: 'code', scopes: row.scopes },
    });
    const sep = stash.redirectUri.includes('?') ? '&' : '?';
    const redirect =
      `${stash.redirectUri}${sep}code=${encodeURIComponent(code)}` +
      (stash.state !== null ? `&state=${encodeURIComponent(stash.state)}` : '');
    return { status: 'approved', redirect };
  }

  // ------------------------------------------------------------------ HTML

  // NOTE: production pages are fully localised Kinyarwanda/English/French
  // (05 §7 — Kinyarwanda-first, plain non-technical language). These minimal
  // self-contained pages are the v1 development rendering.
  private approvalPageHtml(rpName: string, authReqId: string): string {
    const safeName = escapeHtml(rpName);
    const safeTxn = encodeURIComponent(authReqId);
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve this sign-in</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f6f8; color: #1a202c;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #fff; border-radius: 12px; padding: 32px; max-width: 420px;
          box-shadow: 0 2px 12px rgba(0,0,0,.08); text-align: center; }
  h1 { font-size: 1.3rem; margin: 0 0 8px; }
  .rp { font-weight: 600; }
  .hint { color: #4a5568; font-size: .95rem; }
  .spinner { margin: 24px auto 8px; width: 28px; height: 28px; border: 3px solid #cbd5e0;
             border-top-color: #2b6cb0; border-radius: 50%; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1>Approve this sign-in on your phone</h1>
  <p><span class="rp">${safeName}</span> is asking you to sign in.</p>
  <p class="hint">Open the authenticator app on your phone and approve the request. This page will continue automatically.</p>
  <div class="spinner" aria-hidden="true"></div>
  <p class="hint" id="msg">Waiting for your approval…</p>
</div>
<script>
  (function () {
    var timer = setInterval(function () {
      fetch('/oidc/authorize/poll?txn=${safeTxn}')
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j.status === 'approved') { clearInterval(timer); location.assign(j.redirect); }
          else if (j.status === 'denied') {
            clearInterval(timer);
            document.getElementById('msg').textContent = 'The sign-in was not approved.';
          }
        })
        .catch(function () { /* keep polling */ });
    }, 2000);
  })();
</script>
</body>
</html>`;
  }

  private accessDeniedHtml(): string {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in not available</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f6f8; color: #1a202c;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #fff; border-radius: 12px; padding: 32px; max-width: 420px;
          box-shadow: 0 2px 12px rgba(0,0,0,.08); text-align: center; }
  h1 { font-size: 1.3rem; margin: 0 0 8px; }
  p { color: #4a5568; }
</style>
</head>
<body>
<div class="card">
  <h1>We could not start this sign-in</h1>
  <p>Please return to the service you came from and try again.</p>
</div>
</body>
</html>`;
  }
}
