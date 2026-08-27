import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import {
  BridgeError,
  alMeets,
  bcAuthorizeRequestSchema,
  uuidv7,
  type AssuranceLevel,
  type BcAuthorizeRequest,
  type BcAuthorizeResponse,
} from '@sdid/shared';
import { and, eq } from 'drizzle-orm';
import type { Request } from 'express';
import { randomBytes } from 'node:crypto';
import { AuditService } from '../../audit/audit.service.js';
import { ZodPipe } from '../../common/zod.pipe.js';
import { loadConfig } from '../../config.js';
import { DbService } from '../../db/db.module.js';
import { authTransactions, deviceBindings } from '../../db/schema.js';
import { MetricsService } from '../../observability/metrics.service.js';
import { PushService } from '../../push/push.service.js';
import { PairwiseService } from '../../trust/pairwise.service.js';
import { RateLimitService } from '../../trust/rate-limit.service.js';
import { RpService } from '../rp/rp.service.js';

/**
 * CIBA backchannel authentication endpoint (spec 04 §3, CIBA Core).
 * The RP initiates; the citizen's phone completes out-of-band. login_hint is
 * the RP's pairwise subject — never a raw NID or biometric. Device-state
 * detail is never leaked to the RP: no resolvable citizen and no capable
 * binding both answer `unknown_user_id`.
 */
@Controller()
export class CibaController {
  constructor(
    private readonly dbService: DbService,
    private readonly rpService: RpService,
    private readonly rateLimit: RateLimitService,
    private readonly pairwise: PairwiseService,
    private readonly push: PushService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  @Post('oidc/bc-authorize')
  @HttpCode(200)
  async bcAuthorize(
    @Req() req: Request,
    @Body(new ZodPipe(bcAuthorizeRequestSchema)) body: BcAuthorizeRequest,
  ): Promise<BcAuthorizeResponse> {
    const rp = await this.rpService.authenticateClient(req);
    await this.rateLimit.hit(`ciba:rp:${rp.id}`, 60, 60);

    if (!rp.allowedFlows.includes('ciba')) {
      throw new BridgeError('unauthorized_client', 'Client may not use CIBA', 400);
    }
    const scopes = body.scope.split(' ').filter(Boolean);
    if (!scopes.includes('openid') || !scopes.every((s) => rp.allowedScopes.includes(s))) {
      throw new BridgeError('invalid_scope', 'Requested scopes exceed the client grant', 400);
    }
    const requestedAl: AssuranceLevel = body.requested_al ?? 'AL2';
    if (!alMeets(rp.maxAssurance as AssuranceLevel, requestedAl)) {
      throw new BridgeError('invalid_request', 'Requested assurance exceeds client maximum', 400);
    }

    const citizenId = await this.pairwise.citizenForSubject(rp.id, body.login_hint);
    if (!citizenId) {
      throw new BridgeError('unknown_user_id', 'Unknown login_hint', 400);
    }
    // The citizen must hold at least one ACTIVE binding able to meet the
    // requested assurance. Anything else is `unknown_user_id` too — never
    // leak device state to an RP (T9/T16).
    const bindings = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(and(eq(deviceBindings.citizenId, citizenId), eq(deviceBindings.status, 'active')));
    const capable = bindings.some((b) => alMeets(b.assuranceLevel as AssuranceLevel, requestedAl));
    if (!capable) {
      throw new BridgeError('unknown_user_id', 'Unknown login_hint', 400);
    }

    const config = loadConfig();
    const expiresIn = body.requested_expiry ?? config.CIBA_REQUEST_TTL_SECONDS;
    const authReqId = randomBytes(32).toString('base64url');
    await this.dbService.db.insert(authTransactions).values({
      id: uuidv7(),
      authReqId,
      citizenId,
      rpId: rp.id,
      flow: 'ciba',
      scopes,
      requestedAl,
      bindingMessage: body.binding_message ?? null,
      status: 'pending',
      expiresAt: new Date(Date.now() + expiresIn * 1000),
    });
    await this.push.wake(citizenId); // wake-only, no auth data (T6)
    // Flow label only — never the RP id. Per-RP volume is a legitimate
    // operational question, but as a metric label an rp uuid is unbounded
    // cardinality; per-RP abuse is the anomaly detector's job (06 §5).
    this.metrics.recordCibaRequest('ciba');
    await this.audit.append({
      actor: { type: 'rp', id: rp.id },
      action: 'ciba.request_created',
      subjectRef: citizenId,
      rpId: rp.id,
      result: 'success',
      context: { scopes, requestedAl },
    });
    return {
      auth_req_id: authReqId,
      expires_in: expiresIn,
      interval: config.CIBA_POLL_INTERVAL_SECONDS,
    };
  }
}
