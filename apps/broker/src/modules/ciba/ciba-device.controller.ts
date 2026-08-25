import { Body, Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import {
  BridgeError,
  alMeets,
  cibaDecisionRequestSchema,
  type AssuranceLevel,
  type CibaDecisionRequest,
  type PendingTransaction,
  type PendingTransactionsResponse,
} from '@sdid/shared';
import { and, eq, gt, inArray } from 'drizzle-orm';
import type { Request } from 'express';
import { AuditService } from '../../audit/audit.service.js';
import { ZodPipe } from '../../common/zod.pipe.js';
import { DbService } from '../../db/db.module.js';
import { authTransactions, deviceBindings, relyingParties } from '../../db/schema.js';
import { ChallengeService } from '../../trust/challenge.service.js';
import { DeviceSessionGuard, type DeviceSession } from '../../trust/device-session.guard.js';
import { ReverificationService } from '../../trust/reverification.service.js';
import { SignatureService } from '../../trust/signature.service.js';

type DeviceRequest = Request & { deviceSession: DeviceSession };

/** Plain-language scope rendering shown on the approval prompt (05 §2, T7). */
function describeScope(scope: string): string {
  switch (scope) {
    case 'openid':
      return 'Confirm your identity';
    case 'profile':
      return 'Share your name and date of birth';
    case 'address':
      return 'Share your registered address';
    default:
      return scope;
  }
}

/**
 * Device backchannel for CIBA (04 §3 steps 5–7). The push channel is
 * wake-only; the app pulls pending requests here over the authenticated
 * device session, shows who is asking + what for, and returns a SIGNED
 * approve/deny decision (denials are authentic too).
 */
@Controller('v1/device/ciba')
@UseGuards(DeviceSessionGuard)
export class CibaDeviceController {
  constructor(
    private readonly dbService: DbService,
    private readonly challenges: ChallengeService,
    private readonly signatures: SignatureService,
    private readonly audit: AuditService,
    private readonly reverification: ReverificationService,
  ) {}

  @Get('pending')
  async pending(@Req() req: DeviceRequest): Promise<PendingTransactionsResponse> {
    const session = req.deviceSession;
    const db = this.dbService.db;
    const txns = await db
      .select()
      .from(authTransactions)
      .where(
        and(
          eq(authTransactions.citizenId, session.citizenId),
          eq(authTransactions.status, 'pending'),
          gt(authTransactions.expiresAt, new Date()),
        ),
      )
      .orderBy(authTransactions.createdAt);
    if (txns.length === 0) return { transactions: [] };

    const rpIds = [...new Set(txns.map((t) => t.rpId))];
    const rps = await db.select().from(relyingParties).where(inArray(relyingParties.id, rpIds));
    const rpById = new Map(rps.map((r) => [r.id, r]));

    const transactions: PendingTransaction[] = [];
    for (const txn of txns) {
      const rp = rpById.get(txn.rpId);
      if (!rp) continue;
      const challenge = await this.challenges.issueCiba(txn.authReqId, session.bindingId);
      transactions.push({
        authReqId: txn.authReqId,
        rpName: rp.name,
        rpLogoUri: rp.logoUri,
        scopes: txn.scopes,
        scopeDescriptions: txn.scopes.map(describeScope),
        bindingMessage: txn.bindingMessage,
        requestedAssurance: txn.requestedAl as AssuranceLevel,
        createdAt: txn.createdAt.toISOString(),
        expiresAt: txn.expiresAt.toISOString(),
        challenge: {
          challengeId: challenge.challengeId,
          nonce: challenge.nonce,
          approvePayload: challenge.approvePayload,
          denyPayload: challenge.denyPayload,
          expiresAt: challenge.expiresAt,
        },
      });
    }
    return { transactions };
  }

  @Post('decision')
  @HttpCode(200)
  async decision(
    @Req() req: DeviceRequest,
    @Body(new ZodPipe(cibaDecisionRequestSchema)) body: CibaDecisionRequest,
  ): Promise<{ status: 'approved' | 'denied' }> {
    const session = req.deviceSession;
    const db = this.dbService.db;
    const now = new Date();

    const txnRows = await db
      .select()
      .from(authTransactions)
      .where(eq(authTransactions.authReqId, body.authReqId));
    const txn = txnRows[0];
    if (
      !txn ||
      txn.status !== 'pending' ||
      txn.expiresAt.getTime() <= now.getTime() ||
      txn.citizenId !== session.citizenId ||
      body.bindingId !== session.bindingId
    ) {
      throw new BridgeError('access_denied', 'Transaction cannot be decided by this device', 403);
    }

    const bindingRows = await db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.id, session.bindingId));
    const binding = bindingRows[0];
    if (!binding || binding.status !== 'active') {
      throw new BridgeError('binding_not_active', 'Device binding is not active', 401);
    }
    if (!alMeets(binding.assuranceLevel as AssuranceLevel, txn.requestedAl as AssuranceLevel)) {
      throw new BridgeError('assurance_insufficient', 'Binding does not meet requested assurance', 403);
    }

    // Re-verification (03 §6, 06 §6, decision #9): before minting anything on
    // an APPROVAL, re-assert the identity with SDID when this is an AL3 step-up
    // (always) or the binding is past the re-verify cadence (any level). This
    // is our only revoked/deceased-identity signal; an invalid identity
    // suspends the citizen and revokes their bindings. A denial mints nothing,
    // so it needs no fresh identity check.
    if (body.decision === 'approve') {
      await this.reverification.reassertIfDue({
        citizenId: txn.citizenId,
        binding,
        force: txn.requestedAl === 'AL3',
        trigger: txn.requestedAl === 'AL3' ? 'al3-step-up' : 'ciba-approve',
      });
    }

    const payload = await this.challenges.consumeCiba(
      body.challengeId,
      body.authReqId,
      body.bindingId,
      body.decision,
    );
    await this.signatures.verifyDeviceSignature(
      binding.devicePubkeyJwk as { kty: string; crv: string; x: string; y: string },
      payload,
      body.signature,
    );

    const status = body.decision === 'approve' ? 'approved' : 'denied';
    await db
      .update(authTransactions)
      .set({
        status,
        deviceBindingId: binding.id,
        resolvedAt: now,
        ...(body.reportSuspicious ? { suspiciousReport: 'citizen-reported-suspicious' } : {}),
      })
      .where(and(eq(authTransactions.id, txn.id), eq(authTransactions.status, 'pending')));
    await this.audit.append({
      actor: { type: 'citizen', id: txn.citizenId },
      action: body.decision === 'approve' ? 'ciba.request_approved' : 'ciba.request_denied',
      subjectRef: txn.citizenId,
      rpId: txn.rpId,
      deviceBindingId: binding.id,
      assurance: binding.assuranceLevel as AssuranceLevel,
      result: body.decision === 'approve' ? 'success' : 'denied',
      context: {
        flow: txn.flow,
        scopes: txn.scopes,
        ...(body.reportSuspicious ? { reportedSuspicious: true } : {}),
      },
    });
    await db
      .update(deviceBindings)
      .set({ lastUsedAt: now })
      .where(eq(deviceBindings.id, binding.id));

    return { status };
  }
}
