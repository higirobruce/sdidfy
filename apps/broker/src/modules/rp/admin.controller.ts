import { Body, Controller, Get, HttpCode, Param, Post, UseGuards } from '@nestjs/common';
import {
  BridgeError,
  registerRpRequestSchema,
  uuidv7,
  type RegisterRpRequest,
  type RegisterRpResponse,
} from '@sdid/shared';
import { eq } from 'drizzle-orm';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { AuditService } from '../../audit/audit.service.js';
import { ZodPipe } from '../../common/zod.pipe.js';
import { DbService } from '../../db/db.module.js';
import { citizens, relyingParties } from '../../db/schema.js';
import { PairwiseService } from '../../trust/pairwise.service.js';
import { ReverificationService } from '../../trust/reverification.service.js';
import { AdminGuard } from './admin.guard.js';
import { sha256Hex } from './rp.service.js';

const provisionPairwiseSchema = z.object({ pseudoNid: z.string().min(1) });
const reverifySweepSchema = z.object({ limit: z.coerce.number().int().min(1).max(1000).optional() });

/**
 * RP onboarding admin API (04 §6). Every action is admin-gated (AdminGuard)
 * and audited with an admin actor (T9/T12). The client secret is returned
 * exactly once at registration; only its SHA-256 hash is stored.
 */
@Controller('admin')
@UseGuards(AdminGuard)
export class AdminController {
  constructor(
    private readonly dbService: DbService,
    private readonly audit: AuditService,
    private readonly pairwise: PairwiseService,
    private readonly reverification: ReverificationService,
  ) {}

  @Post('rps')
  async registerRp(
    @Body(new ZodPipe(registerRpRequestSchema)) body: RegisterRpRequest,
  ): Promise<RegisterRpResponse> {
    const rpId = uuidv7();
    const clientId = `rp_${randomBytes(6).toString('hex')}`;
    const clientSecret = randomBytes(32).toString('base64url');
    const pairwiseSalt = randomBytes(32).toString('hex');
    await this.dbService.db.insert(relyingParties).values({
      id: rpId,
      clientId,
      name: body.name,
      logoUri: body.logoUri ?? null,
      authMethod: body.authMethod,
      clientSecretHash: sha256Hex(clientSecret),
      allowedScopes: body.allowedScopes,
      maxAssurance: body.maxAssurance,
      allowedFlows: body.allowedFlows,
      redirectUris: body.redirectUris,
      status: 'active',
      pairwiseSalt,
    });
    await this.audit.append({
      actor: { type: 'admin' },
      action: 'rp.registered',
      rpId,
      result: 'success',
      context: { name: body.name, clientId, allowedScopes: body.allowedScopes, allowedFlows: body.allowedFlows, maxAssurance: body.maxAssurance },
    });
    return { rpId, clientId, clientSecret };
  }

  @Get('rps')
  async listRps(): Promise<{
    rps: Array<{
      rpId: string;
      clientId: string;
      name: string;
      logoUri: string | null;
      authMethod: string;
      allowedScopes: string[];
      maxAssurance: string;
      allowedFlows: string[];
      redirectUris: string[];
      status: string;
      createdAt: string;
    }>;
  }> {
    const rows = await this.dbService.db.select().from(relyingParties);
    // No secret hashes and no pairwise salts leave this endpoint.
    return {
      rps: rows.map((r) => ({
        rpId: r.id,
        clientId: r.clientId,
        name: r.name,
        logoUri: r.logoUri,
        authMethod: r.authMethod,
        allowedScopes: r.allowedScopes,
        maxAssurance: r.maxAssurance,
        allowedFlows: r.allowedFlows,
        redirectUris: r.redirectUris,
        status: r.status,
        createdAt: r.createdAt.toISOString(),
      })),
    };
  }

  @Post('rps/:rpId/suspend')
  @HttpCode(200)
  async suspendRp(@Param('rpId') rpId: string): Promise<{ rpId: string; status: 'suspended' }> {
    const updated = await this.dbService.db
      .update(relyingParties)
      .set({ status: 'suspended' })
      .where(eq(relyingParties.id, rpId))
      .returning({ id: relyingParties.id });
    if (updated.length === 0) throw new BridgeError('invalid_request', 'Unknown relying party', 404);
    await this.audit.append({
      actor: { type: 'admin' },
      action: 'rp.suspended',
      rpId,
      result: 'success',
    });
    return { rpId, status: 'suspended' };
  }

  /**
   * Bootstrap pairwise provisioning: how a pilot RP obtains a login_hint for
   * a consented test citizen (04 §6 — onboarding produces the pairwise sub
   * mapping). Input is the pseudonymised NID — never a raw NID.
   */
  @Post('rps/:rpId/pairwise')
  @HttpCode(200)
  async provisionPairwise(
    @Param('rpId') rpId: string,
    @Body(new ZodPipe(provisionPairwiseSchema)) body: z.infer<typeof provisionPairwiseSchema>,
  ): Promise<{ subject: string }> {
    const rpRows = await this.dbService.db
      .select()
      .from(relyingParties)
      .where(eq(relyingParties.id, rpId));
    const rp = rpRows[0];
    if (!rp) throw new BridgeError('invalid_request', 'Unknown relying party', 404);
    const citizenRows = await this.dbService.db
      .select()
      .from(citizens)
      .where(eq(citizens.pseudoNid, body.pseudoNid));
    const citizen = citizenRows[0];
    if (!citizen) throw new BridgeError('invalid_request', 'Unknown citizen reference', 404);
    const subject = await this.pairwise.subjectFor(citizen.id, rp.id, rp.pairwiseSalt);
    await this.audit.append({
      actor: { type: 'admin' },
      action: 'admin.action',
      subjectRef: citizen.id,
      rpId: rp.id,
      result: 'success',
      context: { op: 'provision-pairwise' },
    });
    return { subject };
  }

  @Get('audit/verify')
  async verifyAudit(): Promise<{ intact: boolean; brokenAtSeq: number | null; count: number }> {
    return this.audit.verifyChain();
  }

  /**
   * Proactive re-verification sweep (03 §6 "on a schedule", decision #9). Meant
   * to be driven by an external scheduler (cron / Kubernetes CronJob) so a
   * revoked/deceased identity is caught even on a device that is never used
   * again — rather than only lazily at its next auth. Re-asserts each active
   * binding past the cadence against SDID, one call per citizen; an invalid
   * identity is suspended + revoked as part of the tally, not an error.
   */
  @Post('reverify/sweep')
  @HttpCode(200)
  async reverifySweep(
    @Body(new ZodPipe(reverifySweepSchema)) body: z.infer<typeof reverifySweepSchema>,
  ): Promise<{ scanned: number; due: number; reasserted: number; revoked: number }> {
    const summary = await this.reverification.sweep(body.limit);
    await this.audit.append({
      actor: { type: 'admin' },
      action: 'admin.action',
      result: 'success',
      context: { op: 'reverify-sweep', ...summary },
    });
    return summary;
  }
}
