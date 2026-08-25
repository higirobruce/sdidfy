import { Injectable } from '@nestjs/common';
import { desc, eq } from 'drizzle-orm';
import {
  BridgeError,
  type AssuranceLevel,
  type DeviceListItem,
  type IssuedChallenge,
  type LoginRequest,
  type LoginResponse,
} from '@sdid/shared';
import { loadConfig } from '../../config.js';
import { DbService } from '../../db/db.module.js';
import { auditEvents, deviceBindings, relyingParties } from '../../db/schema.js';
import { AuditService } from '../../audit/audit.service.js';
import { KeysService } from '../../keys/keys.service.js';
import { ChallengeService } from '../../trust/challenge.service.js';
import { DEVICE_SESSION_AUDIENCE } from '../../trust/device-session.guard.js';
import { RateLimitService } from '../../trust/rate-limit.service.js';
import { ReverificationService } from '../../trust/reverification.service.js';
import { SignatureService } from '../../trust/signature.service.js';

/** Login failure lockout: 5 failures / 15 min window (T1, 03 §7). */
const LOGIN_MAX_FAILURES = 5;
const LOGIN_FAILURE_WINDOW_SECONDS = 900;

export interface ActivityItem {
  ts: string;
  action: string;
  result: string;
  rpName?: string;
}

type BindingRow = typeof deviceBindings.$inferSelect;

/**
 * Direct login (01 §2.2) + the citizen's authenticated device backchannel
 * (05 §2): device list, revocation, activity. Routine auth verifies a
 * signature only — no biometric, no SDID round-trip.
 */
@Injectable()
export class DevicesService {
  constructor(
    private readonly dbService: DbService,
    private readonly audit: AuditService,
    private readonly keys: KeysService,
    private readonly challenges: ChallengeService,
    private readonly rateLimit: RateLimitService,
    private readonly signatures: SignatureService,
    private readonly reverification: ReverificationService,
  ) {}

  private async loadBinding(bindingId: string): Promise<BindingRow> {
    const rows = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.id, bindingId));
    const binding = rows[0];
    if (!binding) throw new BridgeError('binding_not_found', 'Unknown device binding', 404);
    return binding;
  }

  /** Binding must be 'active' — a revoked device is rejected immediately (06 §4). */
  private assertActive(binding: BindingRow): void {
    if (binding.status !== 'active') {
      throw new BridgeError('binding_not_active', 'Device binding is not active', 401);
    }
  }

  async issueLoginChallenge(bindingId: string): Promise<IssuedChallenge> {
    const binding = await this.loadBinding(bindingId);
    this.assertActive(binding);
    await this.rateLimit.assertNotLockedOut(`login:${bindingId}`, LOGIN_MAX_FAILURES);
    const challenge = await this.challenges.issue({ kind: 'login' }, bindingId);
    await this.audit.append({
      actor: { type: 'citizen', id: binding.citizenId },
      action: 'auth.challenge_issued',
      subjectRef: binding.citizenId,
      deviceBindingId: bindingId,
      result: 'success',
      context: { purpose: 'login' },
    });
    return challenge;
  }

  async login(req: LoginRequest): Promise<LoginResponse> {
    const binding = await this.loadBinding(req.bindingId);
    this.assertActive(binding);

    try {
      const payload = await this.challenges.consume(
        req.challengeId,
        { kind: 'login' },
        req.bindingId,
      );
      await this.signatures.verifyDeviceSignature(
        binding.devicePubkeyJwk as { kty: string; crv: string; x: string; y: string },
        payload,
        req.signature,
      );
    } catch (err) {
      await this.rateLimit.recordFailure(
        `login:${req.bindingId}`,
        LOGIN_MAX_FAILURES,
        LOGIN_FAILURE_WINDOW_SECONDS,
      );
      await this.audit.append({
        actor: { type: 'citizen', id: binding.citizenId },
        action: 'auth.login_failed',
        subjectRef: binding.citizenId,
        deviceBindingId: binding.id,
        result: 'failure',
        context: { reason: err instanceof BridgeError ? err.code : 'internal_error' },
      });
      throw err;
    }

    await this.rateLimit.clearFailures(`login:${req.bindingId}`);

    // Re-verification cadence (03 §6, decision #9): a routine login only proved
    // a signature. If this binding is past the SDID re-verify cadence, re-assert
    // the identity now — our only signal for a revoked/deceased identity behind
    // an already-bound device. An invalid identity throws access_denied (403)
    // after suspending the citizen and revoking their bindings; the login fails.
    await this.reverification.reassertIfDue({
      citizenId: binding.citizenId,
      binding,
      trigger: 'direct-login',
    });

    await this.dbService.db
      .update(deviceBindings)
      .set({ lastUsedAt: new Date() })
      .where(eq(deviceBindings.id, binding.id));
    await this.audit.append({
      actor: { type: 'citizen', id: binding.citizenId },
      action: 'auth.login_succeeded',
      subjectRef: binding.citizenId,
      deviceBindingId: binding.id,
      assurance: binding.assuranceLevel as AssuranceLevel,
      result: 'success',
    });

    const ttlSeconds = loadConfig().SESSION_TTL_SECONDS;
    const sessionToken = await this.keys.signJwt(
      {
        sub: binding.citizenId,
        binding_id: binding.id,
        acr: binding.assuranceLevel,
        amr: ['hwk', 'bio'],
      },
      { audience: DEVICE_SESSION_AUDIENCE, ttlSeconds },
    );
    return { sessionToken, expiresIn: ttlSeconds };
  }

  /** All of the citizen's bindings, every status (05 §2 devices screen). */
  async listBindings(citizenId: string): Promise<DeviceListItem[]> {
    const rows = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.citizenId, citizenId))
      .orderBy(desc(deviceBindings.enrolledAt));
    return rows.map((b) => ({
      bindingId: b.id,
      deviceLabel: b.deviceLabel,
      assuranceLevel: b.assuranceLevel as AssuranceLevel,
      status: b.status as 'pending' | 'active' | 'revoked',
      enrolledAt: b.enrolledAt.toISOString(),
      lastUsedAt: b.lastUsedAt ? b.lastUsedAt.toISOString() : null,
    }));
  }

  /** Revoke one of the citizen's own bindings (03 §5, 06 §4 — immediate). */
  async revokeBinding(
    citizenId: string,
    bindingId: string,
    reason?: string,
  ): Promise<{ status: 'revoked' }> {
    const rows = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.id, bindingId));
    const binding = rows[0];
    // Own bindings only — a foreign binding id is indistinguishably "not found".
    if (!binding || binding.citizenId !== citizenId) {
      throw new BridgeError('binding_not_found', 'Unknown device binding', 404);
    }
    if (binding.status === 'revoked') return { status: 'revoked' }; // idempotent
    const revokeReason = reason ?? 'citizen-revoked';
    await this.dbService.db
      .update(deviceBindings)
      .set({ status: 'revoked', revokedAt: new Date(), revokeReason })
      .where(eq(deviceBindings.id, bindingId));
    await this.audit.append({
      actor: { type: 'citizen', id: citizenId },
      action: 'device.revoked',
      subjectRef: citizenId,
      deviceBindingId: bindingId,
      result: 'success',
      context: { reason: revokeReason },
    });
    return { status: 'revoked' };
  }

  /**
   * Citizen-rights activity view (08 §5): the citizen's own audit trail,
   * reduced to what is theirs to see — never hashes, never raw context.
   */
  async recentActivity(citizenId: string): Promise<ActivityItem[]> {
    const rows = await this.dbService.db
      .select({
        ts: auditEvents.ts,
        action: auditEvents.action,
        result: auditEvents.result,
        rpName: relyingParties.name,
      })
      .from(auditEvents)
      .leftJoin(relyingParties, eq(auditEvents.rpId, relyingParties.id))
      .where(eq(auditEvents.subjectRef, citizenId))
      .orderBy(desc(auditEvents.seq))
      .limit(50);
    return rows.map((r) => ({
      ts: r.ts.toISOString(),
      action: r.action,
      result: r.result,
      ...(r.rpName ? { rpName: r.rpName } : {}),
    }));
  }
}
