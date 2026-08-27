import { Inject, Injectable } from '@nestjs/common';
import { BridgeError, type AssuranceLevel, type SdidProvider } from '@sdid/shared';
import { and, eq } from 'drizzle-orm';
import { AuditService } from '../audit/audit.service.js';
import { loadConfig } from '../config.js';
import { DbService } from '../db/db.module.js';
import { citizens, deviceBindings } from '../db/schema.js';
import { SDID_PROVIDER } from '../sdid/sdid.module.js';

type BindingRow = typeof deviceBindings.$inferSelect;

export interface ReassertInput {
  citizenId: string;
  binding: BindingRow;
  /** Always re-assert regardless of staleness (AL3 step-up, 03 §6 / 06 §6). */
  force?: boolean;
  /** Audit context — what caused this check (e.g. 'al3-step-up', 'direct-login', 'ciba-approve', 'sweep'). */
  trigger: string;
}

export interface ReassertOutcome {
  /** True when SDID was actually contacted this call. */
  reasserted: boolean;
  assurance?: AssuranceLevel;
}

/**
 * Periodic SDID re-verification (spec 03 §6, decision #9).
 *
 * Routine logins only verify a device signature; SDID does not push identity
 * changes to us (Q12), so re-asserting the identity on a cadence is the ONLY
 * way to catch a revoked, deceased, or otherwise invalid identity behind an
 * already-bound device — at every assurance level, not just AL3. An AL3
 * request additionally forces a fresh re-assertion every time (step-up).
 *
 * A binding is "due" when the time since its last SDID contact — a prior
 * reassert, else its activation/enrolment (both of which validated the
 * identity against SDID) — exceeds REVERIFY_INTERVAL_SECONDS.
 *
 * When SDID declares the identity invalid, the citizen is suspended and every
 * one of their bindings is revoked (06 §6 assurance degradation): the only way
 * back is a fresh enrolment with a live biometric re-match (03 §5).
 */
@Injectable()
export class ReverificationService {
  constructor(
    private readonly dbService: DbService,
    private readonly audit: AuditService,
    @Inject(SDID_PROVIDER) private readonly sdid: SdidProvider,
  ) {}

  /** Anchor for staleness: last time this binding's identity was seen by SDID. */
  private lastSdidContact(binding: BindingRow): Date {
    return binding.lastReassertedAt ?? binding.activatedAt ?? binding.enrolledAt;
  }

  /** True when the binding must be re-asserted now (forced, or stale past the cadence). */
  isDue(binding: BindingRow, now: Date, force = false): boolean {
    if (force) return true;
    const intervalMs = loadConfig().REVERIFY_INTERVAL_SECONDS * 1000;
    return now.getTime() - this.lastSdidContact(binding).getTime() >= intervalMs;
  }

  /**
   * Re-assert the citizen's identity with SDID if the binding is due (or
   * forced). A no-op returns `{ reasserted: false }`. On an invalid identity
   * this THROWS `access_denied` (403) after suspending the citizen and
   * revoking their bindings — callers must let it propagate to fail the auth.
   */
  async reassertIfDue(input: ReassertInput): Promise<ReassertOutcome> {
    const now = new Date();
    if (!this.isDue(input.binding, now, input.force)) {
      return { reasserted: false };
    }
    return this.reassertNow(input.citizenId, input.binding.id, input.trigger, now);
  }

  /**
   * Contact SDID and act on the verdict. Kept separate from the due-check so
   * the sweep can decide dueness in bulk. Assumes the caller has already
   * established the binding is due.
   */
  private async reassertNow(
    citizenId: string,
    bindingId: string,
    trigger: string,
    now: Date,
  ): Promise<ReassertOutcome> {
    const db = this.dbService.db;
    const citizenRows = await db.select().from(citizens).where(eq(citizens.id, citizenId));
    const citizen = citizenRows[0];
    // No SDID subject = we cannot re-verify. For national-ID auth, fail closed.
    if (!citizen || citizen.status !== 'active' || !citizen.sdidSubject) {
      throw new BridgeError('access_denied', 'Identity cannot be re-asserted', 403);
    }

    const result = await this.sdid.reassert(citizen.sdidSubject);

    if (!result.valid) {
      await db.update(citizens).set({ status: 'suspended', updatedAt: now }).where(eq(citizens.id, citizenId));
      await db
        .update(deviceBindings)
        .set({
          status: 'revoked',
          revokedAt: now,
          revokeReason: 'sdid-reassert-invalid',
          // Same statement as the revocation: a suspended identity's devices
          // must stop being woken at once, and their push addresses are no
          // longer ours to hold (05 §5, 06 §4).
          pushPlatform: null,
          pushToken: null,
          pushTokenUpdatedAt: now,
        })
        .where(and(eq(deviceBindings.citizenId, citizenId), eq(deviceBindings.status, 'active')));
      await this.audit.append({
        actor: { type: 'system' },
        action: 'sdid.reassert',
        subjectRef: citizenId,
        deviceBindingId: bindingId,
        sdidTxnRef: result.txnRef,
        result: 'failure',
        context: { trigger, reason: 'identity-invalid', effect: 'citizen-suspended-bindings-revoked' },
      });
      throw new BridgeError('access_denied', 'Identity cannot be re-asserted', 403);
    }

    // A valid re-assertion re-verifies the identity, not a single device — so
    // it refreshes the cadence anchor for all of the citizen's active bindings.
    await db
      .update(deviceBindings)
      .set({ lastReassertedAt: now })
      .where(and(eq(deviceBindings.citizenId, citizenId), eq(deviceBindings.status, 'active')));
    await this.audit.append({
      actor: { type: 'system' },
      action: 'sdid.reassert',
      subjectRef: citizenId,
      deviceBindingId: bindingId,
      assurance: result.assurance,
      sdidTxnRef: result.txnRef,
      result: 'success',
      context: { trigger },
    });
    return { reasserted: true, assurance: result.assurance };
  }

  /**
   * Proactive cadence sweep (03 §6 "on a schedule"): re-assert active bindings
   * whose identity is past the cadence, so a revoked/deceased identity is
   * caught even on a device that is never used again — rather than only lazily
   * at next auth. Intended to be driven by an external scheduler (cron /
   * Kubernetes CronJob) hitting the admin endpoint. Batched and per-citizen
   * fault-isolated: one invalid identity is a recorded revocation, not a
   * sweep-aborting error.
   */
  async sweep(limit = 200): Promise<{ scanned: number; due: number; reasserted: number; revoked: number }> {
    const db = this.dbService.db;
    const now = new Date();
    const active = await db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.status, 'active'));

    // Collapse to one re-assertion per citizen (the check is identity-level).
    const dueCitizen = new Map<string, string>(); // citizenId -> a representative bindingId
    for (const b of active) {
      if (this.isDue(b, now, false) && !dueCitizen.has(b.citizenId)) {
        dueCitizen.set(b.citizenId, b.id);
      }
    }

    let reasserted = 0;
    let revoked = 0;
    let processed = 0;
    for (const [citizenId, bindingId] of dueCitizen) {
      if (processed >= limit) break;
      processed += 1;
      try {
        const outcome = await this.reassertNow(citizenId, bindingId, 'sweep', new Date());
        if (outcome.reasserted) reasserted += 1;
      } catch (err) {
        // access_denied is the expected outcome for an invalidated identity —
        // the revocation is already recorded. Anything else re-throws.
        if (err instanceof BridgeError && err.code === 'access_denied') {
          revoked += 1;
        } else {
          throw err;
        }
      }
    }

    return { scanned: active.length, due: dueCitizen.size, reasserted, revoked };
  }
}
