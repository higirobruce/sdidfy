import { Injectable } from '@nestjs/common';
import { and, eq, isNull } from 'drizzle-orm';
import { BridgeError, uuidv7 } from '@sdid/shared';
import { DbService } from '../../db/db.module.js';
import { AuditService } from '../../audit/audit.service.js';
import { consentGrants, relyingParties } from '../../db/schema.js';

export type ConsentSource = 'ciba-approval' | 'code-flow' | 'standing-grant';

export interface RecordGrantInput {
  citizenId: string;
  rpId: string;
  scopes: string[];
  source: ConsentSource | string;
}

export interface ConsentListItem {
  id: string;
  rpName: string;
  scopes: string[];
  grantedAt: string;
  revokedAt: string | null;
  source: string;
}

/**
 * Consent registry (spec 04 §5, 08 §4): every approval / attribute release is
 * an explicit, logged consent event. Grants are never deleted — revocation
 * sets revokedAt, and both grant and revocation land in the append-only audit.
 */
@Injectable()
export class ConsentService {
  constructor(
    private readonly dbService: DbService,
    private readonly audit: AuditService,
  ) {}

  /** Insert a consent grant + audit 'consent.granted'. Audit failure fails the grant. */
  async recordGrant(input: RecordGrantInput): Promise<{ id: string }> {
    const id = uuidv7();
    await this.dbService.db.insert(consentGrants).values({
      id,
      citizenId: input.citizenId,
      rpId: input.rpId,
      scopes: input.scopes,
      source: input.source,
    });
    await this.audit.append({
      actor: { type: 'citizen', id: input.citizenId },
      action: 'consent.granted',
      subjectRef: input.citizenId,
      rpId: input.rpId,
      result: 'success',
      context: { consentId: id, scopes: input.scopes, source: input.source },
    });
    return { id };
  }

  /** True when a non-revoked grant for (citizen, rp) covers ALL requested scopes. */
  async hasActiveGrant(citizenId: string, rpId: string, scopes: string[]): Promise<boolean> {
    const rows = await this.dbService.db
      .select({ scopes: consentGrants.scopes })
      .from(consentGrants)
      .where(
        and(
          eq(consentGrants.citizenId, citizenId),
          eq(consentGrants.rpId, rpId),
          isNull(consentGrants.revokedAt),
        ),
      );
    return rows.some((grant) => scopes.every((s) => grant.scopes.includes(s)));
  }

  /** Citizen-facing consent list (05 §2 consents/activity screen). */
  async listGrants(citizenId: string): Promise<ConsentListItem[]> {
    const rows = await this.dbService.db
      .select({
        id: consentGrants.id,
        rpName: relyingParties.name,
        scopes: consentGrants.scopes,
        grantedAt: consentGrants.grantedAt,
        revokedAt: consentGrants.revokedAt,
        source: consentGrants.source,
      })
      .from(consentGrants)
      .innerJoin(relyingParties, eq(consentGrants.rpId, relyingParties.id))
      .where(eq(consentGrants.citizenId, citizenId));
    return rows.map((r) => ({
      id: r.id,
      rpName: r.rpName,
      scopes: r.scopes,
      grantedAt: r.grantedAt.toISOString(),
      revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
      source: r.source,
    }));
  }

  /**
   * Revoke a grant the citizen owns. Idempotent for already-revoked grants
   * (no second state change → no second audit row).
   */
  async revokeGrant(citizenId: string, consentId: string): Promise<void> {
    const rows = await this.dbService.db
      .select()
      .from(consentGrants)
      .where(and(eq(consentGrants.id, consentId), eq(consentGrants.citizenId, citizenId)));
    const grant = rows[0];
    if (!grant) {
      // Own grants only — a foreign/unknown id is indistinguishably "not found".
      throw new BridgeError('invalid_request', 'Consent grant not found', 404);
    }
    if (grant.revokedAt) return; // already revoked — nothing to change
    await this.dbService.db
      .update(consentGrants)
      .set({ revokedAt: new Date() })
      .where(eq(consentGrants.id, consentId));
    await this.audit.append({
      actor: { type: 'citizen', id: citizenId },
      action: 'consent.revoked',
      subjectRef: citizenId,
      rpId: grant.rpId,
      result: 'success',
      context: { consentId },
    });
  }
}
