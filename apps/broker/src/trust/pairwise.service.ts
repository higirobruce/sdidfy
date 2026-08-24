import { Injectable } from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { DbService } from '../db/db.module.js';
import { pairwiseSubjects } from '../db/schema.js';
import { and, eq } from 'drizzle-orm';
import { loadConfig } from '../config.js';

/**
 * Pairwise/sectoral subjects (04 §4) and the pseudonymised NID (Q8).
 * A per-RP salt keys the subject derivation so no two RPs can correlate a
 * citizen; the NID pepper keys the pseudo-NID so a DB dump alone cannot be
 * joined back to raw NIDs. Both are privacy non-negotiables (10).
 */
@Injectable()
export class PairwiseService {
  constructor(private readonly dbService: DbService) {}

  pseudoNid(nid: string): string {
    return createHmac('sha256', loadConfig().NID_PEPPER).update(nid).digest('hex');
  }

  deriveSubject(pairwiseSaltHex: string, citizenId: string): string {
    return createHmac('sha256', Buffer.from(pairwiseSaltHex, 'hex')).update(citizenId).digest('base64url');
  }

  /** Get-or-create the persisted pairwise subject for (citizen, rp). */
  async subjectFor(citizenId: string, rpId: string, pairwiseSaltHex: string): Promise<string> {
    const db = this.dbService.db;
    const existing = await db
      .select()
      .from(pairwiseSubjects)
      .where(and(eq(pairwiseSubjects.citizenId, citizenId), eq(pairwiseSubjects.rpId, rpId)));
    if (existing[0]) return existing[0].subject;
    const subject = this.deriveSubject(pairwiseSaltHex, citizenId);
    await db.insert(pairwiseSubjects).values({ citizenId, rpId, subject }).onConflictDoNothing();
    return subject;
  }

  /** Resolve a login_hint (pairwise subject) back to the citizen — RP-scoped by design. */
  async citizenForSubject(rpId: string, subject: string): Promise<string | null> {
    const db = this.dbService.db;
    const rows = await db
      .select()
      .from(pairwiseSubjects)
      .where(and(eq(pairwiseSubjects.rpId, rpId), eq(pairwiseSubjects.subject, subject)));
    return rows[0]?.citizenId ?? null;
  }
}
