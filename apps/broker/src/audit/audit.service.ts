import { Global, Injectable, Logger, Module } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { uuidv7, type AuditEventInput } from '@sdid/shared';
import { DbService } from '../db/db.module.js';
import { MetricsService } from '../observability/metrics.service.js';

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`);
  return `{${entries.join(',')}}`;
}

const GENESIS_HASH = 'genesis';
const CHAIN_LOCK_KEY = 429_001; // pg advisory lock guarding chain linearity

/**
 * Append-only, tamper-evident audit trail (07 §4, 06 §7).
 * Each row's hash = SHA-256(prev_hash || canonical(row)). Appends serialize
 * on a transaction-scoped advisory lock so the chain is strictly linear even
 * across broker replicas. UPDATE/DELETE are blocked by a DB trigger.
 *
 * Audit MUST NOT be best-effort for security events: callers await append()
 * and a failed audit write fails the operation (no unaudited state change).
 */
/**
 * Notified after a row is durably committed. Observers are the audit-stream
 * consumers described in 06 §5 (anomaly detection); they never influence the
 * append, and an observer error is swallowed.
 */
export type AuditObserver = (event: AuditEventInput) => void;

@Injectable()
export class AuditService {
  private readonly logger = new Logger('AuditService');
  private readonly observers: AuditObserver[] = [];

  constructor(
    private readonly dbService: DbService,
    private readonly metrics: MetricsService,
  ) {}

  /**
   * Subscribe to the committed audit stream (06 §5). Deliberately in-process
   * and post-commit: a subscriber sees only events that actually made it into
   * the tamper-evident chain, and cannot roll one back. Nothing here is a
   * durable queue — a broker restart loses in-flight detector windows, which
   * is acceptable for a signal whose windows are minutes long.
   */
  subscribe(observer: AuditObserver): void {
    this.observers.push(observer);
  }

  async append(event: AuditEventInput): Promise<{ id: string; hash: string }> {
    const id = uuidv7();
    const ts = new Date();
    const client = await this.dbService.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [CHAIN_LOCK_KEY]);
      const last = await client.query('SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1');
      const prevHash: string = last.rows[0]?.hash ?? GENESIS_HASH;
      const hash = this.computeHash(prevHash, id, ts, event);
      await client.query(
        `INSERT INTO audit_events
           (id, ts, actor, action, subject_ref, rp_id, device_binding_id, assurance,
            match_result, sdid_txn_ref, result, context, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [
          id,
          ts,
          JSON.stringify(event.actor),
          event.action,
          event.subjectRef ?? null,
          event.rpId ?? null,
          event.deviceBindingId ?? null,
          event.assurance ?? null,
          event.matchResult ? JSON.stringify(event.matchResult) : null,
          event.sdidTxnRef ?? null,
          event.result,
          event.context ? JSON.stringify(event.context) : null,
          prevHash,
          hash,
        ],
      );
      await client.query('COMMIT');
      this.metrics.recordAuditAppend(true);
      this.notify(event);
      return { id, hash };
    } catch (err) {
      await client.query('ROLLBACK');
      // A failed append fails the operation it was recording (no unaudited
      // state change), so this counter is an "the auth path is refusing work"
      // signal, not a background error rate — alert on any non-zero value.
      this.metrics.recordAuditAppend(false);
      throw err;
    } finally {
      client.release();
    }
  }

  /** Fan out to observers. Post-commit, isolated, and never able to throw. */
  private notify(event: AuditEventInput): void {
    for (const observer of this.observers) {
      try {
        observer(event);
      } catch (err) {
        this.logger.warn(
          `audit observer threw: ${err instanceof Error ? err.message : 'unknown'}`,
        );
      }
    }
  }

  private computeHash(prevHash: string, id: string, ts: Date, event: AuditEventInput): string {
    // jsonb round-trips reorder object keys, so hashing must use a
    // key-sorted canonical form or verifyChain would false-alarm.
    const canonical = stableStringify({
      id,
      ts: ts.toISOString(),
      actor: event.actor,
      action: event.action,
      subjectRef: event.subjectRef ?? null,
      rpId: event.rpId ?? null,
      deviceBindingId: event.deviceBindingId ?? null,
      assurance: event.assurance ?? null,
      matchResult: event.matchResult ?? null,
      sdidTxnRef: event.sdidTxnRef ?? null,
      result: event.result,
      context: event.context ?? null,
    });
    return createHash('sha256').update(prevHash).update(canonical).digest('hex');
  }

  /** Walk the chain and verify tamper-evidence. Returns first broken seq, or null if intact. */
  async verifyChain(): Promise<{ intact: boolean; brokenAtSeq: number | null; count: number }> {
    const { rows } = await this.dbService.pool.query(
      `SELECT seq, id, ts, actor, action, subject_ref, rp_id, device_binding_id, assurance,
              match_result, sdid_txn_ref, result, context, prev_hash, hash
         FROM audit_events ORDER BY seq ASC`,
    );
    let prev = GENESIS_HASH;
    for (const r of rows) {
      if (r.prev_hash !== prev) return { intact: false, brokenAtSeq: Number(r.seq), count: rows.length };
      const recomputed = this.computeHash(prev, r.id, new Date(r.ts), {
        actor: r.actor,
        action: r.action,
        subjectRef: r.subject_ref ?? undefined,
        rpId: r.rp_id ?? undefined,
        deviceBindingId: r.device_binding_id ?? undefined,
        assurance: r.assurance ?? undefined,
        matchResult: r.match_result ?? undefined,
        sdidTxnRef: r.sdid_txn_ref ?? undefined,
        result: r.result,
        context: r.context ?? undefined,
      });
      if (recomputed !== r.hash) return { intact: false, brokenAtSeq: Number(r.seq), count: rows.length };
      prev = r.hash;
    }
    return { intact: true, brokenAtSeq: null, count: rows.length };
  }
}

@Global()
@Module({
  providers: [AuditService],
  exports: [AuditService],
})
export class AuditModule {}
