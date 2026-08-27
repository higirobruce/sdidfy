import { Global, Module } from '@nestjs/common';
import type { AttributeSet, MatchEngine, ReassertResult, ReferenceBiometricResult, SdidProvider } from '@sdid/shared';
import { createSdidProvider } from '@sdid/sdid-adapter';
import { createMatchEngine } from '@sdid/match-engine';
import { loadConfig } from '../config.js';
import { AuditService } from '../audit/audit.service.js';
import { MetricsService } from '../observability/metrics.service.js';

/**
 * Injection seam for the SDID adapter + match engine (02 §4).
 * The broker only ever sees the SdidProvider / MatchEngine contracts;
 * SDID_STRATEGY flips mock ↔ real without redeploying broker code.
 */
export const SDID_PROVIDER = Symbol('SDID_PROVIDER');
export const MATCH_ENGINE = Symbol('MATCH_ENGINE');

/**
 * Latency + circuit-breaker instrumentation, wrapped around the adapter at the
 * broker's own seam (09 §2 Phase 3 — SDID is the dependency most likely to be
 * the cause of an incident, and the one we control least).
 *
 * It sits HERE rather than inside the adapter for two reasons: the adapter is
 * owned by another workstream and its `SdidProvider` contract deliberately
 * exposes no breaker state (02 §4), and instrumenting at the seam measures
 * what the broker actually experiences — retries, backoff and breaker
 * rejections included — which is the number an operator needs.
 *
 * The breaker gauge is therefore INFERRED: `SdidCircuitOpenError` means the
 * breaker rejected the call, any success means it is closed again. That is a
 * faithful view of the outcomes, not of the adapter's internal state — a
 * half-open probe is invisible here, and the gauge is stale while no calls are
 * being made. Documented in the metric's HELP text.
 */
function instrumentSdidProvider(inner: SdidProvider, metrics: MetricsService): SdidProvider {
  const timed = async <T>(operation: string, call: () => Promise<T>): Promise<T> => {
    const startedAt = Date.now();
    try {
      const result = await call();
      metrics.recordSdidCall({ operation, outcome: 'success', durationMs: Date.now() - startedAt });
      metrics.recordSdidCircuitState(false);
      return result;
    } catch (err) {
      // Error CLASS name only — a bounded vocabulary the adapter owns, and
      // adapter messages are NID-free but messages are not label material.
      const name = err instanceof Error ? err.name : 'unknown';
      metrics.recordSdidCall({ operation, outcome: name, durationMs: Date.now() - startedAt });
      if (name === 'SdidCircuitOpenError') metrics.recordSdidCircuitState(true);
      throw err;
    }
  };
  return {
    getReferenceBiometric: (input) =>
      timed<ReferenceBiometricResult>('getReferenceBiometric', () => inner.getReferenceBiometric(input)),
    getAttributes: (idOrSubject, scopes) =>
      timed<AttributeSet>('getAttributes', () => inner.getAttributes(idOrSubject, scopes)),
    reassert: (idOrSubject) => timed<ReassertResult>('reassert', () => inner.reassert(idOrSubject)),
  };
}

@Global()
@Module({
  providers: [
    {
      provide: SDID_PROVIDER,
      inject: [AuditService, MetricsService],
      useFactory: (audit: AuditService, metrics: MetricsService): SdidProvider =>
        instrumentSdidProvider(
          createSdidProvider({
            strategy: loadConfig().SDID_STRATEGY,
            nidPepper: loadConfig().NID_PEPPER,
            onAudit: async (e) => {
              await audit.append({
                actor: { type: 'system' },
                action: e.action,
                subjectRef: e.subjectRef,
                sdidTxnRef: e.txnRef,
                result: e.result,
                context: e.context,
              });
            },
          }),
          metrics,
        ),
    },
    {
      provide: MATCH_ENGINE,
      useFactory: (): MatchEngine => createMatchEngine(),
    },
  ],
  exports: [SDID_PROVIDER, MATCH_ENGINE],
})
export class SdidModule {}
