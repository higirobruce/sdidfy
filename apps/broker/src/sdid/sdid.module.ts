import { Global, Module } from '@nestjs/common';
import type { MatchEngine, SdidProvider } from '@sdid/shared';
import { createSdidProvider } from '@sdid/sdid-adapter';
import { createMatchEngine } from '@sdid/match-engine';
import { loadConfig } from '../config.js';
import { AuditService } from '../audit/audit.service.js';

/**
 * Injection seam for the SDID adapter + match engine (02 §4).
 * The broker only ever sees the SdidProvider / MatchEngine contracts;
 * SDID_STRATEGY flips mock ↔ real without redeploying broker code.
 */
export const SDID_PROVIDER = Symbol('SDID_PROVIDER');
export const MATCH_ENGINE = Symbol('MATCH_ENGINE');

@Global()
@Module({
  providers: [
    {
      provide: SDID_PROVIDER,
      inject: [AuditService],
      useFactory: (audit: AuditService): SdidProvider =>
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
    },
    {
      provide: MATCH_ENGINE,
      useFactory: (): MatchEngine => createMatchEngine(),
    },
  ],
  exports: [SDID_PROVIDER, MATCH_ENGINE],
})
export class SdidModule {}
