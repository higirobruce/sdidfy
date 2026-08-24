// PLACEHOLDER — the real adapter (mock strategy, resilience wrapper, factory,
// audit hooks, contract tests) is implemented per spec 02. This stub keeps the
// workspace graph compiling; see src/ modules once implemented.
import type { AuditAction, SdidProvider, SdidStrategyName } from '@sdid/shared';

export interface SdidAuditHookEvent {
  action: AuditAction;
  subjectRef?: string;
  txnRef?: string;
  result: 'success' | 'failure';
  context?: Record<string, unknown>;
}

export interface CreateSdidProviderOptions {
  strategy: SdidStrategyName;
  onAudit?: (event: SdidAuditHookEvent) => Promise<void>;
}

export function createSdidProvider(_opts: CreateSdidProviderOptions): SdidProvider {
  throw new Error('sdid-adapter not yet implemented');
}
