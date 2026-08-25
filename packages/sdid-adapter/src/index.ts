import type { SdidProvider, SdidStrategyName } from '@sdid/shared';
import { MockSdidStrategy, type MockSdidStrategyOptions } from './mock-strategy.js';
import { ResilientSdidProvider, type ResilienceOptions } from './resilience.js';
import { withAuditHook, type SdidAuditHookEvent } from './audit-hook.js';

export {
  SdidUnknownIdentityError,
  SdidUnavailableError,
  SdidTimeoutError,
  SdidCircuitOpenError,
  SdidMalformedResponseError,
} from './errors.js';
export { MockSdidStrategy, type MockSdidStrategyOptions } from './mock-strategy.js';
export {
  ResilientSdidProvider,
  CircuitBreaker,
  type ResilienceOptions,
  type CircuitState,
} from './resilience.js';
export { withAuditHook, type SdidAuditHook, type SdidAuditHookEvent } from './audit-hook.js';
export { sdidSubjectForNid, auditSubjectRef, isSdidSubject } from './pseudonym.js';
// NOTE: the vitest-based contract suite (runSdidProviderContractTests) is
// deliberately NOT re-exported here — this entry is imported by the broker at
// runtime, and vitest's CJS entry throws when require()d outside a test run.
// Test files import it from './contract-tests.js' directly.
export type { SdidProviderContractContext } from './contract-tests.js';

export interface CreateSdidProviderOptions {
  /** Feature-flagged strategy (02 §4): SDID_STRATEGY=mock|oidc|proprietary. */
  strategy: SdidStrategyName;
  /** Broker audit sink; invoked once per adapter call, success or failure. */
  onAudit?: (event: SdidAuditHookEvent) => Promise<void>;
  /** NID pepper for keyed pseudonymisation (Q8, 10) — never a raw NID in audit/DB. */
  nidPepper?: string;
  /** Mock-strategy knobs (latency/failure injection). Ignored for real strategies. */
  mock?: MockSdidStrategyOptions;
  /** Timeout/retry/circuit-breaker overrides; defaults per 02 §4. */
  resilience?: ResilienceOptions;
}

/**
 * Adapter entry point (spec 02). Whatever the strategy, the broker receives a
 * resilience-wrapped, boundary-validated, audit-instrumented SdidProvider.
 */
export function createSdidProvider(opts: CreateSdidProviderOptions): SdidProvider {
  const pepper = opts.nidPepper ?? 'dev-only-nid-pepper-change-me';
  switch (opts.strategy) {
    case 'mock': {
      const strategy = new MockSdidStrategy({ ...(opts.mock ?? {}), nidPepper: pepper });
      const resilient = new ResilientSdidProvider(strategy, opts.resilience);
      return withAuditHook(resilient, opts.onAudit, 'mock', pepper);
    }
    case 'oidc':
    case 'proprietary':
      throw new Error('SDID strategy pending integration answers A1/A2 (docs/SPEC.md 02 §3)');
  }
}
