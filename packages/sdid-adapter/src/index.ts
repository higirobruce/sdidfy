import type { SdidProvider, SdidStrategyName } from '@sdid/shared';
import { SdidConfigurationError } from './errors.js';
import { MockSdidStrategy, type MockSdidStrategyOptions } from './mock-strategy.js';
import {
  OidcEsignetStrategy,
  type OidcEsignetStrategyOptions,
} from './oidc-esignet-strategy.js';
import {
  ProprietaryRestStrategy,
  type ProprietaryRestStrategyOptions,
} from './proprietary-rest-strategy.js';
import { ResilientSdidProvider, type ResilienceOptions } from './resilience.js';
import { withAuditHook, type SdidAuditHookEvent } from './audit-hook.js';
import type { UpstreamGapReport } from './upstream.js';

export {
  SdidUnknownIdentityError,
  SdidUnavailableError,
  SdidTimeoutError,
  SdidCircuitOpenError,
  SdidMalformedResponseError,
  SdidConfigurationError,
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

// --- Real-strategy surface (Phase 3, spec 02 §1). Exported so a deployment
// --- can supply the A1/A2-dependent adapter functions, and so the contract
// --- suite can drive both strategies against a fake transport (09 §3).
export {
  createFetchTransport,
  joinUrl,
  parseJsonBody,
  throwForStatus,
  type SdidHttpRequest,
  type SdidHttpResponse,
  type SdidHttpTransport,
} from './http-transport.js';
export {
  filterAttributesByScope,
  type AttributesFetcher,
  type ReassertChecker,
  type ReferenceBiometricFetcher,
  type SubjectResolver,
  type UpstreamCallContext,
  type UpstreamCallOptions,
  type UpstreamGapReport,
  type UpstreamReassert,
  type UpstreamReferenceBiometric,
} from './upstream.js';
export {
  OidcEsignetStrategy,
  OIDC_GAPS,
  STANDARD_OIDC_CLAIM_NAMES,
  type OidcAttributeClaimNames,
  type OidcAttributesConfig,
  type OidcAttributesContext,
  type OidcDiscoveryDocument,
  type OidcEsignetStrategyOptions,
} from './oidc-esignet-strategy.js';
export {
  ClientCredentialsTokenSource,
  signClientAssertion,
  type OidcClientAuth,
} from './oidc-client-auth.js';
export {
  ProprietaryRestStrategy,
  PROPRIETARY_GAPS,
  type ProprietaryAuth,
  type ProprietaryRestStrategyOptions,
} from './proprietary-rest-strategy.js';

// NOTE: the vitest-based contract suite (runSdidProviderContractTests) is
// deliberately NOT re-exported here — this entry is imported by the broker at
// runtime, and vitest's CJS entry throws when require()d outside a test run.
// Test files import it from './contract-tests.js' directly.
export type { SdidProviderContractContext } from './contract-tests.js';

/** `nidPepper` is threaded in by the factory, so callers never set it twice. */
export type OidcStrategyConfig = Omit<OidcEsignetStrategyOptions, 'nidPepper'>;
export type ProprietaryStrategyConfig = Omit<ProprietaryRestStrategyOptions, 'nidPepper'>;

export interface CreateSdidProviderOptions {
  /** Feature-flagged strategy (02 §4): SDID_STRATEGY=mock|oidc|proprietary. */
  strategy: SdidStrategyName;
  /** Broker audit sink; invoked once per adapter call, success or failure. */
  onAudit?: (event: SdidAuditHookEvent) => Promise<void>;
  /** NID pepper for keyed pseudonymisation (Q8, 10) — never a raw NID in audit/DB. */
  nidPepper?: string;
  /** Mock-strategy knobs (latency/failure injection). Ignored for real strategies. */
  mock?: MockSdidStrategyOptions;
  /** OIDC/eSignet configuration. Required when strategy === 'oidc' (02 §1, A1). */
  oidc?: OidcStrategyConfig;
  /** Proprietary REST/SOAP configuration. Required when strategy === 'proprietary' (02 §1, A1). */
  proprietary?: ProprietaryStrategyConfig;
  /**
   * Fail closed at construction when a real strategy still has unfilled A1/A2
   * gaps (default true). Setting this to false lets a partially answered
   * integration run the methods that ARE configured — the unfilled ones still
   * throw SdidConfigurationError at call time, never wrong data. Use it only
   * for deliberate partial-cutover testing, never in production.
   */
  requireFullyConfigured?: boolean;
  /** Timeout/retry/circuit-breaker overrides; defaults per 02 §4. */
  resilience?: ResilienceOptions;
}

/** Fail-closed boot check: refuse to start a real strategy with open holes. */
function assertNoGaps(gaps: UpstreamGapReport[], strategy: SdidStrategyName): void {
  if (gaps.length === 0) return;
  throw new SdidConfigurationError(
    gaps.map((g) => g.optionPath).join(', '),
    [...new Set(gaps.map((g) => g.openQuestion))].join(' + '),
    `SDID_STRATEGY=${strategy} cannot serve ${gaps
      .map((g) => g.detail)
      .join('; ')} — supply the adapter function(s) or set requireFullyConfigured:false ` +
      'to run only the configured methods',
  );
}

/**
 * Adapter entry point (spec 02). Whatever the strategy, the broker receives a
 * resilience-wrapped, boundary-validated, audit-instrumented SdidProvider —
 * identical composition for mock and real, so cutover is a configuration
 * change. A real strategy NEVER bypasses resilience or audit (02 §4).
 */
export function createSdidProvider(opts: CreateSdidProviderOptions): SdidProvider {
  const pepper = opts.nidPepper ?? 'dev-only-nid-pepper-change-me';
  const requireFullyConfigured = opts.requireFullyConfigured ?? true;
  const compose = (strategy: SdidProvider, name: SdidStrategyName): SdidProvider =>
    withAuditHook(new ResilientSdidProvider(strategy, opts.resilience), opts.onAudit, name, pepper);

  switch (opts.strategy) {
    case 'mock': {
      const strategy = new MockSdidStrategy({ ...(opts.mock ?? {}), nidPepper: pepper });
      return compose(strategy, 'mock');
    }
    case 'oidc': {
      if (!opts.oidc) {
        throw new SdidConfigurationError(
          'oidc',
          'A1/A3/A4',
          'SDID_STRATEGY=oidc requires the `oidc` configuration block (issuer, clientId, ' +
            'clientAuth) plus the A1/A2-dependent adapter functions',
        );
      }
      const strategy = new OidcEsignetStrategy({ ...opts.oidc, nidPepper: pepper });
      if (requireFullyConfigured) assertNoGaps(strategy.describeGaps(), 'oidc');
      return compose(strategy, 'oidc');
    }
    case 'proprietary': {
      if (!opts.proprietary) {
        throw new SdidConfigurationError(
          'proprietary',
          'A1/A3/A4',
          'SDID_STRATEGY=proprietary requires the `proprietary` configuration block (baseUrl, ' +
            'auth) plus the A1/A2-dependent adapter functions',
        );
      }
      const strategy = new ProprietaryRestStrategy({ ...opts.proprietary, nidPepper: pepper });
      if (requireFullyConfigured) assertNoGaps(strategy.describeGaps(), 'proprietary');
      return compose(strategy, 'proprietary');
    }
  }
}
