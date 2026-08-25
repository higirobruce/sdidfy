import type {
  AttributeSet,
  AuditAction,
  BiometricModality,
  ReassertResult,
  ReferenceBiometricResult,
  SdidProvider,
  SdidStrategyName,
} from '@sdid/shared';
import { auditSubjectRef } from './pseudonym.js';

/**
 * Event handed to the broker's audit service for every adapter call (02 §4:
 * every call carries an audit record, txnRef-linked). subjectRef is always
 * pseudonymous; context NEVER contains biometric bytes, attribute values, or
 * raw NIDs.
 */
export interface SdidAuditHookEvent {
  action: AuditAction;
  subjectRef?: string;
  txnRef?: string;
  result: 'success' | 'failure';
  context?: Record<string, unknown>;
}

export type SdidAuditHook = (event: SdidAuditHookEvent) => Promise<void>;

/** Wraps a provider so every call (success or failure) emits one audit event. */
export function withAuditHook(
  inner: SdidProvider,
  onAudit: SdidAuditHook | undefined,
  strategy: SdidStrategyName,
): SdidProvider {
  if (!onAudit) return inner;

  const emit = async (event: SdidAuditHookEvent): Promise<void> => {
    try {
      await onAudit(event);
    } catch {
      // Audit transport errors must not alter the auth outcome; the audit
      // service owns its own durability/alerting.
    }
  };

  const instrument = async <T>(
    action: AuditAction,
    subjectRef: string,
    baseContext: Record<string, unknown>,
    call: () => Promise<T>,
    txnRefOf: (result: T) => string | undefined,
  ): Promise<T> => {
    const startedAt = Date.now();
    try {
      const result = await call();
      await emit({
        action,
        subjectRef,
        txnRef: txnRefOf(result),
        result: 'success',
        context: { ...baseContext, strategy, durationMs: Date.now() - startedAt },
      });
      return result;
    } catch (err) {
      await emit({
        action,
        subjectRef,
        result: 'failure',
        context: {
          ...baseContext,
          strategy,
          durationMs: Date.now() - startedAt,
          // Error class name only — adapter error messages are NID-free by
          // construction, but we still keep messages out of audit context.
          error: err instanceof Error ? err.name : 'unknown',
        },
      });
      throw err;
    }
  };

  return {
    getReferenceBiometric: (input: { nid: string; modality: BiometricModality }) =>
      instrument<ReferenceBiometricResult>(
        'sdid.reference_fetched',
        auditSubjectRef(input.nid),
        { modality: input.modality },
        () => inner.getReferenceBiometric(input),
        (r) => r.txnRef,
      ),
    getAttributes: (idOrSubject: string, scopes: string[]) =>
      instrument<AttributeSet>(
        'sdid.reference_fetched',
        auditSubjectRef(idOrSubject),
        { scopes: [...scopes] },
        () => inner.getAttributes(idOrSubject, scopes),
        () => undefined,
      ),
    reassert: (idOrSubject: string) =>
      instrument<ReassertResult>(
        'sdid.reassert',
        auditSubjectRef(idOrSubject),
        {},
        () => inner.reassert(idOrSubject),
        (r) => r.txnRef,
      ),
  };
}
