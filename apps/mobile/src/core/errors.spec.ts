import { ERROR_CODES } from '@sdid/shared';
import { describe, expect, it } from 'vitest';
import { createTranslator, RESOURCES } from '../i18n/index.js';
import type { MessageKey } from '../i18n/types.js';
import {
  LOCAL_ERROR_CODES,
  MobileError,
  isErrorCode,
  messageKeyForCode,
  toMobileError,
} from './errors.js';

describe('error → message-key mapping (03 §7)', () => {
  it('maps every broker error code to a message key that exists in every locale', () => {
    for (const code of ERROR_CODES) {
      const key = messageKeyForCode(code);
      expect(key, code).toBe(`errors.${code}`);
      for (const locale of Object.keys(RESOURCES) as (keyof typeof RESOURCES)[]) {
        expect(RESOURCES[locale][key as MessageKey]).toBeTruthy();
      }
    }
  });

  it('maps every device-local error code too', () => {
    for (const code of LOCAL_ERROR_CODES) {
      expect(messageKeyForCode(code)).toBe(`errors.${code}`);
    }
  });

  it('renders a citizen-facing string for every code, in Kinyarwanda by default', () => {
    const t = createTranslator();
    for (const code of [...ERROR_CODES, ...LOCAL_ERROR_CODES]) {
      const text = t.t(messageKeyForCode(code));
      expect(text.length).toBeGreaterThan(5);
      // No English leaking into the default locale's error text.
      expect(text).not.toMatch(/\b(please|failed|error|invalid)\b/i);
    }
  });
});

describe('MobileError.fromBrokerBody', () => {
  it('takes the machine code and DISCARDS the server description', () => {
    const err = MobileError.fromBrokerBody(
      { error: 'enrolment_failed', error_description: 'match score 0.31 below threshold' },
      403,
    );
    expect(err.code).toBe('enrolment_failed');
    expect(err.source).toBe('protocol');
    expect(err.httpStatus).toBe(403);
    expect(err.messageKey).toBe('errors.enrolment_failed');
    // The server's prose must not survive anywhere on the error object.
    expect(JSON.stringify({ ...err, message: err.message, detail: err.detail })).not.toContain(
      'match score',
    );
  });

  it('fails closed on an unrecognised code', () => {
    const err = MobileError.fromBrokerBody({ error: 'some_new_code' }, 400);
    expect(err.code).toBe('unknown');
    expect(err.userRetryable).toBe(false);
    expect(err.detail).toBe('unmapped_code=some_new_code');
  });

  it('fails closed on a non-JSON / bodyless failure (e.g. an HTML gateway page)', () => {
    const err = MobileError.fromBrokerBody(undefined, 502);
    expect(err.code).toBe('unknown');
    expect(err.messageKey).toBe('errors.unknown');
  });
});

describe('retry and terminal classification', () => {
  it('does NOT offer a retry for spent single-use challenges (T4)', () => {
    // The nonce is consumed with GETDEL before verification: retrying the same
    // request can only fail again, so the flow must restart instead.
    expect(new MobileError('challenge_invalid', { source: 'protocol' }).userRetryable).toBe(false);
    expect(new MobileError('signature_invalid', { source: 'protocol' }).userRetryable).toBe(false);
  });

  it('does NOT offer a retry for an attestation refusal, but does for an outage', () => {
    expect(new MobileError('attestation_rejected', { source: 'protocol' }).userRetryable).toBe(
      false,
    );
    expect(new MobileError('attestation_unavailable', { source: 'protocol' }).userRetryable).toBe(
      true,
    );
  });

  it('marks a dead binding terminal so the app drops local state (06 §4)', () => {
    expect(new MobileError('binding_not_active', { source: 'protocol' }).terminalForBinding).toBe(
      true,
    );
    expect(new MobileError('binding_not_found', { source: 'protocol' }).terminalForBinding).toBe(
      true,
    );
    expect(new MobileError('access_denied', { source: 'protocol' }).terminalForBinding).toBe(false);
  });
});

describe('local errors', () => {
  it('classifies the source so the UI knows who must act', () => {
    expect(MobileError.local('network_timeout').source).toBe('transport');
    expect(MobileError.local('biometric_not_enrolled').source).toBe('device');
    expect(MobileError.local('unexpected_response').source).toBe('client');
  });

  it('toMobileError wraps anything thrown into one shape', () => {
    const wrapped = toMobileError(new TypeError('boom'));
    expect(wrapped).toBeInstanceOf(MobileError);
    expect(wrapped.code).toBe('unknown');
    const passthrough = MobileError.local('biometric_cancelled');
    expect(toMobileError(passthrough)).toBe(passthrough);
  });

  it('isErrorCode only accepts codes the shared enum declares', () => {
    expect(isErrorCode('rate_limited')).toBe(true);
    expect(isErrorCode('not_a_code')).toBe(false);
    expect(isErrorCode(42)).toBe(false);
  });
});
