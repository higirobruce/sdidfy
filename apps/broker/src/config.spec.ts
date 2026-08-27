import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig, resetConfigForTest } from './config.js';

/**
 * Production guard rails for the Phase 3 additions (09 §2, 06 §8).
 *
 * The existing rails refuse to boot on a dev pepper or a dev admin token; the
 * ones exercised here extend the same posture to observability and push. Each
 * failure they catch is one that produces a broker which LOOKS healthy and is
 * quietly wrong — a scrape credential that also onboards relying parties, a
 * recomputable source handle, a push transport half-configured so every wake
 * silently goes nowhere. Guard rails exist for exactly that class.
 */

/** A production env that satisfies every pre-existing rail, so each test can break one thing. */
function productionEnv(): Record<string, string> {
  return {
    NODE_ENV: 'production',
    NID_PEPPER: 'real-pepper',
    ADMIN_API_TOKEN: 'real-admin-token',
    ATTESTATION_MODE: 'strict',
    ANDROID_PACKAGE_NAME: 'rw.gov.risa.sdid',
    ANDROID_CERT_SHA256_DIGESTS: 'abc123=',
    PLAY_INTEGRITY_CREDENTIALS_JSON: '{}',
    IOS_APP_ID: 'TEAMID123.rw.gov.risa.sdid',
    IOS_ATTESTATION_PRODUCTION: 'true',
    ANOMALY_SOURCE_PEPPER: 'real-anomaly-pepper',
    METRICS_TOKEN: 'real-metrics-token',
  };
}

describe('production configuration guard rails (Phase 3 additions)', () => {
  let saved: NodeJS.ProcessEnv;

  beforeEach(() => {
    saved = { ...process.env };
    resetConfigForTest();
  });

  afterEach(() => {
    process.env = saved;
    resetConfigForTest();
  });

  function applyEnv(overrides: Record<string, string>): void {
    for (const [k, v] of Object.entries({ ...productionEnv(), ...overrides })) process.env[k] = v;
  }

  it('accepts a fully-specified production config', () => {
    applyEnv({});
    expect(() => loadConfig()).not.toThrow();
  });

  it('refuses a scrape endpoint sharing the RP-onboarding admin token (T12)', () => {
    applyEnv({ METRICS_TOKEN: 'real-admin-token' });
    expect(() => loadConfig()).toThrow(/METRICS_TOKEN must differ/);
  });

  it('refuses metrics enabled with no dedicated token', () => {
    applyEnv({ METRICS_TOKEN: '' });
    expect(() => loadConfig()).toThrow(/dedicated METRICS_TOKEN/);
  });

  it('allows metrics to be turned off entirely instead', () => {
    applyEnv({ METRICS_TOKEN: '', METRICS_ENABLED: 'false' });
    expect(() => loadConfig()).not.toThrow();
  });

  it('refuses the dev anomaly pepper (a recomputable source handle is no handle)', () => {
    applyEnv({ ANOMALY_SOURCE_PEPPER: 'dev-only-anomaly-source-pepper-change-me' });
    expect(() => loadConfig()).toThrow(/ANOMALY_SOURCE_PEPPER/);
  });

  it('accepts push left entirely unconfigured — it is an optimisation, not a control', () => {
    applyEnv({ FCM_PROJECT_ID: '', FCM_CREDENTIALS_JSON: '', APNS_TEAM_ID: '' });
    expect(() => loadConfig()).not.toThrow();
  });

  it('refuses HALF-configured FCM (a deployment that thinks it has push and does not)', () => {
    applyEnv({ FCM_PROJECT_ID: 'gor-sdid', FCM_CREDENTIALS_JSON: '' });
    expect(() => loadConfig()).toThrow(/FCM push is half-configured/);
  });

  it('refuses half-configured APNs', () => {
    applyEnv({ APNS_TEAM_ID: 'TEAMID123', APNS_KEY_ID: 'KEYID12345' });
    expect(() => loadConfig()).toThrow(/APNs push is half-configured/);
  });

  it('refuses production APNs pointed at the sandbox gateway', () => {
    applyEnv({
      APNS_TEAM_ID: 'TEAMID123',
      APNS_KEY_ID: 'KEYID12345',
      // Placeholder, not a PEM header — APNS_PRIVATE_KEY_P8 is a plain
      // z.string() with no shape validation, and a literal key header in
      // source trips repo secret scanners.
      APNS_PRIVATE_KEY_P8: 'p8-key-material-placeholder',
      APNS_TOPIC: 'rw.gov.risa.sdid',
      APNS_PRODUCTION: 'false',
    });
    expect(() => loadConfig()).toThrow(/APNS_PRODUCTION=true/);
  });

  it('applies none of these rails outside production', () => {
    applyEnv({ NODE_ENV: 'development', METRICS_TOKEN: 'real-admin-token', FCM_PROJECT_ID: 'x' });
    expect(() => loadConfig()).not.toThrow();
  });
});
