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
    // Production must name a real custody boundary (06 §3, T13, decision #5).
    // The dev store is refused outright, so the baseline production env picks
    // the KMS seam and supplies everything it declares.
    KEY_CUSTODY: 'kms',
    KMS_ENDPOINT: 'https://kms.gov.rw',
    KMS_KEY_GROUP: 'sdid-broker-signing',
    KMS_CREDENTIALS: '/run/secrets/kms-client',
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

  // --- signing-key custody (06 §3, T13, decision #5) -----------------------

  it('refuses the dev key store in production (a plaintext token-forgery key)', () => {
    applyEnv({ KEY_CUSTODY: 'postgres-dev' });
    // One call only: loadConfig() memoises the parsed config before running
    // the rails, so a second call returns it instead of throwing again.
    expect(() => loadConfig()).toThrow(/KEY_CUSTODY=postgres-dev[\s\S]*decision #5/);
  });

  it('refuses KEY_CUSTODY=kms with no endpoint, key group or credential', () => {
    applyEnv({ KMS_ENDPOINT: '', KMS_KEY_GROUP: '', KMS_CREDENTIALS: '' });
    expect(() => loadConfig()).toThrow(/KEY_CUSTODY=kms requires: KMS_ENDPOINT, KMS_KEY_GROUP, KMS_CREDENTIALS/);
  });

  it('refuses a half-configured KMS (custody it believes in and does not have)', () => {
    applyEnv({ KMS_CREDENTIALS: '' });
    expect(() => loadConfig()).toThrow(/KEY_CUSTODY=kms requires: KMS_CREDENTIALS/);
  });

  it('accepts a fully-specified HSM custody config', () => {
    applyEnv({
      KEY_CUSTODY: 'hsm',
      HSM_PKCS11_LIBRARY: '/usr/lib/softhsm/libsofthsm2.so',
      HSM_SLOT: '0',
      HSM_KEY_LABEL: 'sdid-broker-signing',
      HSM_PIN: 'pin-from-the-platform-secret-store',
    });
    expect(() => loadConfig()).not.toThrow();
  });

  it('refuses an HSM with no PIN — presence only, and never echoed back', () => {
    applyEnv({
      KEY_CUSTODY: 'hsm',
      HSM_PKCS11_LIBRARY: '/usr/lib/softhsm/libsofthsm2.so',
      HSM_SLOT: '0',
      HSM_KEY_LABEL: 'sdid-broker-signing',
      HSM_PIN: '',
    });
    expect(() => loadConfig()).toThrow(/KEY_CUSTODY=hsm requires: HSM_PIN/);
  });

  it('applies none of these rails outside production', () => {
    applyEnv({
      NODE_ENV: 'development',
      METRICS_TOKEN: 'real-admin-token',
      FCM_PROJECT_ID: 'x',
      KEY_CUSTODY: 'postgres-dev',
    });
    expect(() => loadConfig()).not.toThrow();
  });
});
