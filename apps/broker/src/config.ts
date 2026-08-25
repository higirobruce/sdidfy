import { z } from 'zod';
import { DEFAULT_MAX_TOKEN_AGE_MS } from '@sdid/attestation';

/**
 * Env booleans: `z.coerce.boolean()` is a trap — it applies JS truthiness, so
 * the string "false" parses as true. Accept the usual spellings explicitly.
 */
const envBool = (defaultValue: boolean) =>
  z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase())))
    .default(defaultValue);

const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  BROKER_PORT: z.coerce.number().default(3100),
  BROKER_ISSUER: z.string().default('http://localhost:3100'),
  DATABASE_URL: z.string().default('postgresql://sdid:sdid_dev@localhost:5432/sdid_bridge'),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  SDID_STRATEGY: z.enum(['mock', 'oidc', 'proprietary']).default('mock'),
  NID_PEPPER: z.string().default('dev-only-nid-pepper-change-me'),
  KEYSTORE_DIR: z.string().default('./data/keys'),
  ATTESTATION_MODE: z.enum(['mock', 'strict']).default('mock'),
  // --- Strict-mode attestation (05 §4, 06 T2/T3/T4, decision #4) ---------
  /** Our Android app's package name. Anything else is `app_mismatch`. */
  ANDROID_PACKAGE_NAME: z.string().default(''),
  /**
   * Comma-separated base64 SHA-256 digests of the accepted app-signing
   * certificates. Empty is a configuration error in strict mode, never
   * "accept any" — see `androidCertificateDigests()`.
   */
  ANDROID_CERT_SHA256_DIGESTS: z.string().default(''),
  /**
   * Play Integrity service-account credentials (path or inline JSON blob) for
   * `playintegrity.googleapis.com/v1/{pkg}:decodeIntegrityToken`. GoR
   * credentials do not exist yet — the decoder is a declared seam that throws
   * (`apps/broker/src/trust/play-integrity.decoder.ts`).
   */
  PLAY_INTEGRITY_CREDENTIALS_JSON: z.string().default(''),
  /** Apple App ID `<teamId>.<bundleId>`. Anything else is `app_mismatch`. */
  IOS_APP_ID: z.string().default(''),
  /** false accepts Apple's development aaguid; production MUST be true. */
  IOS_ATTESTATION_PRODUCTION: envBool(false),
  /**
   * TTL of a minted attestation nonce. Must be <= the verifiers' token-age
   * window (DEFAULT_MAX_TOKEN_AGE_MS) — a nonce that outlives the freshness
   * check would widen the replay window it exists to close.
   */
  ATTESTATION_NONCE_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  ADMIN_API_TOKEN: z.string().default('dev-admin-token'),
  // Conservative token lifetimes (open decision #2 — start short, no refresh in v1).
  ID_TOKEN_TTL_SECONDS: z.coerce.number().default(300),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(600),
  SESSION_TTL_SECONDS: z.coerce.number().default(900),
  CHALLENGE_TTL_SECONDS: z.coerce.number().default(120),
  CIBA_REQUEST_TTL_SECONDS: z.coerce.number().default(180),
  CIBA_POLL_INTERVAL_SECONDS: z.coerce.number().default(2),
  AUTH_CODE_TTL_SECONDS: z.coerce.number().default(60),
  // Re-verification cadence (03 §6, decision #9): routine auth verifies a
  // signature only, so periodic SDID re-assertion is our ONLY signal for a
  // revoked/deceased/changed identity. A binding older than this since its
  // last SDID contact (enrolment or a prior reassert) is re-verified at its
  // next use, on top of the always-on AL3 step-up. Default ~90 days.
  REVERIFY_INTERVAL_SECONDS: z.coerce.number().default(90 * 24 * 60 * 60),
});

export type BrokerConfig = z.infer<typeof configSchema>;

/** Parsed, whitespace-trimmed Android signing-certificate digests. */
export function androidCertificateDigests(config: BrokerConfig): string[] {
  return config.ANDROID_CERT_SHA256_DIGESTS.split(',')
    .map((d) => d.trim())
    .filter((d) => d.length > 0);
}

let cached: BrokerConfig | null = null;

export function loadConfig(): BrokerConfig {
  if (!cached) {
    cached = configSchema.parse(process.env);
    if (cached.NODE_ENV === 'production') {
      // Guard rails: production must never run on dev defaults (T13, 08).
      if (cached.NID_PEPPER.startsWith('dev-only') || cached.ADMIN_API_TOKEN === 'dev-admin-token') {
        throw new Error('Production requires real NID_PEPPER and ADMIN_API_TOKEN (KMS-held)');
      }
      if (cached.ATTESTATION_MODE !== 'strict') {
        throw new Error('Production requires ATTESTATION_MODE=strict');
      }
      assertStrictAttestationConfigured(cached);
    }
    // Applies in every environment that runs strict: a nonce outliving the
    // verifier's freshness window is a replay window, not a nonce.
    if (cached.ATTESTATION_MODE === 'strict') {
      if (cached.ATTESTATION_NONCE_TTL_SECONDS * 1000 > DEFAULT_MAX_TOKEN_AGE_MS) {
        throw new Error(
          `ATTESTATION_NONCE_TTL_SECONDS must be <= ${DEFAULT_MAX_TOKEN_AGE_MS / 1000}s ` +
            "(the verifiers' maximum accepted token age)",
        );
      }
    }
  }
  return cached;
}

/**
 * Production guard rails for strict attestation, in the same spirit as the
 * NID_PEPPER / ADMIN_API_TOKEN checks: an app identifier or trust anchor left
 * empty does not "accept any", it makes the verdict meaningless — so refuse to
 * boot rather than attest against nothing (06 T2/T3, 08).
 */
function assertStrictAttestationConfigured(config: BrokerConfig): void {
  const missing: string[] = [];
  if (config.ANDROID_PACKAGE_NAME.trim() === '') missing.push('ANDROID_PACKAGE_NAME');
  if (androidCertificateDigests(config).length === 0) missing.push('ANDROID_CERT_SHA256_DIGESTS');
  if (config.PLAY_INTEGRITY_CREDENTIALS_JSON.trim() === '') missing.push('PLAY_INTEGRITY_CREDENTIALS_JSON');
  // Apple App ID is `<teamId>.<bundleId>` — a bare bundle id would silently
  // never match, so shape is checked, not just presence.
  if (!/^[A-Za-z0-9]+\.[A-Za-z0-9.-]+$/.test(config.IOS_APP_ID.trim())) missing.push('IOS_APP_ID (<teamId>.<bundleId>)');
  if (!config.IOS_ATTESTATION_PRODUCTION) missing.push('IOS_ATTESTATION_PRODUCTION=true');
  if (missing.length > 0) {
    throw new Error(
      `Production strict attestation requires real values for: ${missing.join(', ')}`,
    );
  }
}

/** Test-only escape hatch to re-read env. */
export function resetConfigForTest(): void {
  cached = null;
}
