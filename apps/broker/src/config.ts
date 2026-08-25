import { z } from 'zod';

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
    }
  }
  return cached;
}

/** Test-only escape hatch to re-read env. */
export function resetConfigForTest(): void {
  cached = null;
}
