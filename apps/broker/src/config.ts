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
  ATTESTATION_MODE: z.enum(['mock', 'strict']).default('mock'),
  // --- Signing-key custody (06 §3, 07 §5, T13, decision #5) --------------
  /**
   * Which custody boundary signs broker tokens.
   *
   * `postgres-dev` keeps the private JWK in the `signing_keys` table and signs
   * in-process — the only provider that holds key material here, and refused
   * outright in production (see the guard rail below and
   * `apps/broker/src/keys/postgres-dev.custody.ts`). `kms` and `hsm` are
   * declared seams awaiting decision #5, which residency (Q17) has narrowed to
   * a GoR-approved in-country KMS or an on-prem HSM.
   *
   * (`KEYSTORE_DIR` used to live here as a "reserved" knob that nothing read.
   * It is gone: the dev store is the DB table, and an unused key-path setting
   * next to a real custody selector is an invitation to misconfigure.)
   */
  KEY_CUSTODY: z.enum(['postgres-dev', 'kms', 'hsm']).default('postgres-dev'),
  /**
   * How often the per-kid signature tally is flushed to the audit trail as one
   * `key.usage_summary` row (T13 key-usage audit). NOT one row per token — at
   * national scale that would swamp an append-only chain whose every append
   * takes a global advisory lock (07 §4). Rotation and shutdown flush too.
   */
  KEY_USAGE_SUMMARY_INTERVAL_SECONDS: z.coerce.number().int().positive().default(300),
  /** In-country KMS API base URL. See apps/broker/src/keys/kms.custody.ts. */
  KMS_ENDPOINT: z.string().default(''),
  /**
   * Logical key group/ring/alias holding the broker's signing keys — a GROUP,
   * not one key id: JWKS overlap (06 §3) needs the retired keys too.
   */
  KMS_KEY_GROUP: z.string().default(''),
  /** KMS client credential (path or inline). Sign/GetPublicKey/List only. */
  KMS_CREDENTIALS: z.string().default(''),
  /** Absolute path to the vendor's PKCS#11 shared library. */
  HSM_PKCS11_LIBRARY: z.string().default(''),
  /** PKCS#11 slot id or token label. */
  HSM_SLOT: z.string().default(''),
  /** Label / CKA_ID PREFIX identifying the broker's signing keys. */
  HSM_KEY_LABEL: z.string().default(''),
  /** PKCS#11 token PIN. From the platform secret store, never an image file. */
  HSM_PIN: z.string().default(''),
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

  // --- Observability (09 §2 Phase 3) -------------------------------------
  /**
   * Serve `/metrics`. Off means the route answers 404, not "unprotected".
   */
  METRICS_ENABLED: envBool(true),
  /**
   * Bearer token for `/metrics`. Empty falls back to ADMIN_API_TOKEN, which
   * production refuses: a scrape job's credential is long-lived, widely
   * readable infra config, and must not double as the RP-onboarding admin
   * token (T12). See apps/broker/src/observability/metrics.guard.ts.
   */
  METRICS_TOKEN: z.string().default(''),
  /** `silent` disables the JSON logger entirely (used by the test suite). */
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error', 'silent']).default('info'),

  // --- Anomaly detection (06 §5) — DETECTION ONLY, never auto-ban --------
  ANOMALY_ENABLED: envBool(true),
  /**
   * Pepper for the source-address handle recorded on a detection. A separate
   * key from NID_PEPPER on purpose: they protect different things with
   * different lifetimes, and rotating this one must not orphan citizen rows.
   */
  ANOMALY_SOURCE_PEPPER: z.string().default('dev-only-anomaly-source-pepper-change-me'),
  /**
   * T14 enrolment probing: distinct pseudo-NIDs attempted from one source
   * within the window. 10/15 min — a genuine shared egress (district office,
   * carrier NAT) can exceed this, which is precisely why detection never
   * auto-bans; it is a human-review signal.
   */
  ANOMALY_ENROL_PROBE_DISTINCT_NIDS: z.coerce.number().int().positive().default(10),
  ANOMALY_ENROL_PROBE_WINDOW_SECONDS: z.coerce.number().int().positive().default(900),
  /** T2/T3 attestation rejections from one source: 10 / 15 min. */
  ANOMALY_ATTESTATION_REJECTION_THRESHOLD: z.coerce.number().int().positive().default(10),
  ANOMALY_ATTESTATION_REJECTION_WINDOW_SECONDS: z.coerce.number().int().positive().default(900),
  /**
   * T9 CIBA initiation flood per RP: 200 / 5 min. The hard limit is 60/min
   * (= 300 per 5 min), so this fires as a LEADING indicator, while the RP is
   * still being served rather than after it is already being throttled.
   */
  ANOMALY_CIBA_INITIATION_THRESHOLD: z.coerce.number().int().positive().default(200),
  ANOMALY_CIBA_INITIATION_WINDOW_SECONDS: z.coerce.number().int().positive().default(300),
  /** T1/T4 signature-failure burst against one binding: 5 / 15 min (= the lockout). */
  ANOMALY_SIGNATURE_FAILURE_THRESHOLD: z.coerce.number().int().positive().default(5),
  ANOMALY_SIGNATURE_FAILURE_WINDOW_SECONDS: z.coerce.number().int().positive().default(900),
  /**
   * T7 consent-fatigue / relay: citizen-flagged "I didn't request this"
   * denials against one RP. 3 / hour — deliberately low, because a citizen
   * actively reporting a prompt they did not expect is the highest-signal
   * input the system has.
   */
  ANOMALY_SUSPICIOUS_DENIAL_THRESHOLD: z.coerce.number().int().positive().default(3),
  ANOMALY_SUSPICIOUS_DENIAL_WINDOW_SECONDS: z.coerce.number().int().positive().default(3600),

  // --- Push (05 §5) — wake-only; no GoR credentials exist yet ------------
  /** Per-provider request timeout. Push must never hold an RP request open. */
  PUSH_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
  /** Firebase project id; empty leaves the FCM transport an unconfigured seam. */
  FCM_PROJECT_ID: z.string().default(''),
  /** Google service-account JSON (path or inline) with FCM enabled. */
  FCM_CREDENTIALS_JSON: z.string().default(''),
  APNS_TEAM_ID: z.string().default(''),
  APNS_KEY_ID: z.string().default(''),
  /** APNs auth key `.p8` (path or inline PEM). */
  APNS_PRIVATE_KEY_P8: z.string().default(''),
  /** APNs topic = the iOS app bundle id. */
  APNS_TOPIC: z.string().default(''),
  /** false targets api.sandbox.push.apple.com; production MUST be true. */
  APNS_PRODUCTION: envBool(false),
  /**
   * `alert` sends a content-free loc-key the app localises (05 §7) and is
   * delivered promptly; `background` is fully silent but iOS throttles it,
   * which can exceed the CIBA window. Default `alert`.
   */
  APNS_PUSH_TYPE: z.enum(['alert', 'background']).default('alert'),
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
      assertKeyCustodyConfigured(cached);
      assertObservabilityConfigured(cached);
      assertPushConfigured(cached);
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

/**
 * Production guard rails for signing-key custody (06 §3, 07 §5, T13,
 * decision #5), in the same spirit as the NID_PEPPER / ATTESTATION_MODE rails.
 *
 * `postgres-dev` keeps the token-signing private key as plaintext in the
 * database and imports it into this process. In production that is a
 * token-forgery key for the national identity service, sitting in every
 * backup and every DB dump — precisely what T13, 06 §3 and 07 §5 forbid. The
 * provider's own constructor refuses too (belt and braces for paths that never
 * reach this function), but failing at config load gives the operator the
 * message before anything else has started.
 *
 * The seams get the half-configured treatment as well: a KMS endpoint with no
 * credential is a deployment that believes it has custody and has none, and it
 * would fail on the first citizen's login rather than at boot.
 */
function assertKeyCustodyConfigured(config: BrokerConfig): void {
  if (config.KEY_CUSTODY === 'postgres-dev') {
    throw new Error(
      'Production refuses KEY_CUSTODY=postgres-dev: it stores the broker signing key in the ' +
        'database as plaintext and imports it into app memory, which SPEC 06 §3 (T13) and 07 §5 ' +
        'forbid. Spec open decision #5 requires a GoR-approved in-country KMS or an on-prem HSM ' +
        '(residency, Q17). Set KEY_CUSTODY=kms or KEY_CUSTODY=hsm and supply that provider\'s ' +
        'adapter — see docs/runbook.md §4.',
    );
  }
  if (config.KEY_CUSTODY === 'kms') {
    const missing = (
      [
        ['KMS_ENDPOINT', config.KMS_ENDPOINT],
        ['KMS_KEY_GROUP', config.KMS_KEY_GROUP],
        ['KMS_CREDENTIALS', config.KMS_CREDENTIALS],
      ] as const
    )
      .filter(([, value]) => value.trim() === '')
      .map(([name]) => name);
    if (missing.length > 0) {
      throw new Error(`KEY_CUSTODY=kms requires: ${missing.join(', ')}`);
    }
  }
  if (config.KEY_CUSTODY === 'hsm') {
    const missing = (
      [
        ['HSM_PKCS11_LIBRARY', config.HSM_PKCS11_LIBRARY],
        ['HSM_SLOT', config.HSM_SLOT],
        ['HSM_KEY_LABEL', config.HSM_KEY_LABEL],
        ['HSM_PIN', config.HSM_PIN],
      ] as const
    )
      .filter(([, value]) => value.trim() === '')
      .map(([name]) => name);
    if (missing.length > 0) {
      throw new Error(`KEY_CUSTODY=hsm requires: ${missing.join(', ')}`);
    }
  }
}

/**
 * Production guard rails for observability (09 §2 Phase 3).
 *
 * A scrape credential and the RP-onboarding admin credential must not be the
 * same string: the Prometheus job's token lives in monitoring config that a
 * much wider group can read, and if it also registers relying parties then
 * every monitoring operator holds a privilege escalation (T12). Also refuses
 * the dev anomaly pepper, which would make a source handle recomputable by
 * anyone who read the repository.
 */
function assertObservabilityConfigured(config: BrokerConfig): void {
  if (config.METRICS_ENABLED) {
    if (config.METRICS_TOKEN.trim() === '') {
      throw new Error(
        'Production requires a dedicated METRICS_TOKEN when METRICS_ENABLED=true ' +
          '(or set METRICS_ENABLED=false) — the scrape job must not hold ADMIN_API_TOKEN',
      );
    }
    if (config.METRICS_TOKEN === config.ADMIN_API_TOKEN) {
      throw new Error('METRICS_TOKEN must differ from ADMIN_API_TOKEN');
    }
  }
  if (config.ANOMALY_ENABLED && config.ANOMALY_SOURCE_PEPPER.startsWith('dev-only')) {
    throw new Error('Production requires a real ANOMALY_SOURCE_PEPPER');
  }
}

/**
 * Production guard rails for push (05 §5).
 *
 * Push is OPTIONAL — the app polls the backchannel, so an unconfigured
 * transport degrades wake latency and nothing else, and no GoR credentials
 * exist yet. A HALF-configured transport is not optional-shaped though: it is
 * a deployment that believes it has push and silently does not, so partial
 * configuration fails the boot. APNs in production must also target Apple's
 * production gateway, or every send goes to the sandbox and quietly succeeds
 * against nothing.
 */
function assertPushConfigured(config: BrokerConfig): void {
  const fcmFields = [config.FCM_PROJECT_ID, config.FCM_CREDENTIALS_JSON].map((v) => v.trim() !== '');
  if (fcmFields.some(Boolean) && !fcmFields.every(Boolean)) {
    throw new Error('FCM push is half-configured: set both FCM_PROJECT_ID and FCM_CREDENTIALS_JSON');
  }
  const apnsFields = [
    config.APNS_TEAM_ID,
    config.APNS_KEY_ID,
    config.APNS_PRIVATE_KEY_P8,
    config.APNS_TOPIC,
  ].map((v) => v.trim() !== '');
  if (apnsFields.some(Boolean)) {
    if (!apnsFields.every(Boolean)) {
      throw new Error(
        'APNs push is half-configured: set APNS_TEAM_ID, APNS_KEY_ID, APNS_PRIVATE_KEY_P8 and APNS_TOPIC',
      );
    }
    if (!config.APNS_PRODUCTION) {
      throw new Error('Production requires APNS_PRODUCTION=true (sandbox pushes reach no real device)');
    }
  }
}

/** Test-only escape hatch to re-read env. */
export function resetConfigForTest(): void {
  cached = null;
}
