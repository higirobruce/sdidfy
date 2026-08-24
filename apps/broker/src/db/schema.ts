import {
  bigint,
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

/**
 * Data model per spec 07. Enums are text + CHECK constraints (see migration
 * SQL) for painless evolution. NO table ever stores biometric bytes (07 §1).
 */

export const citizens = pgTable(
  'citizens',
  {
    id: uuid('id').primaryKey(),
    /** Keyed hash of NID (Q8) — the only identity reference at rest. */
    pseudoNid: text('pseudo_nid').notNull(),
    /** SDID's opaque subject (from enrolment) — for attribute fetch + reassert; never the raw NID. */
    sdidSubject: text('sdid_subject'),
    status: text('status').notNull().default('active'), // active|suspended|deceased-per-sdid
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('citizens_pseudo_nid_idx').on(t.pseudoNid)],
);

export const deviceBindings = pgTable(
  'device_bindings',
  {
    id: uuid('id').primaryKey(),
    citizenId: uuid('citizen_id')
      .notNull()
      .references(() => citizens.id),
    /** Public key only (EC P-256 JWK). The private key never leaves the device (05 §3). */
    devicePubkeyJwk: jsonb('device_pubkey_jwk').notNull(),
    attestation: jsonb('attestation').notNull(),
    assuranceLevel: text('assurance_level').notNull(), // AL1|AL2|AL3
    status: text('status').notNull().default('pending'), // pending|active|revoked
    deviceLabel: text('device_label').notNull(),
    enrolledAt: timestamp('enrolled_at', { withTimezone: true }).notNull().defaultNow(),
    activatedAt: timestamp('activated_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    lastReassertedAt: timestamp('last_reasserted_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokeReason: text('revoke_reason'),
  },
  (t) => [index('device_bindings_citizen_idx').on(t.citizenId)],
);

export const relyingParties = pgTable(
  'relying_parties',
  {
    id: uuid('id').primaryKey(),
    clientId: text('client_id').notNull(),
    name: text('name').notNull(),
    logoUri: text('logo_uri'),
    authMethod: text('auth_method').notNull(), // secret|private_key_jwt|mtls
    /** SHA-256 hash of the client secret — never the secret itself. */
    clientSecretHash: text('client_secret_hash'),
    jwks: jsonb('jwks'),
    allowedScopes: text('allowed_scopes').array().notNull(),
    maxAssurance: text('max_assurance').notNull(), // AL1|AL2|AL3
    allowedFlows: text('allowed_flows').array().notNull(), // code|ciba — interactive only (00 non-goal)
    redirectUris: text('redirect_uris').array().notNull().default([]),
    status: text('status').notNull().default('active'), // active|suspended
    /** Hex-encoded salt deriving the per-RP pairwise subject (04 §4). */
    pairwiseSalt: text('pairwise_salt').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('relying_parties_client_id_idx').on(t.clientId)],
);

export const pairwiseSubjects = pgTable(
  'pairwise_subjects',
  {
    citizenId: uuid('citizen_id')
      .notNull()
      .references(() => citizens.id),
    rpId: uuid('rp_id')
      .notNull()
      .references(() => relyingParties.id),
    subject: text('subject').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.citizenId, t.rpId] }),
    uniqueIndex('pairwise_subjects_rp_subject_idx').on(t.rpId, t.subject),
  ],
);

export const authTransactions = pgTable(
  'auth_transactions',
  {
    id: uuid('id').primaryKey(),
    authReqId: text('auth_req_id').notNull(),
    citizenId: uuid('citizen_id')
      .notNull()
      .references(() => citizens.id),
    rpId: uuid('rp_id')
      .notNull()
      .references(() => relyingParties.id),
    flow: text('flow').notNull(), // code|ciba
    scopes: text('scopes').array().notNull(),
    requestedAl: text('requested_al').notNull(),
    bindingMessage: text('binding_message'),
    status: text('status').notNull().default('pending'), // pending|approved|denied|expired|consumed
    deviceBindingId: uuid('device_binding_id'),
    suspiciousReport: text('suspicious_report'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    resolvedAt: timestamp('resolved_at', { withTimezone: true }),
  },
  (t) => [
    uniqueIndex('auth_transactions_auth_req_id_idx').on(t.authReqId),
    index('auth_transactions_citizen_status_idx').on(t.citizenId, t.status),
  ],
);

export const authorizationCodes = pgTable('authorization_codes', {
  /** SHA-256 hash of the code — the code itself is never at rest. */
  codeHash: text('code_hash').primaryKey(),
  citizenId: uuid('citizen_id').notNull(),
  rpId: uuid('rp_id').notNull(),
  scopes: text('scopes').array().notNull(),
  redirectUri: text('redirect_uri').notNull(),
  codeChallenge: text('code_challenge').notNull(),
  nonce: text('nonce'),
  assurance: text('assurance').notNull(),
  authTime: timestamp('auth_time', { withTimezone: true }).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
});

export const consentGrants = pgTable(
  'consent_grants',
  {
    id: uuid('id').primaryKey(),
    citizenId: uuid('citizen_id')
      .notNull()
      .references(() => citizens.id),
    rpId: uuid('rp_id')
      .notNull()
      .references(() => relyingParties.id),
    scopes: text('scopes').array().notNull(),
    source: text('source').notNull(), // ciba-approval|code-flow|standing-grant
    grantedAt: timestamp('granted_at', { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [index('consent_grants_citizen_rp_idx').on(t.citizenId, t.rpId)],
);

/**
 * Append-only, tamper-evident audit (07 §4). INSERT-only is enforced by a DB
 * trigger (see migration). `seq` orders the hash chain; AuditService links
 * each row to the previous via prevHash/hash under an advisory lock.
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    seq: bigint('seq', { mode: 'number' }).generatedAlwaysAsIdentity().primaryKey(),
    id: uuid('id').notNull(),
    ts: timestamp('ts', { withTimezone: true }).notNull().defaultNow(),
    actor: jsonb('actor').notNull(),
    action: text('action').notNull(),
    subjectRef: text('subject_ref'),
    rpId: uuid('rp_id'),
    deviceBindingId: uuid('device_binding_id'),
    assurance: text('assurance'),
    matchResult: jsonb('match_result'),
    sdidTxnRef: text('sdid_txn_ref'),
    result: text('result').notNull(),
    context: jsonb('context'),
    prevHash: text('prev_hash').notNull(),
    hash: text('hash').notNull(),
  },
  (t) => [index('audit_events_subject_idx').on(t.subjectRef), index('audit_events_action_idx').on(t.action)],
);

/** DEV-ONLY key store (prod: KMS/HSM — decision #5). Private JWK never leaves in prod. */
export const signingKeys = pgTable('signing_keys', {
  kid: text('kid').primaryKey(),
  alg: text('alg').notNull(),
  publicJwk: jsonb('public_jwk').notNull(),
  privateJwk: jsonb('private_jwk').notNull(),
  status: text('status').notNull().default('active'), // active|retired
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
