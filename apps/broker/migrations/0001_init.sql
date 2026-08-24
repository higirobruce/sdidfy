-- SDID Auth Bridge — initial schema (spec 07)
-- Enums are text + CHECK for painless evolution. No biometric bytes anywhere (07 §1).

CREATE TABLE citizens (
  id uuid PRIMARY KEY,
  pseudo_nid text NOT NULL,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'deceased-per-sdid')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX citizens_pseudo_nid_idx ON citizens (pseudo_nid);

CREATE TABLE device_bindings (
  id uuid PRIMARY KEY,
  citizen_id uuid NOT NULL REFERENCES citizens (id),
  device_pubkey_jwk jsonb NOT NULL,
  attestation jsonb NOT NULL,
  assurance_level text NOT NULL CHECK (assurance_level IN ('AL1', 'AL2', 'AL3')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
  device_label text NOT NULL,
  enrolled_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  last_used_at timestamptz,
  last_reasserted_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text
);
CREATE INDEX device_bindings_citizen_idx ON device_bindings (citizen_id);

CREATE TABLE relying_parties (
  id uuid PRIMARY KEY,
  client_id text NOT NULL,
  name text NOT NULL,
  logo_uri text,
  auth_method text NOT NULL CHECK (auth_method IN ('secret', 'private_key_jwt', 'mtls')),
  client_secret_hash text,
  jwks jsonb,
  allowed_scopes text[] NOT NULL,
  max_assurance text NOT NULL CHECK (max_assurance IN ('AL1', 'AL2', 'AL3')),
  allowed_flows text[] NOT NULL,
  redirect_uris text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  pairwise_salt text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX relying_parties_client_id_idx ON relying_parties (client_id);

CREATE TABLE pairwise_subjects (
  citizen_id uuid NOT NULL REFERENCES citizens (id),
  rp_id uuid NOT NULL REFERENCES relying_parties (id),
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (citizen_id, rp_id)
);
CREATE UNIQUE INDEX pairwise_subjects_rp_subject_idx ON pairwise_subjects (rp_id, subject);

CREATE TABLE auth_transactions (
  id uuid PRIMARY KEY,
  auth_req_id text NOT NULL,
  citizen_id uuid NOT NULL REFERENCES citizens (id),
  rp_id uuid NOT NULL REFERENCES relying_parties (id),
  flow text NOT NULL CHECK (flow IN ('code', 'ciba')),
  scopes text[] NOT NULL,
  requested_al text NOT NULL CHECK (requested_al IN ('AL1', 'AL2', 'AL3')),
  binding_message text,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
  device_binding_id uuid,
  suspicious_report text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  resolved_at timestamptz
);
CREATE UNIQUE INDEX auth_transactions_auth_req_id_idx ON auth_transactions (auth_req_id);
CREATE INDEX auth_transactions_citizen_status_idx ON auth_transactions (citizen_id, status);

CREATE TABLE authorization_codes (
  code_hash text PRIMARY KEY,
  citizen_id uuid NOT NULL,
  rp_id uuid NOT NULL,
  scopes text[] NOT NULL,
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  nonce text,
  assurance text NOT NULL,
  auth_time timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);

CREATE TABLE consent_grants (
  id uuid PRIMARY KEY,
  citizen_id uuid NOT NULL REFERENCES citizens (id),
  rp_id uuid NOT NULL REFERENCES relying_parties (id),
  scopes text[] NOT NULL,
  source text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX consent_grants_citizen_rp_idx ON consent_grants (citizen_id, rp_id);

CREATE TABLE audit_events (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL,
  ts timestamptz NOT NULL DEFAULT now(),
  actor jsonb NOT NULL,
  action text NOT NULL,
  subject_ref text,
  rp_id uuid,
  device_binding_id uuid,
  assurance text,
  match_result jsonb,
  sdid_txn_ref text,
  result text NOT NULL,
  context jsonb,
  prev_hash text NOT NULL,
  hash text NOT NULL
);
CREATE INDEX audit_events_subject_idx ON audit_events (subject_ref);
CREATE INDEX audit_events_action_idx ON audit_events (action);

-- Append-only enforcement (07 §4): no UPDATE or DELETE, ever, for any role
-- that isn't explicitly bypassing (there is no bypass path in the app role).
CREATE OR REPLACE FUNCTION audit_events_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only (spec 07 §4)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_mutation();

-- DEV-ONLY key store (prod: KMS/HSM — open decision #5).
CREATE TABLE signing_keys (
  kid text PRIMARY KEY,
  alg text NOT NULL,
  public_jwk jsonb NOT NULL,
  private_jwk jsonb NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at timestamptz NOT NULL DEFAULT now()
);
