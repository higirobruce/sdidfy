-- Wake-only push addresses for bound devices (spec 05 §5, 06 T6).
--
-- The token is the address FCM/APNs require to reach a device; it cannot be
-- hashed or pseudonymised the way an identity reference can (Q8). It is a
-- DEVICE handle, not a citizen identifier: it carries no identity, providers
-- rotate it freely, and the broker clears it on binding revocation (06 §4) and
-- whenever a provider reports it undeliverable.
--
-- Nothing about the pending authentication is ever sent to it — the payload is
-- a type and a version, and the app pulls the real request over the
-- authenticated backchannel (04 §3 step 5).

ALTER TABLE device_bindings
  ADD COLUMN push_platform text CHECK (push_platform IN ('fcm', 'apns')),
  ADD COLUMN push_token text,
  ADD COLUMN push_token_updated_at timestamptz;

-- Partial index: `wake()` only ever selects the active bindings that actually
-- hold an address, which today (and for most citizens at any time) is a small
-- fraction of the table.
CREATE INDEX device_bindings_push_target_idx
  ON device_bindings (citizen_id)
  WHERE status = 'active' AND push_token IS NOT NULL;
