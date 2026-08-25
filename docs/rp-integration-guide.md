# Relying-Party Integration Guide

How a GoR system (relying party, "RP") integrates with the SDID Auth Bridge. The broker speaks standard OIDC (spec 04): you never touch SDID, never see a biometric, and never see a national ID number. Every authentication is completed by a live citizen approving on their enrolled phone — there is no headless verification path (spec 00 non-goals).

All examples assume the broker at `http://localhost:3100` (dev default). Error responses are OAuth2-style JSON: `{"error": "<code>", "error_description": "..."}`.

## 1. Onboarding

Registration is admin-gated and audited (spec 04 §6). A bridge administrator registers your system:

```bash
curl -s http://localhost:3100/admin/rps \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "IFMIS",
    "authMethod": "secret",
    "allowedScopes": ["openid", "profile"],
    "maxAssurance": "AL2",
    "allowedFlows": ["ciba", "code"],
    "redirectUris": ["https://ifmis.example.gov.rw/callback"]
  }'
```

Response:

```json
{
  "rpId": "0191...",
  "clientId": "rp_a1b2c3d4e5f6",
  "clientSecret": "…"
}
```

You receive exactly three things:

- **`clientId`** — your OAuth2 client identifier.
- **`clientSecret`** — shown **exactly once**, at registration. The broker stores only a SHA-256 hash; it cannot be recovered later. Lose it and you re-register. Store it in your secret manager, never in code or config files.
- **`rpId`** — the broker-internal id, used in admin URLs (e.g. suspension, pairwise provisioning).

Your registration also fixes policy the broker enforces on every request: `allowedScopes` (scope requests outside this set are rejected with `invalid_scope`), `allowedFlows` (`ciba` and/or `code`), `maxAssurance` (the highest assurance you may demand), and `redirectUris` (exact-match allow-list for the code flow).

## 2. login_hint — pairwise subjects, and why you cannot correlate

The `login_hint` you send to identify a citizen is the **pairwise subject** the broker issued to *you* for that citizen — the same value that comes back as `sub` in your ID tokens. It is derived per-RP: `HMAC-SHA256(your_pairwise_salt, citizen_id)`, with a random 32-byte salt generated at your registration.

Consequences (spec 04 §4, a privacy design choice, not a config):

- The subject IFMIS holds for a citizen and the subject Irembo holds for the same citizen are unrelated strings. **Cross-agency correlation of citizens by subject is impossible** — no two RPs can join their user tables on `sub`.
- The hint is never a NID, never a phone number, never a biometric.
- You obtain subjects only through the broker: from the `sub` of previous ID tokens for that citizen, or — for pilot bootstrap — via the admin provisioning endpoint `POST /admin/rps/{rpId}/pairwise` with `{"pseudoNid": "..."}` (admin-gated; input is the pseudonymised NID, never a raw NID), which returns `{"subject": "..."}`.

## 3. CIBA — the decoupled flow (spec 04 §3)

CIBA is what makes this a bridge: you initiate, the citizen's phone finishes. Use it whenever there is no shared browser (call centre, kiosk, cross-device) or you want phone-only approval.

### 3.1 Initiate: POST /oidc/bc-authorize

Form-encoded, authenticated with `client_secret_basic` (`client_secret_post` also supported):

```bash
curl -s http://localhost:3100/oidc/bc-authorize \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "login_hint=$PAIRWISE_SUBJECT" \
  --data-urlencode "binding_message=Login to IFMIS · code 7Q42" \
  --data-urlencode "requested_al=AL2"
```

Fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `scope` | yes | Space-separated; must include `openid`; every scope must be in your `allowedScopes` |
| `login_hint` | yes | Your pairwise subject for the citizen (§2) |
| `binding_message` | no, strongly recommended | Short human-readable string (max 140 chars) shown on the citizen's phone — see §3.4 |
| `requested_al` | no (default `AL2`) | Minimum assurance level: `AL1`, `AL2`, or `AL3` (§8); must not exceed your `maxAssurance` |
| `requested_expiry` | no | Request lifetime in seconds (max 600; default 180) |

Success (HTTP 200):

```json
{ "auth_req_id": "…", "expires_in": 180, "interval": 2 }
```

Initiation errors: `invalid_client` (401 — bad credentials or suspended client), `unauthorized_client` (CIBA not in your `allowedFlows`), `invalid_scope`, `invalid_request` (`requested_al` above your maximum), `rate_limited` (429 — more than 60 initiations per minute per RP), and `unknown_user_id` (400). Note that `unknown_user_id` deliberately covers both "no such subject" and "citizen has no active device able to meet the requested assurance" — the broker never leaks device state to an RP.

### 3.2 The citizen approves

The broker wakes the citizen's phone (push is wake-only — no auth data rides in it). The app pulls the pending request over its authenticated backchannel, shows your RP name, the requested scopes in plain language, and your `binding_message`, and the citizen approves or denies with their biometric, which signs the decision with the device's hardware-backed key.

### 3.3 Poll: POST /oidc/token

Poll at the returned `interval` (seconds), same client authentication:

```bash
curl -s http://localhost:3100/oidc/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:openid:params:grant-type:ciba" \
  --data-urlencode "auth_req_id=$AUTH_REQ_ID"
```

While pending, the broker answers HTTP 400 with an error code. Handle each:

| `error` | Meaning | What to do |
|---------|---------|-----------|
| `authorization_pending` | Citizen has not decided yet | Keep polling at `interval`; do not tighten the loop |
| `access_denied` | Citizen denied the request | Stop. Show "sign-in was declined". Never auto-retry — re-prompting a citizen who said no is the consent-fatigue attack (T7) |
| `expired_token` | Request expired undecided | Stop polling this `auth_req_id`. Offer the user a fresh attempt (new `bc-authorize`) |
| `invalid_grant` | Unknown `auth_req_id`, or tokens already collected for it | Stop; treat as a bug in your integration (each `auth_req_id` is single-use) |

(`slow_down` is reserved in the error vocabulary; a conforming client should respond by adding a second to its interval, as the reference `RpClient` does.)

On approval (HTTP 200):

```json
{
  "access_token": "…",
  "id_token": "…",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "openid profile"
}
```

The approval **is** the consent event: the broker records a consent grant and an audit entry before releasing tokens (spec 04 §5).

### 3.4 binding_message UX (threat T7)

`binding_message` is your defence against consent-fatigue and relay attacks ("just approve the prompt"). The same string is shown on the citizen's phone and must be shown on **your** surface:

- Display the message — especially any short code in it — **prominently on the screen or channel where the citizen initiated** (web page, kiosk, or read out by the call-centre agent).
- Instruct the citizen to approve **only if the code on their phone matches**.
- Make the code per-transaction and short (e.g. `Login to IFMIS · code 7Q42`), within the 140-character limit.
- If a citizen reports a prompt they did not initiate, the app has a deny-and-report path; treat any such report against your client seriously.

## 4. Validating the ID token

Tokens are ES256-signed JWTs. Verify against the broker's JWKS — do not skip any check:

- **JWKS:** `GET /oidc/jwks` (also advertised as `jwks_uri` in `GET /.well-known/openid-configuration`). Keys rotate with overlap; always select by the token's `kid` and re-fetch on unknown `kid`.
- **`iss`** must equal the broker issuer from the discovery document.
- **`aud`** must equal your `clientId`.
- **`exp`** must be in the future (ID tokens live 300 s by default — validate promptly).
- **`sub`** is your pairwise subject for the citizen — this is the value to key your user records on and reuse as future `login_hint`.
- **`acr`** is the assurance level actually achieved (`AL1`/`AL2`/`AL3`) — check it meets what your transaction needs; it reflects the approving device's live binding, so treat it as authoritative over what you requested.
- **`amr`** is `["hwk","bio"]` — hardware key + biometric.
- **`auth_time`** is when the citizen actually approved.
- In the code flow, also check `nonce` matches the one you sent.

The reference implementation is `apps/test-rp/src/rp-client.ts` (`verifyIdToken`).

## 5. Userinfo

```bash
curl -s http://localhost:3100/oidc/userinfo -H "Authorization: Bearer $ACCESS_TOKEN"
```

Returns `sub` and `acr` always; with the `profile` scope also `name` and `dateOfBirth`; with `address` also `address`. Attributes are fetched from SDID on demand under the citizen's consent — the broker does not warehouse them (spec 07 §3). Expect:

- `403 access_denied` when the citizen has revoked consent for those scopes — a live access token is not enough; consent is checked on every call.
- `401 access_denied` for a missing/invalid/revoked token.
- `503 sdid_unavailable` when the attribute source is down — retry later; do not cache around it.

## 6. Introspection and revocation

Both are client-authenticated, form-encoded POSTs.

```bash
# Is this token still good?
curl -s http://localhost:3100/oidc/introspect \
  -u "$CLIENT_ID:$CLIENT_SECRET" --data-urlencode "token=$TOKEN"
# → {"active": true, "sub": "...", "scope": "...", "client_id": "...", "exp": ..., "acr": "...", "token_use": "access"}
#   or {"active": false}

# Done with it (e.g. logout)? Revoke it.
curl -s http://localhost:3100/oidc/revoke \
  -u "$CLIENT_ID:$CLIENT_SECRET" --data-urlencode "token=$TOKEN"
# → HTTP 200 always (RFC 7009), even for unknown tokens
```

Revocation denylists the token's `jti` until its natural expiry; introspection and userinfo both honour the denylist. You can only revoke tokens issued to your own `client_id`.

## 7. Authorization code + PKCE (browser flow)

Use when the citizen is at a browser on your site. v1 has no broker login session: you must pass the citizen's pairwise subject as `login_hint`, and the citizen still approves on their phone — the browser page just waits for that approval.

**Step 1 — redirect the browser** to:

```
GET /oidc/authorize
    ?response_type=code
    &client_id=rp_a1b2c3d4e5f6
    &redirect_uri=https://ifmis.example.gov.rw/callback   (must be registered, exact match)
    &scope=openid%20profile
    &state=<opaque CSRF value>
    &nonce=<random value, echoed in the ID token>
    &code_challenge=<base64url(SHA-256(code_verifier))>
    &code_challenge_method=S256
    &acr_values=AL2                                        (optional; AL1|AL2|AL3)
    &login_hint=<pairwise subject>                         (required in v1)
```

**Step 2 — the phone-approval page.** The broker renders a "Approve this sign-in on your phone" page and creates a pending transaction exactly like CIBA. The page polls `GET /oidc/authorize/poll?txn=...` every 2 s; when the citizen approves on their phone, the poll returns the redirect and the browser is sent to your `redirect_uri` with `code` and your `state`. (An unknown `login_hint` renders a generic "could not start this sign-in" page — nothing is leaked to the browser.)

**Step 3 — exchange the code** (codes are single-use and expire after 60 s):

```bash
curl -s http://localhost:3100/oidc/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=https://ifmis.example.gov.rw/callback" \
  --data-urlencode "code_verifier=$CODE_VERIFIER"
```

Any mismatch — wrong client, wrong `redirect_uri`, failed PKCE check, expired or reused code — is a single undifferentiated `invalid_grant`. Validate `state` yourself before exchanging, and `nonce` in the resulting ID token.

## 8. Assurance levels — choosing `requested_al`

From spec 03 §3, as implemented:

| Level | How a binding reaches it | When to require it |
|-------|--------------------------|--------------------|
| **AL1** | Device bound after a biometric match, but weaker attestation (no hardware-backed key attestation) | Low-risk informational services |
| **AL2** | Strong device/app attestation + hardware-backed key + PAD-verified biometric match at enrolment | Default for most services (and the broker's default when you omit `requested_al`) |
| **AL3** | AL2, plus the broker re-asserts the identity with SDID at approval time (step-up; also catches revoked/deceased identities) | High-value: financial, land, health records |

Guidance:

- Request the **lowest level that covers the transaction's risk**. AL3 triggers an SDID round-trip on every approval — reserve it for actions that warrant it.
- Your registration's `maxAssurance` caps what you may request; asking above it fails with `invalid_request`.
- If the citizen has no active device meeting the requested level, CIBA initiation fails with `unknown_user_id` (indistinguishable, by design, from an unknown citizen).
- Always read `acr` back from the ID token rather than assuming your requested level.

## Reference clients

- `apps/test-rp` — a complete RP client (`RpClient`) and CLI covering registration, CIBA initiation, polling with `authorization_pending`/`slow_down` handling, ID-token verification, userinfo, introspection and revocation.
- `e2e` — the ghost-login demo wiring RP + simulated device together end to end.
