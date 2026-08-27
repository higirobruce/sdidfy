# SDID Authentication Bridge — Consolidated Spec Kit

> **Single-file bundle** of the full spec kit, for use as Claude Code context.
> Generated 24 Aug 2026 · reflects all decisions from the 17-question SDID pass.

## Contents
- 00 — Overview & Scope
- 01 — System Architecture
- 02 — SDID Adapter & Integration Contract
- 03 — Enrolment & Device-Binding Protocol
- 04 — Broker & Relying-Party Protocol (OIDC + CIBA)
- 05 — Mobile Authenticator App
- 06 — Security & Threat Model
- 07 — Data Model & Storage
- 08 — Data Protection & Compliance
- 09 — Build Sequence & Delivery Plan
- 10 — Decisions Log
- Appendix — SDID Integration Packet (questions for the SDID/NIDA team)

---

<!-- file: 00-overview.md -->

# SDID Authentication Bridge — Spec Kit

> **Working name:** *SDID Auth Bridge*. Rename before Phase 1 (see `10-open-decisions.md` #10).
> **Owner:** RISA Engineering Division · **Status:** Draft v0.1 · **Depends on:** NIDA / SDID team confirmation (see `02-sdid-adapter.md`).

## 1. What this is

A national-scale authentication service, fronted by a citizen mobile app, that lets Rwandans authenticate with SDID using biometrics **and** lets any other system delegate that authentication instead of integrating with SDID directly.

It is deliberately **three services, not one app**:

| # | Component | One-line role |
|---|-----------|---------------|
| A | **SDID Adapter** | The only code that speaks SDID's native protocol. Everything else depends on its interface, never on SDID. |
| B | **Identity Broker** ("the bridge") | Exposes standard **OIDC** to relying-party systems; orchestrates citizen auth and mints tokens. |
| C | **Mobile Authenticator** | The citizen's device: enrol once (server-side biometric), then approve logins with device biometric. |

The pattern for (B)+(C) is an **identity broker doing CIBA-style decoupled authentication** — a relying system initiates a login, the citizen's phone completes it out-of-band. Reference: OpenID Connect CIBA (Client-Initiated Backchannel Authentication).

## 2. The chosen biometric model — hybrid

Confirmed decision: **server-side enrolment, device-native thereafter.**

1. **Enrolment (once per device):** capture face + fingerprint with liveness, then **we 1:1-match it against NIDA's reference template** for the claimed NID (matching runs on our side — Q2 — in memory, never stored), and bind a **hardware-backed keypair** on the phone to the verified identity. The raw biometric is handled only this once, transiently.
2. **Every subsequent auth:** device biometric (Face/Touch) unlocks the private key; the phone signs a server challenge. No biometric transmitted; phishing-resistant; scales cheaply.

Why hybrid: strong identity proofing at enrolment without the cost, latency, and data-protection exposure of matching a face on every single login. See `03-enrollment-device-binding.md`.

## 3. Scope

**In scope (v1):**
- Citizen enrolment + device binding via SDID.
- Device-native biometric authentication.
- OIDC broker for relying parties (redirect flow + CIBA decoupled flow).
- One pilot relying party integrated end-to-end.
- Append-only audit trail; consent capture.

**Out of scope (v1), revisit later:**
- WhatsApp/USSD channels (web + app first — same reasoning as the citizen AI agents).
- Kinyarwanda NLP / conversational auth.
- Federation to non-SDID identity sources.
- Signing/e-signature use cases (auth only for now).
- Offline authentication (flagged, `10-open-decisions.md` #7).

## 4. Non-goals

- The bridge is **not** an identity source. It never becomes the authority on who a citizen is — SDID/NIDA remains authoritative. The bridge only proves *possession + biometric control of a device that was bound to a verified SDID identity*.
- The bridge is **not** a headless verification gateway. Every relying-party authentication requires a **live citizen approving on their enrolled phone** (interactive, Option 1 only). There is no "submit a biometric + NID, get a verdict" path for back-office / KYC checks — that would be a separate system with its own risk assessment.
- The bridge **processes** biometrics only transiently at enrolment and **never persists** them (Q2 → see `07-data-model.md` §1).

## 5. Stakeholders

| Role | Who | Interest |
|------|-----|----------|
| Product/eng owner | Bruce / RISA Eng | Delivery, architecture |
| Identity authority | NIDA / SDID team | Auth to SDID, biometric matching, authorization |
| Regulator | Data protection authority | Law Nº 058/2021 compliance, DPIA |
| Relying parties | GoR systems (Irembo, IFMIS, ministries…) | Simple OIDC integration |
| Delivery leads | Gervais (delivery), Pacifique (infra/security), Odilo (enablement/RP onboarding) | Build & run |

## 6. Document index

| Doc | Contents | SDID-dependent? |
|-----|----------|-----------------|
| `01-architecture.md` | Components, trust boundaries, core flows, topology, stack | partly |
| `02-sdid-adapter.md` | Adapter contract + **SDID integration questionnaire** | **yes — pending team** |
| `03-enrollment-device-binding.md` | Hybrid enrolment protocol, PAD, recovery, multi-device | partly |
| `04-broker-oidc-ciba.md` | OIDC endpoints, CIBA flow, tokens, RP onboarding | no |
| `05-mobile-app.md` | Authenticator app: UX, key storage, attestation, i18n | no |
| `06-security-threat-model.md` | Threats, mitigations, key management, assurance levels | no |
| `07-data-model.md` | Entities, append-only audit, no-raw-biometric rule | no |
| `08-data-protection-compliance.md` | Law Nº 058/2021, NIDA authorization, DPIA | no |
| `09-build-sequence.md` | Phased plan (mock SDID first), testing, team mapping | no |
| `10-open-decisions.md` | Decisions to resolve pre/during Phase 1 | mixed |

## 7. Status legend (used throughout)

- 🟢 **Decided** — locked unless new information.
- 🟡 **Provisional** — reasonable default, revisit.
- 🔴 **Blocked** — needs external input (usually SDID team or legal/DPO).

---

<!-- file: 01-architecture.md -->

# 01 — System Architecture

## 1. Component map & trust boundaries

```
                          ┌──────────────────────────────────────────────┐
   Relying-party systems  │                  YOUR TRUST BOUNDARY          │
   (Irembo, IFMIS, …)     │                                              │
        │  OIDC/CIBA       │   ┌────────────┐        ┌────────────────┐  │
        └──────────────────┼──▶│  Identity  │───────▶│  SDID Adapter  │──┼──▶ SDID / NIDA
                           │   │  Broker (B)│        │      (A)       │  │   (external
   Citizen phone           │   └─────┬──────┘        └────────────────┘  │   authority)
        │  signed          │         │ push (FCM/APNs, wake-only)        │
        │  challenge       │         ▼                                    │
   ┌────────────┐  attest  │   ┌────────────┐   ┌──────────┐  ┌───────┐  │
   │ Mobile (C) │──────────┼──▶│ Enrolment/ │   │ Postgres │  │ Redis │  │
   └────────────┘          │   │ Auth API   │   │ + audit  │  │+ Bull │  │
                           │   └────────────┘   └──────────┘  └───────┘  │
                           └──────────────────────────────────────────────┘
```

**Trust rules**
- Only the **SDID Adapter** holds SDID credentials and knows SDID's protocol. Swapping SDID's interface changes exactly one component.
- The **Broker** trusts a device only because that device holds a private key that was bound to a verified SDID identity at enrolment (see `03`).
- Relying parties trust **only the Broker** (standard OIDC). They never see SDID, never see biometrics. Every RP authentication is **interactive** — a live citizen approves on their phone; there is no headless verify path (`00` non-goal).
- The push channel (FCM/APNs) is **wake-only** — it carries no auth decision and is never trusted (see `06`).

## 2. Core flows

### 2.1 Enrolment (once per device) 🟢
1. Citizen installs app, starts enrolment.
2. App attests itself (Play Integrity / App Attest) and generates a hardware-backed keypair.
3. App captures biometric + liveness (PAD) and submits to Enrolment API.
4. **SDID Adapter** fetches NIDA's reference template for the claimed NID; the **Match Engine** performs the 1:1 comparison + PAD locally (sample vs reference, both discarded post-match — Q2).
5. On success, Broker stores a **DeviceBinding**: `{pseudo_nid, device_pubkey, attestation, assurance_level}`. No biometric persisted.
6. Device is now an authenticator for that citizen. Full protocol in `03`.

### 2.2 Direct login (first-party) 🟢
Citizen opens app → biometric unlock → app signs a fresh challenge → Broker verifies signature against the bound public key → session issued. No SDID round-trip needed for routine auth (identity was proven at enrolment); re-verification cadence is an open decision (`10` #9).

### 2.3 Decoupled auth — the bridge (CIBA) 🟢
1. Relying party calls Broker's **CIBA backchannel** endpoint: "authenticate citizen X for scope Y."
2. Broker creates a pending `AuthTransaction`, pushes a wake to the citizen's phone.
3. App pulls the pending request over the secure backchannel, shows *who is asking + what for*.
4. Citizen approves with biometric → app signs the transaction challenge.
5. Broker verifies signature, records consent + audit, mints an **ID/access token** for the relying party.
6. Relying party receives the token. It never touched SDID. Full protocol in `04`.

## 3. Deployment topology 🟡

- **Broker + Adapter + APIs:** containerised (Docker), horizontally scalable behind a load balancer. Stateless request handling; state in Postgres/Redis.
- **Postgres 16:** primary store + append-only audit. PgBouncer (transaction mode) in front — same pattern as the Consent Framework.
- **Redis + BullMQ:** CIBA pending-transaction state, push dispatch, rate-limit counters, short-lived challenge nonces.
- **Signing keys:** cloud KMS or HSM (open decision `10` #5) — token-signing and any adapter client keys never sit in app memory as plaintext.
- **Push:** FCM (Android) + APNs (iOS).
- **Observability:** structured logs, metrics, traces; audit stream is separate from ops logs.
- **Environments:** `dev` (mock SDID) → `staging` (mock SDID — no SDID sandbox exists, Q4) → `prod` (real SDID, controlled cohort). See `09`.
- **Residency:** all components, data, and audit run **in-country on GoR infrastructure** (Q17) — this bounds the KMS/HSM choice (`10` #5).

## 4. Technology stack 🟡

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Broker / APIs | **NestJS + TypeScript (strict)** | Protocol-heavy backend; matches Consent Framework; good OIDC/guards/interceptor model |
| OIDC engine | `node-oidc-provider` (or equivalent), extended for CIBA | Don't hand-roll OIDC; extend a vetted provider |
| DB | **PostgreSQL 16 + Prisma** | Team standard (consider Drizzle for the audit/ledger context, as with Ikigea) |
| Queue/cache | **Redis + BullMQ** | CIBA async, push, rate limits |
| Mobile | **React Native + Expo (dev client)** with native crypto/attestation modules | Team standard (Higa); needs bare/native for Secure Enclave + attestation |
| Crypto model | Hardware-backed keypair + biometric-gated signing (FIDO2/WebAuthn-style) | Phishing-resistant, no biometric transmitted |
| Biometric match + PAD | Matching SDK + ISO 30107 L2 liveness, in-memory only | We run the 1:1 match ourselves (Q2); sample + NIDA reference discarded post-match |
| Key custody | **GoR-approved KMS or on-prem HSM** (in-country) | Residency-constrained (Q17); decision `10` #5 |
| Monorepo | Turborepo (broker, adapter, mobile, shared types) | Team standard (Mailora) |

## 5. Why an adapter + broker (not "just call SDID")

- **Contain the unknown.** SDID's interface is unconfirmed (`02`). An adapter localises every SDID assumption to one module behind a stable internal interface, so the rest of the system is built and tested now against a **mock SDID**.
- **One integration, many consumers.** Relying parties integrate once with plain OIDC instead of each solving SDID + biometrics + device security independently.
- **Policy chokepoint.** Consent, audit, rate-limiting, assurance levels, and revocation all live in one place instead of being re-implemented per system.

---

<!-- file: 02-sdid-adapter.md -->

# 02 — SDID Adapter & Integration Contract

> The adapter is still the one place SDID lives. Since our Q&A, most of the biometric/identity decisions are settled **on our side** (we match, 1:1, pseudonymised NID, our own consent). What remains open is genuinely SDID-team territory — narrowed below. 🟡

## 1. The internal interface (stable — build against this now)

The Broker depends only on this TypeScript contract. Any SDID reality is adapted *to* it. Note the shift from earlier: because **we** run the match (Q2), the adapter's job at enrolment is to **fetch the reference template** for a claimed NID, not to ask SDID for a match verdict.

```ts
interface SdidProvider {
  // Enrolment-time: fetch the enrolled reference biometric for a claimed identity,
  // so WE can perform the 1:1 match locally (sample vs reference, both discarded post-match).
  getReferenceBiometric(input: {
    nid: string;
    modality: 'face' | 'fingerprint';
  }): Promise<{
    reference: BiometricReference;   // template/image; format TBD by SDID (A2)
    sdidSubject: string;             // maps to our pseudonymised-NID key
    txnRef: string;                  // SDID-side reference for audit
  }>;

  // Fetch minimal attributes we're authorised to receive.
  getAttributes(nid: string, scopes: string[]): Promise<AttributeSet>; // face-ref, name, DOB, address (Q9)

  // Periodic re-verification — also our mechanism for catching revoked/deceased IDs (Q12).
  reassert(nid: string): Promise<{ valid: boolean; assurance: AssuranceLevel }>;
}
```

> ⚠️ **Open dependency A2:** the exact mechanics of `getReferenceBiometric` — does NIDA return the reference per request, in what format, for both modalities — is the largest remaining unknown. The interface above holds regardless of the answer; only the adapter body changes.

**Two concrete strategies, one interface** (pick after A1):

- `OidcEsignetStrategy` — if SDID exposes a standard OIDC / eSignet-style interface.
- `ProprietaryRestStrategy` — if SDID is a bespoke REST/SOAP API. Handles request signing, its auth scheme, payload shaping, response parsing.

Both return the same shapes, so **Broker code is identical either way.**

## 2. Mock SDID (build enabler) 🟢 — now confirmed essential

There is **no SDID sandbox** (Q4) — production only. So `MockSdidStrategy` is not just convenient, it's the only way to build Phases 0–2:
- `getReferenceBiometric` returns seeded reference data for a set of test NIDs; configurable latency/failure injection.
- `getAttributes` returns seeded attributes; `reassert` returns configurable validity.
- Emits the same audit fields (incl. `txnRef`, match outcome) as the real adapter.

Real-SDID testing (Phase 3) is a **controlled prod cohort** — likely the team's own consented identities, pending NIDA test-identity provisioning (A7).

## 3. Remaining SDID/NIDA questions (see appendix)

Settled on our side, so **dropped** from the ask: who matches, matching type (1:1), modalities, PAD level, subject identifier, consent artefact, attribute set.

Still open — grouped for sending:

**For the SDID engineering team**
- **A1** — Interface: OIDC/eSignet or proprietary REST/SOAP? Which flows? Docs/OpenAPI?
- **A2** — Reference biometric: does NIDA return the reference template per request? Format (ISO 19794 / image)? Both face + fingerprint? *(critical)*
- **A3** — OAuth2/API-key details: token endpoint, scopes, issuance, **rotation policy + grace**.
- **A4** — Prod endpoints + hosts/ports to allow-list.
- **A5** — Verification-call quotas (our design only calls at enrolment + re-verify).
- **A6** — Uptime SLA + incident contacts.
- **A7** — Can NIDA provision **test identities in prod** (no sandbox)?

**To confirm in the data-sharing agreement (already in place)**
- **B1** — Mandated audit fields / reporting.
- **B2** — Residency/retention terms (we assume in-country / GoR infra).
- **B3** — Confirm no SDID-mandated consent artefact.

**Internal — infra (Pacifique)**
- **C1** — Outbound reachability to SDID endpoints (443 constraints).
- **C2** — Key custody under in-country residency: GoR-approved KMS vs on-prem HSM.

## 4. Adapter design rules 🟢

- Adapter is the **only** module importing SDID SDKs/credentials.
- All calls wrapped with: timeout, retry-with-jitter (idempotent only), circuit breaker, and an audit record (`txnRef` linked).
- **Reference templates and samples are held in memory only** and discarded immediately after the match (see `07` §1).
- Adapter output validated against `SdidProvider` before it reaches the Broker — a malformed SDID response never propagates.
- Feature-flag the strategy (`SDID_STRATEGY=mock|oidc|proprietary`) so we cut over without redeploying the Broker.

---

<!-- file: 03-enrollment-device-binding.md -->

# 03 — Enrolment & Device-Binding Protocol

> The crux of the hybrid model. Get this right and everything downstream is "verify a signature." Get it wrong and the whole trust chain is hollow. 🟢 for the shape; a few 🟡 parameters flagged.

## 1. Goal

Turn a phone into a trustworthy authenticator by binding a **hardware-backed keypair** to a **biometrically-verified SDID identity**, exactly once, then never handling the raw biometric again.

## 2. Enrolment sequence

```
App                         Broker/Enrolment API           SDID Adapter → SDID
 │  1. attest device ─────────▶ verify attestation           │
 │  2. gen keypair (secure HW)                                │
 │  3. capture biometric+liveness                             │
 │  4. POST {nid, sample, liveness, pubkey, attestation} ───▶ │
 │                              5. getReferenceBiometric(nid) ▶ fetch NIDA reference
 │                              6. ◀── {reference, subject}    │
 │                             6b. Match Engine (local): 1:1 sample vs reference
 │                                 + PAD; both discarded post-match
 │                              7. bind: store DeviceBinding   │
 │  8. ◀── {bindingId, assuranceLevel, activationChallenge}   │
 │  9. sign activationChallenge, return signature ──────────▶  │
 │                             10. verify sig vs pubkey → ACTIVE
```

**Step notes**
- **1 — Attestation.** Play Integrity (Android) / App Attest (iOS) proves a genuine, unmodified app on a non-rooted device. Also request **hardware key attestation** proving the keypair lives in Secure Enclave / StrongBox (see `06`). Reject emulators and rooted/jailbroken devices for enrolment (policy in `10` #4).
- **2 — Keypair.** Generated on-device, non-exportable, private key access **gated by biometric** (`setUserAuthenticationRequired`). Algorithm: EC P-256 (or Ed25519 where supported).
- **3 — Capture + PAD.** Client-side liveness/presentation-attack detection. Never store the sample locally beyond the request.
- **5–6b — Match (our side).** The adapter fetches NIDA's reference template (`02` A2); our **Match Engine** runs the 1:1 comparison + PAD (ISO 30107 L2) locally, then discards the sample and reference (Q2; `07` §1). Format/mechanics pending A2.
- **7 — Bind.** Persist `DeviceBinding` (see `07`): `pseudo_nid`, `device_pubkey`, `attestation_record`, `assurance_level`, `enrolled_at`, `status=PENDING`. **No biometric persisted.**
- **9–10 — Proof of possession.** Device signs a server challenge to prove it controls the private key before the binding goes `ACTIVE`. Prevents binding a public key the enrolling party doesn't actually control.

## 3. Assurance levels 🟡

Map proofing strength to an assurance level carried on the binding and later into tokens (so RPs can require a minimum):

| Level | How reached | Example RP use |
|-------|-------------|----------------|
| **AL1** | Device bound, weaker attestation, biometric match | Low-risk info services |
| **AL2** | Strong attestation + hardware key + PAD-verified biometric match | Default for most services |
| **AL3** | AL2 + periodic SDID re-verification and/or in-person step | High-value (financial, land, health records) |

Exact criteria and which RPs get which: `10` #9. Align AL definitions with SDID's own assurance output.

## 4. Multi-device policy 🟡

- Each device = one binding. A citizen may hold N active devices (default N = TBD, `10` #3).
- A new device enrols through the **same** biometric+SDID flow — never by cloning an existing device (keys are non-exportable, by design).
- Maintain a device list in-app: name, enrolled date, last used, **revoke**.

## 5. Recovery — lost / stolen / replaced device 🟢

Because private keys cannot be exported, device loss = **re-enrol on the new device**:
1. New device runs full enrolment (biometric re-verified against SDID). This is the recovery path — no "backup key" to steal.
2. Citizen (or an admin/support flow with its own authz) revokes the lost binding → `status=REVOKED`, immediately rejected at auth time (see revocation, `06`).
3. Optional cool-down / notification to other bound devices on new-device enrolment (anti-takeover; `10`).

This is a feature: there is no exportable secret, so there is nothing to phish or restore insecurely.

## 6. Re-verification cadence 🟡 — also our identity-change signal

Routine logins verify a **signature**, not a biometric-against-NIDA. NIDA does **not push** identity changes to us (Q12), so periodic re-verification is our *only* way to catch a revoked, deceased, or changed identity — which elevates its importance beyond assurance freshness. Re-assert with SDID:
- On a schedule (e.g. every 90 days), and
- On step-up for AL3 actions.

Cadence is an open decision (`10` #9) balancing security vs SDID call volume/cost (`02` A5).

## 7. Failure & abuse handling

- Biometric no-match → bounded retries, then lockout + guidance to in-person/support fallback (`10` #6).
- Attestation failure → refuse enrolment, log, surface a clear reason.
- Repeated failed enrolments per NID/device → rate-limit and flag (see `06` anti-automation).
- Never reveal *why* a match failed in a way that helps an attacker probe (generic user-facing error, detailed server-side audit).

---

<!-- file: 04-broker-oidc-ciba.md -->

# 04 — Broker & Relying-Party Protocol (OIDC + CIBA)

> How other systems consume the bridge. Standard OIDC so any GoR integrator already knows how to use it. 🟢 shape; 🟡 on lifetimes/claims.

## 1. Two flows, one broker

| Flow | When | Who initiates |
|------|------|---------------|
| **Authorization Code + PKCE** | RP has a browser session; user is at a screen | RP redirects user to Broker |
| **CIBA (backchannel)** | Decoupled — RP has no browser session, or wants phone-only approval (call centres, kiosks, cross-device). **A live citizen still approves on their phone** — never headless | RP calls Broker's backchannel endpoint |

CIBA is the flow that makes this a *bridge*: the RP starts auth, the citizen's phone finishes it. Reference: OpenID Connect CIBA Core.

**Both flows require a live citizen to approve on their enrolled phone.** There is no non-interactive / back-office verification path — that's a hard non-goal (`00`).

## 2. OIDC endpoints (exposed to RPs)

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | Discovery |
| `/authorize` | Auth Code + PKCE start |
| `/token` | Token exchange (both flows) |
| `/jwks` | Broker's public signing keys |
| `/userinfo` | Minimal authorised claims |
| `/bc-authorize` | **CIBA** backchannel auth request |
| `/backchannel-callback` *(or poll on `/token`)* | CIBA completion |
| `/revoke`, `/introspect` | Token lifecycle |

Build on a vetted OIDC provider (`node-oidc-provider` or equivalent) extended for CIBA — do **not** hand-roll OIDC.

## 3. CIBA decoupled flow (detailed)

```
RP                         Broker                         Citizen phone
 │ 1. POST /bc-authorize                                    │
 │    {login_hint, scope, binding_message, requested_al} ─▶ │
 │ 2. ◀── {auth_req_id, expires_in, interval}               │
 │                        3. resolve citizen → device(s)     │
 │                        4. create AuthTransaction, push ─▶ │ (wake-only)
 │                                                           │ 5. pull pending req
 │                                                           │    show RP + scope +
 │                                                           │    binding_message
 │ 6. poll POST /token (auth_req_id)                         │ 7. approve → biometric
 │    ◀── authorization_pending                              │    → sign challenge ─▶
 │                        8. verify sig, record consent+audit│
 │ 9. poll /token ◀── {id_token, access_token}              │
```

- **`login_hint`** identifies the citizen to the Broker (a pairwise identifier the RP holds; never a raw biometric). How RPs obtain it: onboarding, §6.
- **`binding_message`** — short human-readable string shown on BOTH the RP screen and the phone ("Login to IFMIS · code 7Q42") so the citizen confirms *this* request and not an attacker's overlapping one. Mitigates consent-fatigue/relay (see `06`).
- **`requested_al`** — RP demands a minimum assurance level (`03` §3); Broker refuses if the binding can't meet it.
- Delivery mode: **poll** (RP polls `/token`) for v1; ping/push callback later.

## 4. Tokens 🟡

- **ID token (JWT):** `iss`, `aud` (the RP), `sub` (**pairwise/sectoral** — a per-RP identifier, so RPs can't correlate citizens across services), `auth_time`, `acr` (assurance level), `amr` (`["hwk","bio"]`). Minimal PII by default; attributes only via `/userinfo` with consent and authorisation.
- **Access token:** short-lived, scope-bounded.
- **Signing:** RS256/ES256, keys in KMS/HSM (`10` #5), rotated via `/jwks` with overlap.
- **Lifetimes:** open decision (`10` #2) — start conservative (e.g. ID token minutes, refresh only where justified).

**Pairwise subjects matter here:** because this is one broker in front of many GoR services, a shared `sub` would let services silently link a citizen's activity across government. Pairwise/sectoral identifiers prevent that by default — a privacy design choice, not just a config.

## 5. Consent 🟢

- Every CIBA approval and every attribute release is an explicit, logged consent event (`07` audit).
- Where consent semantics get rich (granular scopes, revocable standing grants), reuse the **Consent Framework** rather than reinventing — the bridge can be a consumer of the consent registry, and the registry's audit log gives us the append-only trail for free. Integration depth: `10` #8.

## 6. Relying-party onboarding 🟡

- RPs are registered clients: `client_id`, credentials (prefer mTLS or signed-JWT client auth over shared secrets), allowed scopes, allowed flows, max assurance they may request, redirect URIs.
- Onboarding produces: client config, the pairwise `sub` mapping, scope grants, and a short integration guide (Odilo's enablement remit).
- Registration is admin-gated and audited — a rogue RP is a real threat (`06`).

## 7. Sessions

- Broker sessions (first-party app) are short-lived and bound to the device key.
- No ambient long-lived cookies for high-assurance actions — step-up re-auth (fresh signature) for AL3 (`03` §3).

---

<!-- file: 05-mobile-app.md -->

# 05 — Mobile Authenticator App

> The citizen's device is the authenticator. Its security properties are load-bearing for the whole system. 🟢 shape; 🟡 on stack specifics.

## 1. Responsibilities

1. Enrol (capture biometric + liveness, generate hardware keypair, bind — see `03`).
2. Store the private key in secure hardware, gated by device biometric.
3. Authenticate: unlock key with biometric → sign server challenges (direct login + CIBA approvals).
4. Attest the device/app on enrolment and periodically.
5. Show the citizen *who is asking and for what* before every approval.
6. Manage devices/consents; allow revocation.

## 2. Key screens / flows

- **Onboarding & enrolment:** language pick → NID entry → biometric capture (face + fingerprint) w/ liveness (ISO 30107 L2) → success/assurance shown. **Constraint:** phone fingerprint sensors can't supply a print for NIDA matching, so the fingerprint capture channel is a parked decision (`10` D1) — self-service face-match vs assisted enrolment with an external reader.
- **Home:** identity summary (name from authorised attributes), device status, recent auth activity.
- **Approval prompt (CIBA):** RP name + logo, requested scope in plain language, `binding_message` code, Approve/Deny — approval requires biometric. Time-boxed with countdown.
- **Direct login:** biometric → done.
- **Devices:** list bound devices, enrol new, **revoke**.
- **Consents/activity:** history of approvals and attribute releases; revoke standing grants.
- **Help / report:** "I didn't request this" → deny + flag path.

## 3. Cryptographic storage 🟢

| Platform | Secure element | API |
|----------|----------------|-----|
| iOS | Secure Enclave | Keychain + `SecKey`, `LAContext`, biometric-gated |
| Android | StrongBox / TEE Keystore | `KeyGenParameterSpec` w/ `setUserAuthenticationRequired`, StrongBox where present |

- Keys **non-exportable**; every signing op requires a fresh biometric unlock.
- Prefer **hardware key attestation** so the server can verify the key really lives in secure hardware (`06`).
- No secret is ever written to app storage, logs, or backups.

## 4. Device & app attestation 🟢

- **Android:** Play Integrity API (device/app/account integrity) + Key Attestation.
- **iOS:** App Attest + DeviceCheck.
- Minimum device-security bar (reject rooted/jailbroken/emulated for enrolment and high-AL auth) — policy in `10` #4.

## 5. Push 🟢

- FCM (Android) / APNs (iOS) used **only to wake the app**. The push payload carries no auth data and is never trusted; the app pulls the real pending request over the authenticated backchannel (`04` §3). This defeats push spoofing and payload tampering.

## 6. Offline behaviour 🟡

- Direct login and CIBA approval both need the Broker → generally online-only for v1.
- Possible later: pre-issued offline challenge tokens for constrained contexts. Decision `10` #7.

## 7. Internationalisation & accessibility 🟢

- Languages: **Kinyarwanda (default), English, French** — full localisation, not just labels (dates, errors, RTL-safe layout). Kinyarwanda-first, consistent with prior work (Higa).
- Accessibility: large-text support, screen-reader labels on all controls, high-contrast, biometric-alternative guidance for citizens who can't use a given modality (ties to fallback, `10` #6).
- Clear, non-technical language on every security prompt — most users are not security experts and must still make a safe choice.

## 8. Stack 🟡

- **React Native + Expo (dev client / bare)** — team standard, but deep native crypto + attestation exceed managed Expo, so bare workflow or custom native modules are required.
- Native modules: secure key generation/signing, attestation, biometric prompts.
- Shared TypeScript types with the Broker via the Turborepo monorepo.
- Minimal dependencies on the security path; audit any library that touches keys or capture.

## 9. Anti-abuse in the client

- Rate-limit approval prompts; collapse duplicates; show a clear "multiple requests pending" state to fight consent-fatigue attacks (`06`).
- Detect and warn on screen-recording/overlay during approval where the platform allows.

---

<!-- file: 06-security-threat-model.md -->

# 06 — Security & Threat Model

> National citizen biometric auth: the threat model is the product. This is a first pass to drive a formal review + external pentest before prod (`09`). 🟢

## 1. Trust assumptions

- Secure hardware (Secure Enclave / StrongBox / TEE) protects private keys from extraction.
- Platform attestation (Play Integrity / App Attest) reliably signals genuine app on a sound device.
- SDID/NIDA is authoritative for identity and returns a correct reference template (we perform the match — Q2).
- The Broker's signing keys are protected in KMS/HSM.

If any assumption weakens (e.g. attestation bypass on a platform), the affected assurance level degrades — mapped below.

## 2. Threat catalogue & mitigations

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | **Stolen/borrowed phone** | Private key gated by biometric on every signing op; device revocation; lockout on repeated biometric failure; step-up for high AL |
| T2 | **Rooted / jailbroken device** | Attestation + hardware key attestation; refuse enrolment/high-AL on failed attestation |
| T3 | **Emulator / cloned app** | App attestation; hardware-backed non-exportable keys can't be cloned |
| T4 | **Replay of a signed challenge** | Server-issued single-use nonces, short TTL, bound to `auth_req_id`; reject reuse |
| T5 | **MITM / TLS interception** | TLS 1.3, **certificate pinning** in app; mTLS or signed-JWT for RP↔Broker and Broker↔SDID |
| T6 | **Push spoofing / tampering** | Push is wake-only; real request pulled over authenticated backchannel; payload never trusted (`04`/`05`) |
| T7 | **Consent-fatigue / relay ("approve this")** | `binding_message` code shown on both surfaces; RP identity + scope in plain language; duplicate-collapse; time-box; deny-and-flag path |
| T8 | **Biometric spoof / PAD bypass at enrolment** | **We own PAD** (ISO/IEC 30107 **L2**) since we match (Q2); enrolment is the only biometric moment, limiting exposure; match + PAD run in memory, discarded after |
| T9 | **Malicious / compromised RP** | Admin-gated onboarding; per-RP scopes + max assurance; pairwise subjects; token audience binding; revocation; anomaly monitoring |
| T10 | **SIM swap** | Auth does not depend on SMS/phone-number possession; binding is to a hardware key, not a number |
| T11 | **Phishing** | Hardware-key signing is origin/audience-bound (FIDO2-style) — nothing phishable to hand over; no OTP to read out |
| T12 | **Insider / admin abuse** | Least privilege; admin actions MFA'd + append-only audited; no admin path to mint a citizen token or read raw biometrics (there are none stored) |
| T13 | **Broker signing-key theft** | KMS/HSM custody, no plaintext keys in app memory, rotation w/ `/jwks` overlap, key-usage audit |
| T14 | **Enrolment abuse / automated NID probing** | Rate-limit per NID/device/IP; anomaly detection; attestation gate; lockouts |
| T15 | **Lost-device takeover via recovery** | Recovery = full re-enrolment (biometric vs SDID) + notify existing devices + optional cool-down |
| T16 | **Data exfiltration** | No raw biometrics stored; PII minimised; pairwise subjects; encryption at rest; scoped DB access + RLS option (`07`) |
| T17 | **Reference-template exposure (from NIDA)** | Template fetched per request, held **in memory only**, never persisted or logged, zeroed post-match (`07` §1); in-country only; TLS/mTLS on the SDID path |
| T18 | **Matching-engine evasion / tampering** | Vetted matching SDK; PAD L2; score-band thresholds tuned + audited; match outcome logged (never the biometric); enrolment rate-limited (T14) |

## 3. Key management 🟡

- **Broker signing keys:** Cloud KMS **or** HSM (`10` #5). Never leave the boundary in plaintext. Scheduled rotation with JWKS overlap.
- **Adapter↔SDID credentials:** per SDID's scheme (mTLS/JWT/keys); rotation aligned to SDID policy (24h grace precedent from Consent Framework).
- **Device keys:** on-device secure hardware, non-exportable, biometric-gated. Server stores only public keys + attestation.

## 4. Revocation (must be fast) 🟢

- Device binding, RP client, and token revocation all effective quickly (target: seconds, cache-invalidated). Note the ~300ms eventual-consistency behaviour we accepted in the Consent Framework — decide the acceptable revocation propagation window here explicitly (`10`).
- Revocation reasons audited; revoked bindings rejected at signature-verify time.

## 5. Rate limiting & anti-automation 🟢

- Per-identity, per-device, per-IP, per-RP limits (Redis counters).
- Exponential backoff + lockout on repeated auth/enrolment failure.
- Bot/abuse monitoring on enrolment and CIBA initiation endpoints.

## 6. Assurance degradation

| Condition | Effect |
|-----------|--------|
| Attestation unavailable/weak on a platform | Cap that device at AL1; block AL2/AL3 actions |
| Binding older than re-verify window | Force SDID re-assertion before AL3 (`03` §6) |
| SDID signals identity change/revocation | Suspend binding; require re-enrolment |

## 7. Auditing (security view)

- Every enrolment, auth, consent, revocation, admin action → append-only audit (`07`).
- Include SDID `txnRef` for cross-system traceability and NIDA reporting obligations.
- Audit stream is separate from operational logs and tamper-evident.

## 8. Pre-prod security gate 🔴

Before any real-SDID production traffic: threat-model review sign-off, external penetration test, PAD/liveness evaluation, key-custody review, and DPIA (`08`).

---

<!-- file: 07-data-model.md -->

# 07 — Data Model & Storage

> Postgres 16. The governing principle: **process the least, persist even less, and never persist a biometric.** 🟢 Updated for the "we match ourselves" decision (Q2).

## 1. Cardinal rule — biometrics processed transiently, never persisted

Because we perform the 1:1 match ourselves (not SDID — Q2), the bridge **does handle biometric data at enrolment**. It does so only in memory, for the duration of a single match, and **never persists it**:

- The **captured sample** (face + fingerprint, with liveness) exists only in-request during enrolment.
- NIDA's **reference template** for the claimed NID is fetched, compared, and discarded in the *same* request — never written to disk, never cached.
- What survives the request is only a *binding + proof + verification result*: device public key, attestation, assurance level, and an audit record. No sample, no template.

This is the single most important data-protection control (see `08`). Note it is now an **active in-memory-only discipline on our matching path**, not a "we never see biometrics" claim — that distinction drives the DPIA.

## 2. Core entities

```
Citizen (reference only)
  id                uuid  (uuidv7)
  pseudo_nid        text  (keyed hash of NID)       -- internal stable identity ref (Q8)
  status            enum  active|suspended|deceased-per-sdid
  created_at, updated_at
  -- NO name/photo/biometric stored here; attributes fetched on demand w/ consent

DeviceBinding
  id                uuid
  citizen_id        uuid  -> Citizen
  device_pubkey     bytea
  attestation       jsonb  (platform, integrity verdict, key attestation)
  assurance_level   enum   AL1|AL2|AL3
  status            enum   pending|active|revoked
  device_label      text
  enrolled_at, last_used_at, revoked_at, revoke_reason

RelyingParty
  id                uuid
  client_id         text
  auth_method       enum   mtls|private_key_jwt|secret
  allowed_scopes    text[]
  max_assurance     enum
  allowed_flows     text[] (code|ciba)              -- interactive only; no headless verify (00 non-goal)
  redirect_uris     text[]
  status            enum   active|suspended
  pairwise_salt     bytea  -- derives per-RP subject

PairwiseSubject
  citizen_id + rp_id -> subject (deterministic, per-RP; prevents cross-service linkage)

AuthTransaction
  id                uuid
  citizen_id        uuid
  rp_id             uuid
  flow              enum   code|ciba
  scopes            text[]
  requested_al      enum
  binding_message   text
  challenge_nonce   bytea  (single-use)
  status            enum   pending|approved|denied|expired
  created_at, resolved_at
  -- short-lived; hot copy in Redis, durable record in PG

ConsentGrant
  id, citizen_id, rp_id, scopes, granted_at, revoked_at, source
  -- delegate to Consent Framework registry (decision #8 = resolved: reuse it)

AuditEvent  (append-only, see §4)
```

- **PKs: UUIDv7** (time-sortable), consistent with Ikigea.
- Consider **Drizzle** for the audit/transaction context (as with Ikigea's ledger) and Prisma elsewhere — or one ORM for simplicity (`10` #12).

## 3. What we deliberately do NOT store

- **Raw biometric samples or templates** — neither the captured sample nor NIDA's reference template; both discarded post-match (§1).
- **Attribute values** (name, DOB, address, face reference) at rest by default — fetched from SDID/NIDA per request under consent, cached only where a specific need + lawful basis justifies it.
- Anything that lets an attacker reconstruct identity from a DB dump beyond the **pseudonymised-NID** reference.

## 4. Append-only audit 🟢

- `AuditEvent` is **insert-only** (no update/delete; enforce via DB role privileges + trigger guard). Same shape/philosophy as the Consent Framework's audit log.
- Fields: `id (uuidv7)`, `ts`, `actor` (citizen/RP/admin/system), `action`, `subject_ref`, `rp_id`, `assurance`, `match_result`, `sdid_txn_ref`, `result`, `context jsonb`, `prev_hash`/`hash` (tamper-evident chain — recommended for national ID).
- Because we run the match, log the **match outcome** (pass/fail + score band, never the biometric) for every enrolment.
- Retained per regulatory requirement; queryable for NIDA reporting and citizen access requests (`08`).

## 5. Storage & access controls 🟢

- Encryption at rest for the DB; secrets/keys in KMS/HSM, not the DB. **All storage in-country / on GoR infrastructure** (Q17 — see `01`, `08`).
- **Row-Level Security** as an option for service isolation (Postgres RLS — pattern from Ikigea).
- PgBouncer (transaction mode) in front of Postgres — Consent Framework pattern.
- Least-privilege DB roles: the app role cannot delete audit rows; no role can read a raw biometric (none are stored).

## 6. Retention & lifecycle 🟡

| Data | Retention (default — confirm w/ DPO) |
|------|--------------------------------------|
| Captured sample + NIDA reference template | **Never persisted**; discarded in-request post-match |
| DeviceBinding | Life of binding + defined tail after revocation |
| AuthTransaction (durable record) | Short operational window, then reduced to audit summary |
| AuditEvent | Long, per legal/NIDA obligation |
| Cached attributes (if any) | Minimal TTL, consent-scoped |

Retention values are a legal/DPO decision (`08`, `10`).

---

<!-- file: 08-data-protection-compliance.md -->

# 08 — Data Protection & Regulatory Compliance

> ⚠️ **Frames obligations for the build; not legal advice.** Biometric processing of citizen data must be signed off by RISA's legal/DPO function and, per the SDID relationship, by NIDA. 🔴 on sign-offs. Updated for the "we match ourselves" decision, which *increases* the DPIA surface.

## 1. Why this is high-risk processing — and more so now

The system processes **biometric data of citizens** — a special/sensitive category under Rwanda's data-protection regime (Law Nº 058/2021). The **"we match ourselves" decision (Q2) raises the stakes**: the bridge now actively processes captured samples *and* receives NIDA's reference template at enrolment (in memory only, `07` §1). That is heavier processing than a design where SDID returns a match verdict, so the **DPIA is firmly a gating deliverable before production**.

## 2. How the architecture reduces exposure

| Principle | How the design meets it |
|-----------|-------------------------|
| **Data minimisation** | Samples + reference templates processed in memory only, never persisted (`07` §1); attributes fetched on demand, not warehoused |
| **Purpose limitation** | Auth only; **no headless verification path** (`00` non-goal); scopes/assurance bound per RP; pairwise subjects prevent cross-service profiling |
| **Storage limitation** | Retention schedule per data class (`07` §6), DPO-set |
| **Integrity/confidentiality** | Hardware-backed keys, encryption at rest, mTLS/pinning, append-only tamper-evident audit, **all data in-country** |
| **Accountability** | Full audit trail with SDID `txn_ref` and match outcome; consent events logged |
| **Transparency** | Plain-language prompts (who's asking, what for) at every approval |

## 3. Specific to "we match ourselves"

- **Biometric processing purpose + lawful basis** must explicitly cover *us* running a matching engine and receiving a reference template — document this in the DPIA, not just SDID's role.
- **In-memory-only discipline** (`07` §1) is a stated control the DPIA relies on — it must be verifiable (no logging of samples/templates, no swap-to-disk, memory zeroed post-match).
- **Matching engine + PAD** (ISO/IEC 30107 L2) are now our security responsibility (`06`).

## 4. Consent 🟢

- We use **our own consent artefact** (Q16) — no SDID-mandated form (confirm B3).
- Explicit, informed, per-transaction consent for CIBA approvals and attribute releases; logged (`07`).
- **Reuse the Consent Framework** (decision #8 resolved): registry + citizen dashboard + revocation + append-only audit, consistent with the rest of Rwanda DPI rather than a parallel silo.

## 5. Citizen rights (build must support)

- **Access:** produce a citizen's auth/consent history (audit query).
- **Rectification/erasure:** reconcile erasure of a binding vs retention of audit with the DPO (audit typically retained for legal reasons even when a binding is deleted).
- **Revoke device / consent:** self-service in-app.
- **Object/complain:** a clear path.

## 6. NIDA authorization & data-sharing 🟢 — in place

- The formal **authorization / data-sharing agreement with NIDA is already in place (Q13)** — this clears the heaviest long-lead production dependency.
- Confirm within that agreement: mandated **audit fields/reporting** (B1), **residency/retention** terms (B2).
- Meet any NIDA-mandated logging obligations.

## 7. Data residency 🟢 — in-country

- **All citizen data, audit, and any biometric reference received stays in-country / on GoR infrastructure (Q17).** This constrains key custody (`10` #5) toward a **GoR-approved KMS or on-prem HSM** — no foreign-region cloud KMS.

## 8. Breach readiness

- Breach detection, response runbook, and notification timelines per Law Nº 058/2021 and the NIDA agreement. Append-only audit supports forensic reconstruction.

## 9. Compliance checklist (pre-prod gate)

- [ ] **DPIA** completed and accepted — *now higher priority given we process biometrics* 🔴
- [ ] Lawful basis documented per purpose, **including our matching + reference-template handling** 🔴
- [x] NIDA authorization / data-sharing agreement signed ✅ (Q13)
- [ ] Retention schedule approved by DPO
- [ ] In-memory-only biometric discipline verified (no persistence/logging) 🔴
- [ ] Consent artefacts reviewed (our own; confirm no SDID form — B3)
- [ ] Citizen-rights request procedures in place
- [ ] Breach response runbook approved
- [x] Residency requirement defined: in-country / GoR infra (confirm terms — B2)
- [ ] External security assessment complete (`06` §8) 🔴

> Confirm exact statutory citations, thresholds, and current guidance with the DPO — this doc is not the legal source of truth.

---

<!-- file: 09-build-sequence.md -->

# 09 — Build Sequence & Delivery Plan

> Build the hard core against a mock first; wire the real, blocked dependency last. 🟢

## 1. Guiding sequencing rule

The riskiest thing is **not** the UI — it's the trust chain (device binding → signature auth → token issuance) and the **SDID integration (blocked)**. So: prove the trust chain against a **mock SDID** early, keep SDID behind the adapter, and integrate the real service only once the questionnaire (`02`) is answered.

## 2. Phases

### Phase 0 — Foundations & mock (unblocked, start now)
- Turborepo scaffold: `broker`, `adapter`, `mobile`, `packages/shared-types`.
- Define the `SdidProvider` interface (`02` §1) + `MockSdidStrategy`.
- Postgres schema (`07`) + append-only audit + migrations; PgBouncer.
- CI/CD, env/feature-flag plumbing (`SDID_STRATEGY`).
- **Exit:** mock verify returns deterministic results; audit writes; schema migrates cleanly.

### Phase 1 — Broker core (unblocked)
- Stand up OIDC provider; implement `/authorize`, `/token`, `/jwks`, `/userinfo`.
- Implement **CIBA** `/bc-authorize` + poll completion (`04`).
- Challenge/nonce issuance + signature verification against a public key.
- Token minting (pairwise subjects, `acr`/`amr`), signing via KMS/HSM.
- **Exit:** a test RP completes a CIBA login end-to-end against **mock SDID** and a simulated signing key.

### Phase 2 — Mobile authenticator + real trust chain (unblocked)
- Enrolment flow (`03`): attestation, hardware keypair, biometric capture (mock match via mock SDID), device binding, activation proof-of-possession.
- Direct login + CIBA approval UX; push (FCM/APNs) wake-only; pull pending over backchannel.
- Secure key storage + biometric-gated signing; i18n (rw/en/fr).
- **Exit:** real phone enrols against mock SDID, then approves a CIBA login from the test RP with a real hardware-backed signature.

### Phase 3 — Real SDID + pilot RP + hardening (unblocks when `02` answered)
- Implement `OidcEsignetStrategy` **or** `ProprietaryRestStrategy` per A1; wire **reference-template retrieval** (A2) and run our own 1:1 match + PAD (ISO 30107 L2) against it.
- Integrate **one pilot relying party** end-to-end.
- Hardening: attestation enforcement, rate limits, revocation propagation, key custody, monitoring/anomaly detection.
- **Security & compliance gates:** threat-model sign-off, external pentest, PAD (ISO 30107 L2) evaluation (`06` §8), **DPIA** (`08`). NIDA authorization already in place (Q13).
- **Exit:** pilot RP authenticates real citizens via real SDID in a controlled cohort.

### Phase 4 — Rollout
- Onboard additional RPs; scale test; observability maturation; incident runbooks; assurance-level tuning.

## 3. Testing strategy 🟢

- **Contract tests** against the `SdidProvider` interface — mock and real strategies must pass the same suite, so cutover is low-risk.
- **Mock SDID** with latency + failure injection for resilience testing (timeouts, circuit breaker).
- **Crypto/e2e:** enrol→sign→verify→token on real devices (iOS + Android, incl. StrongBox vs TEE).
- **Security:** SAST/dependency scanning in CI; external pentest before prod; attestation-bypass and replay test cases from `06`.
- **PAD/liveness:** evaluate our ISO/IEC 30107 **L2** matching path against spoofing (our responsibility now — Q2).
- **Load:** CIBA initiation + signature verify throughput; SDID call-rate within quota.

## 4. Team mapping 🟡 (11 builders, three leads)

| Lead | Area | Owns |
|------|------|------|
| **Gervais** (delivery) | Broker + mobile app feature delivery | Phases 1–2 build, pilot integration |
| **Pacifique** (infra/support reduction) | Infra, security hardening, key custody, observability | Topology, KMS/HSM, rate limits, pentest coordination, revocation |
| **Odilo** (enablement) | RP onboarding + docs + adoption | Onboarding flow, integration guides, RP self-service, dev-experience |

Cross-cutting: adapter + SDID liaison; DPO/legal liaison for `08` gates.

## 5. Critical-path dependencies

1. 🔴 **SDID questionnaire answers** (`02` A1–A7) — gates Phase 3, so send *now*, in parallel with Phase 0–2. Reference-template mechanics (A2) is the critical one.
2. ✅ **NIDA authorization / data-sharing agreement** — already in place (Q13); confirm audit/residency terms within it (B1/B2).
3. 🔴 **DPIA** (`08`) — gates prod; *higher priority* now we process biometrics ourselves.
4. 🔴 **External security assessment** (`06` §8) — gates prod.
5. 🟡 Key-custody decision (GoR KMS vs HSM, in-country) — needed by Phase 1 signing.

## 6. Suggested first milestone

"**Ghost login**": a test RP completes a full CIBA login of a real phone against mock SDID, end-to-end, with a genuine hardware-backed signature and a minted token — no real SDID, no UI polish. That single demo proves the entire trust chain and de-risks everything after it.

---

<!-- file: 10-open-decisions.md -->

# 10 — Decisions Log

> Updated after the 17-question SDID pass. **Decided** items are locked; **open** items still need team/infra/DPO input.

## Decided 🟢

| # | Decision | Outcome |
|---|----------|---------|
| — | **Bridge model** | Interactive identity broker only (CIBA + auth-code). **No headless verification path** — hard non-goal (`00`) |
| — | **Who matches** | We match ourselves (1:1), in memory, never persisted (Q2 → `07`/`08`) |
| — | **Matching type** | 1:1 verify against claimed NID (Q6) |
| — | **Modalities** | Face + fingerprint (Q5) |
| — | **Liveness/PAD** | ISO/IEC 30107 Level 2, our responsibility (Q7) |
| — | **Subject identifier** | Pseudonymised NID (keyed hash) + pairwise per RP (Q8) |
| — | **Attributes** | Face reference, name, DOB, address; fetched on demand (Q9) |
| — | **Auth to SDID** | OAuth2 / API keys (Q3; detail A3) |
| — | **Identity-change detection** | Poll / periodic re-verification (Q12) |
| — | **Sandbox** | None → mock-first mandatory; prod-cohort testing (Q4) |
| — | **NIDA authorization** | Already in place (Q13) |
| 8 | **Consent Framework integration** | **Reuse it fully** — our own consent artefact, registry + dashboard + audit (Q16) |
| — | **Data residency** | In-country / GoR infrastructure (Q17) |
| 10 | **Naming / branding** | **RwandaPass** — citizen-facing, distinct from the internal `SDID` broker name; wired into `common.appName` (`en`/`fr`/`rw`) |

## Open — still to resolve

| # | Decision | Options | Recommendation | Owner | Needed by |
|---|----------|---------|----------------|-------|-----------|
| 1 | 🔴 **SDID interface type** | OIDC/eSignet · proprietary REST/SOAP | Per `02` A1 — don't guess | SDID team | Phase 3 |
| — | 🔴 **Reference-template mechanics** | per-request fetch · other; format; both modalities | Per `02` A2 (critical) | SDID team | Phase 3 |
| — | 🟡 **Fingerprint capture channel** | assisted enrol + external reader · face-match self-service, fingerprint = device unlock | Revisit (parked, D1) | Bruce | Phase 2 |
| 2 | **Token & session lifetimes** | short-only · short + refresh · sliding | Conservative; AL3 needs fresh signature | Gervais | Phase 1 |
| 3 | **Multi-device policy** | 1 · N capped · unlimited | N capped (3–5), each via full biometric flow | Bruce + Gervais | Phase 2 |
| 4 | **Device-security bar / attestation** | strict · tiered by AL | Tiered; block root/emulator for enrol + AL2/AL3; Play Integrity + App Attest | Pacifique | Phase 2 |
| 5 | **Signing-key custody** | GoR-approved KMS · on-prem HSM | **Narrowed by in-country residency** — no foreign cloud KMS. HSM if mandated, else GoR KMS | Pacifique | Phase 1 |
| 6 | **Fallback when biometric/device unavailable** | in-person re-enrol · assisted desk · OTP-assisted | In-person / assisted-desk; avoid SMS-OTP as primary (SIM-swap). Accessible path for citizens who can't use a modality | Bruce + DPO | Phase 2–3 |
| 7 | **Offline authentication (v1?)** | no · pre-issued offline challenges | No for v1 | Bruce | Phase 2 |
| 9 | **Re-verification cadence** | fixed · periodic + AL3 step-up | **Elevated** — also our only revoked/deceased signal (Q12). ~90d + AL3 step-up, balanced vs SDID call cost (A5) | Bruce + SDID team | Phase 1 (defs), Phase 3 (tune) |
| 11 | **Revocation propagation window** | seconds · ~300ms eventual (Consent Framework precedent) | Lean aggressive for device/token revocation on national ID | Pacifique | Phase 3 |
| 12 | **ORM split** | one everywhere · Drizzle for audit/txn + Prisma elsewhere | Match Ikigea, or unify for simplicity | Gervais | Phase 0 |

## Non-negotiables

- Biometric samples + reference templates processed **in memory only, never persisted** (`07` §1).
- Private keys non-exportable, biometric-gated, in secure hardware (`05` §3).
- Pairwise/sectoral subjects for RPs (`04` §4).
- Append-only, tamper-evident audit (`07` §4).
- **No headless verification path** — interactive citizen approval always required (`00`).
- All citizen data in-country / on GoR infrastructure (Q17).
- DPIA + external security assessment before production (`08`).
- SDID reachable through the adapter only (`02` §4).

---

<!-- file: sdid-integration-packet.md (appendix) -->

# SDID Integration — Open Questions to Confirm

> **From:** RISA Engineering Division · **Date:** 24 Aug 2026
> **Context:** We're building a citizen biometric authentication bridge on SDID — a mobile authenticator plus an OIDC broker that lets other GoR systems delegate authentication instead of integrating with SDID directly.

## Already settled on our side (context)

- We **perform the biometric matching** ourselves (1:1, verifying against the claimed NID).
- Modalities: **face + fingerprint** (fingerprint capture channel still a design decision our side).
- Liveness / presentation-attack target: **ISO/IEC 30107 Level 2**.
- We bind each device to a **pseudonymised NID**, with pairwise identifiers per relying party (no cross-service correlation).
- Consent: we use **our own consent artefact** (please confirm SDID does not mandate its own — item B3).
- **NIDA authorization / data-sharing agreement: already in place.**

## A. For the SDID engineering team

**A1 — Interface & docs.** Does SDID expose a standard **OIDC / eSignet** interface or a **proprietary REST/SOAP** API? If OIDC, which flows (auth code, CIBA, wallet)? Is there API documentation / an OpenAPI spec?

**A2 — Reference biometric (critical).** Since we perform the matching, does NIDA **return the enrolled reference template** for a claimed NID on each verification request? In what **format** (e.g. ISO/IEC 19794 template, JPEG2000 image)? For **both face and fingerprint**?

**A3 — Client auth details.** Confirm the **OAuth2 client-credentials / API-key** setup: token endpoint, scopes, credential issuance, and the **key/cert rotation policy + grace period**.

**A4 — Endpoints & network.** Production endpoint hosts and the **hosts/ports** we must allow-list for outbound access.

**A5 — Rate limits.** Verification-call **quotas / throughput limits**.

**A6 — SLA & incidents.** **Uptime SLA** and incident / escalation contacts.

**A7 — Test identities.** There is **no sandbox** — can NIDA **provision test identities in production** that we can safely verify against for controlled end-to-end testing?

## B. To confirm in the existing data-sharing agreement

**B1 — Audit obligations.** Any **audit fields or reporting** NIDA requires us to log and be able to produce on request.

**B2 — Residency & retention.** Confirm residency/retention terms (we are assuming **in-country / GoR infrastructure**).

**B3 — Consent.** Confirm SDID does **not** require its own per-verification consent artefact.

## C. Internal — RISA infra (Pacifique)

**C1 — Outbound reachability.** Confirm hosting tiers can reach SDID's endpoints.

**C2 — Key custody.** Given the in-country residency requirement, decide **GoR-approved KMS vs on-prem HSM** for token-signing and SDID credentials.

## D. Parked design decision — RISA

**D1 — Fingerprint capture channel.** Phone fingerprint sensors can't provide a print for 1:1 matching against NIDA. Decide between:
- **Assisted enrolment** at a point with an external fingerprint reader, or
- **Face-match self-service** on the citizen's own phone, with fingerprint used only as a device-native unlock (not matched against NIDA).

## Answer key (for folding back into the spec)

| # | Question | Status |
|---|----------|--------|
| 1 | SDID interface type | 🔴 A1 |
| 2 | Who matches | 🟢 we do |
| 3 | Auth to SDID | 🟢 OAuth2/API keys (detail: A3) |
| 4 | Sandbox | 🟢 none → mock-first + A7 |
| 5 | Modalities | 🟢 face + fingerprint |
| — | Fingerprint capture | 🟡 D1 |
| 6 | Matching type | 🟢 1:1 |
| 7 | PAD level | 🟢 ISO 30107 L2 |
| 8 | Subject id | 🟢 pseudonymised NID |
| 9 | Attributes | 🟢 face ref, name, DOB, address |
| 10 | Network reachability | 🟡 C1 |
| 11 | Quotas | 🔴 A5 |
| 12 | Identity changes | 🟢 poll / re-verify |
| 13 | NIDA authorization | 🟢 in place |
| 14 | Audit fields | 🟡 B1 |
| 15 | SLA | 🔴 A6 |
| 16 | Consent artefact | 🟢 our own (confirm B3) |
| 17 | Residency | 🟢 in-country (confirm B2) |
