/**
 * Wire contract: endpoint paths and zod schemas for every broker response the
 * app parses (05 §8 — shared types with the broker via the monorepo).
 *
 * Rules:
 *  - Request/response shapes that exist in `@sdid/shared` are re-used verbatim.
 *    Re-declaring them here would let the app and broker drift silently.
 *  - Responses that @sdid/shared does not model (the backchannel list views)
 *    get a schema here, kept deliberately *narrow*: unknown extra fields are
 *    stripped by zod, and a missing required field is a hard
 *    `unexpected_response` rather than an `undefined` rendered on a screen.
 *  - Everything crossing the boundary is validated. A malformed broker
 *    response must never propagate into UI state (the same discipline the
 *    adapter applies to SDID, 02 §4).
 */
import { z } from 'zod';
import {
  ASSURANCE_LEVELS,
  attestationChallengeResponseSchema,
  biometricSampleDtoSchema,
  deviceListItemSchema,
  enrolActivateResponseSchema,
  enrolStartResponseSchema,
  loginResponseSchema,
  pendingTransactionsResponseSchema,
  publicKeyJwkSchema,
} from '@sdid/shared';

export {
  attestationChallengeResponseSchema,
  enrolActivateResponseSchema,
  enrolStartResponseSchema,
  loginResponseSchema,
  pendingTransactionsResponseSchema,
};

export type BiometricSampleDto = z.infer<typeof biometricSampleDtoSchema>;

/** Attestation blob as `enrolStartRequestSchema.attestation` expects it. */
export const attestationPayloadSchema = z.object({
  platform: z.enum(['android', 'ios', 'sim']),
  token: z.string().min(1),
  keyAttestation: z.string().optional(),
  nonceId: z.string().min(1).optional(),
});
export type AttestationPayload = z.infer<typeof attestationPayloadSchema>;

/**
 * `POST /v1/device/login/challenge` returns an `IssuedChallenge`. @sdid/shared
 * declares the interface but no schema, so the app validates it here — this is
 * a payload we are about to *sign*, and signing an unvalidated string is how a
 * confused-deputy bug starts.
 */
export const issuedChallengeSchema = z.object({
  challengeId: z.string().min(1),
  nonce: z.string().min(1),
  payload: z.string().min(1),
  expiresAt: z.string().min(1),
});

/** `POST /v1/device/ciba/decision` */
export const cibaDecisionResponseSchema = z.object({
  status: z.enum(['approved', 'denied']),
});
export type CibaDecisionResponse = z.infer<typeof cibaDecisionResponseSchema>;

/** `GET /v1/device/bindings` */
export const bindingsResponseSchema = z.object({
  devices: z.array(deviceListItemSchema),
});

/** `POST /v1/device/bindings/revoke` and `POST /v1/device/consents/revoke` */
export const revokedResponseSchema = z.object({
  status: z.literal('revoked'),
});

/** `GET /v1/device/consents` — mirrors broker ConsentListItem. */
export const consentListItemSchema = z.object({
  id: z.string(),
  rpName: z.string(),
  scopes: z.array(z.string()),
  grantedAt: z.string(),
  revokedAt: z.string().nullable(),
  source: z.string(),
});
export type ConsentListItem = z.infer<typeof consentListItemSchema>;

export const consentsResponseSchema = z.object({
  consents: z.array(consentListItemSchema),
});

/**
 * `GET /v1/device/activity` — mirrors broker ActivityItem. `action` is a
 * broker-side audit action string; the UI maps known values to localised
 * labels and falls back to `activity.action.other` (never renders it raw).
 */
export const activityItemSchema = z.object({
  ts: z.string(),
  action: z.string(),
  result: z.string(),
  rpName: z.string().optional(),
});
export type ActivityItem = z.infer<typeof activityItemSchema>;

export const activityResponseSchema = z.object({
  events: z.array(activityItemSchema),
});

export const assuranceLevelSchema = z.enum(ASSURANCE_LEVELS);
export const publicKeyJwkWireSchema = publicKeyJwkSchema;

/** Every path the authenticator calls. Single source of truth for the client. */
export const ENDPOINTS = {
  attestationChallenge: '/v1/enrol/attestation-challenge',
  enrolStart: '/v1/enrol/start',
  enrolActivate: '/v1/enrol/activate',
  loginChallenge: '/v1/device/login/challenge',
  login: '/v1/device/login',
  cibaPending: '/v1/device/ciba/pending',
  cibaDecision: '/v1/device/ciba/decision',
  bindings: '/v1/device/bindings',
  revokeBinding: '/v1/device/bindings/revoke',
  consents: '/v1/device/consents',
  revokeConsent: '/v1/device/consents/revoke',
  activity: '/v1/device/activity',
} as const;
