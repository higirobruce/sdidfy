import { z } from 'zod';
import { ASSURANCE_LEVELS } from '../assurance.js';

/**
 * Enrolment DTOs (03 §2). The biometric sample rides in as base64 and is
 * decoded into an in-memory Uint8Array immediately; it must never be logged
 * or persisted (07 §1).
 */

export const attestationSchema = z.object({
  platform: z.enum(['android', 'ios', 'sim']),
  /** Play Integrity / App Attest token (mock format in dev: see attestation module). */
  token: z.string().min(1).max(16384),
  /** Hardware key attestation over the enrolled public key, where available. */
  keyAttestation: z.string().max(16384).optional(),
  /**
   * Id of the single-use attestation nonce minted by
   * `POST /v1/enrol/attestation-challenge`; the nonce itself must appear
   * *inside* the signed platform token (T4 — without it a token captured from
   * one genuine device replays from another).
   *
   * Optional in the schema but REQUIRED when `ATTESTATION_MODE=strict`: the
   * broker enforces presence itself so a missing nonce fails as a uniform
   * attestation rejection (03 §7) rather than a shape-revealing zod error, and
   * so mock-mode clients (device-sim, e2e) keep working unchanged.
   */
  nonceId: z.string().min(1).max(256).optional(),
});

export const publicKeyJwkSchema = z.object({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: z.string(),
  y: z.string(),
});

export const biometricSampleDtoSchema = z.object({
  modality: z.enum(['face', 'fingerprint']),
  /** base64-encoded capture bytes — transient, in-memory only. */
  data: z.string().min(1).max(2_000_000),
  liveness: z.object({
    method: z.string().max(64),
    score: z.number().min(0).max(1),
  }),
});

/**
 * Response of `POST /v1/enrol/attestation-challenge` (03 §2 step 1, T4).
 * `nonce` is what the app feeds to Play Integrity / App Attest; `nonceId` is
 * what it sends back on `/v1/enrol/start` so the broker can look the nonce up
 * and consume it exactly once. Unauthenticated and rate-limited per IP.
 */
export const attestationChallengeResponseSchema = z.object({
  /** Opaque handle; echoed back as `attestation.nonceId` on enrolment. */
  nonceId: z.string(),
  /** base64url, >=32 bytes of CSPRNG output — embed in the attestation. */
  nonce: z.string(),
  expiresAt: z.string(),
});
export type AttestationChallengeResponse = z.infer<typeof attestationChallengeResponseSchema>;

export const enrolStartRequestSchema = z.object({
  nid: z.string().regex(/^\d{16}$/, 'NID must be 16 digits'),
  devicePublicKeyJwk: publicKeyJwkSchema,
  attestation: attestationSchema,
  deviceLabel: z.string().min(1).max(120),
  sample: biometricSampleDtoSchema,
});
export type EnrolStartRequest = z.infer<typeof enrolStartRequestSchema>;

export const enrolStartResponseSchema = z.object({
  bindingId: z.string().uuid(),
  assuranceLevel: z.enum(ASSURANCE_LEVELS),
  activationChallenge: z.object({
    challengeId: z.string(),
    nonce: z.string(),
    payload: z.string(),
    expiresAt: z.string(),
  }),
});
export type EnrolStartResponse = z.infer<typeof enrolStartResponseSchema>;

export const enrolActivateRequestSchema = z.object({
  bindingId: z.string().uuid(),
  challengeId: z.string(),
  /** base64url ECDSA P-256/SHA-256 signature (raw r||s) over the challenge payload. */
  signature: z.string().min(1).max(512),
});
export type EnrolActivateRequest = z.infer<typeof enrolActivateRequestSchema>;

export const enrolActivateResponseSchema = z.object({
  bindingId: z.string().uuid(),
  status: z.literal('active'),
});
export type EnrolActivateResponse = z.infer<typeof enrolActivateResponseSchema>;
