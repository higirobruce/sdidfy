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
