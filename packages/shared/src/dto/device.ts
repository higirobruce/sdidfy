import { z } from 'zod';
import { ASSURANCE_LEVELS } from '../assurance.js';

/**
 * Device backchannel DTOs (04 §3 steps 5–7, 05 §2).
 * The device authenticates these calls by signing challenges with its bound
 * key — the push channel is wake-only and never carries auth data (T6).
 */

/** Direct login: request a challenge for a binding. */
export const loginChallengeRequestSchema = z.object({
  bindingId: z.string().uuid(),
});
export type LoginChallengeRequest = z.infer<typeof loginChallengeRequestSchema>;

export const loginRequestSchema = z.object({
  bindingId: z.string().uuid(),
  challengeId: z.string(),
  signature: z.string().min(1).max(512),
});
export type LoginRequest = z.infer<typeof loginRequestSchema>;

export const loginResponseSchema = z.object({
  /** Short-lived first-party session JWT, bound to the device key (04 §7). */
  sessionToken: z.string(),
  expiresIn: z.number(),
});
export type LoginResponse = z.infer<typeof loginResponseSchema>;

/** Pending CIBA transactions for the citizen (pulled over the authenticated backchannel). */
export const pendingTransactionSchema = z.object({
  authReqId: z.string(),
  rpName: z.string(),
  rpLogoUri: z.string().nullable(),
  scopes: z.array(z.string()),
  scopeDescriptions: z.array(z.string()),
  bindingMessage: z.string().nullable(),
  requestedAssurance: z.enum(ASSURANCE_LEVELS),
  createdAt: z.string(),
  expiresAt: z.string(),
  /** Challenge the device must sign to approve or deny. */
  challenge: z.object({
    challengeId: z.string(),
    nonce: z.string(),
    approvePayload: z.string(),
    denyPayload: z.string(),
    expiresAt: z.string(),
  }),
});
export type PendingTransaction = z.infer<typeof pendingTransactionSchema>;

export const pendingTransactionsResponseSchema = z.object({
  transactions: z.array(pendingTransactionSchema),
});
export type PendingTransactionsResponse = z.infer<typeof pendingTransactionsResponseSchema>;

export const cibaDecisionRequestSchema = z.object({
  authReqId: z.string(),
  bindingId: z.string().uuid(),
  challengeId: z.string(),
  decision: z.enum(['approve', 'deny']),
  signature: z.string().min(1).max(512),
  /** "I didn't request this" flag on deny (05 §2 help/report path). */
  reportSuspicious: z.boolean().optional(),
});
export type CibaDecisionRequest = z.infer<typeof cibaDecisionRequestSchema>;

export const deviceListItemSchema = z.object({
  bindingId: z.string().uuid(),
  deviceLabel: z.string(),
  assuranceLevel: z.enum(ASSURANCE_LEVELS),
  status: z.enum(['pending', 'active', 'revoked']),
  enrolledAt: z.string(),
  lastUsedAt: z.string().nullable(),
});
export type DeviceListItem = z.infer<typeof deviceListItemSchema>;

export const revokeDeviceRequestSchema = z.object({
  bindingId: z.string().uuid(),
  reason: z.string().max(240).optional(),
});
export type RevokeDeviceRequest = z.infer<typeof revokeDeviceRequestSchema>;
