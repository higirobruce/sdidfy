import { z } from 'zod';
import { ASSURANCE_LEVELS } from '../assurance.js';

/** RP onboarding (04 §6) — admin-gated and audited (T9). */
export const registerRpRequestSchema = z.object({
  name: z.string().min(1).max(120),
  logoUri: z.string().url().optional(),
  authMethod: z.enum(['secret', 'private_key_jwt', 'mtls']).default('secret'),
  allowedScopes: z.array(z.string()).min(1),
  maxAssurance: z.enum(ASSURANCE_LEVELS).default('AL2'),
  allowedFlows: z.array(z.enum(['code', 'ciba'])).min(1),
  redirectUris: z.array(z.string().url()).default([]),
});
export type RegisterRpRequest = z.infer<typeof registerRpRequestSchema>;

export const registerRpResponseSchema = z.object({
  rpId: z.string().uuid(),
  clientId: z.string(),
  /** Returned exactly once at registration; only a hash is stored. */
  clientSecret: z.string().optional(),
});
export type RegisterRpResponse = z.infer<typeof registerRpResponseSchema>;
