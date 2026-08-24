import { z } from 'zod';
import { ASSURANCE_LEVELS } from '../assurance.js';

/** CIBA backchannel authentication request (04 §3). Form-encoded per OAuth2. */
export const bcAuthorizeRequestSchema = z.object({
  scope: z.string().min(1),
  /** Pairwise subject the RP holds for this citizen (04 §3) — never a raw NID. */
  login_hint: z.string().min(1),
  binding_message: z.string().max(140).optional(),
  /** RP-required minimum assurance (maps to acr_values in CIBA Core). */
  requested_al: z.enum(ASSURANCE_LEVELS).optional(),
  requested_expiry: z.coerce.number().int().positive().max(600).optional(),
});
export type BcAuthorizeRequest = z.infer<typeof bcAuthorizeRequestSchema>;

export const bcAuthorizeResponseSchema = z.object({
  auth_req_id: z.string(),
  expires_in: z.number(),
  interval: z.number(),
});
export type BcAuthorizeResponse = z.infer<typeof bcAuthorizeResponseSchema>;

/** /token request (grant_type discriminates the flow). */
export const tokenRequestSchema = z.object({
  grant_type: z.string(),
  // CIBA
  auth_req_id: z.string().optional(),
  // Authorization code + PKCE
  code: z.string().optional(),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
  client_id: z.string().optional(),
});
export type TokenRequest = z.infer<typeof tokenRequestSchema>;

export const tokenResponseSchema = z.object({
  access_token: z.string(),
  id_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
  scope: z.string(),
});
export type TokenResponse = z.infer<typeof tokenResponseSchema>;

export const authorizeRequestSchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string(),
  redirect_uri: z.string().url(),
  scope: z.string(),
  state: z.string().optional(),
  nonce: z.string().optional(),
  code_challenge: z.string(),
  code_challenge_method: z.literal('S256'),
  acr_values: z.string().optional(),
});
export type AuthorizeRequest = z.infer<typeof authorizeRequestSchema>;
