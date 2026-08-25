// @sdid/test-rp — pilot relying-party client (SPEC 04): CIBA initiation,
// /oidc/token polling, and ID-token verification against the broker JWKS.
export {
  RpClient,
  type RpClientOptions,
  type InitiateCibaParams,
  type InitiateCibaResult,
  type PollOptions,
  type CibaTokens,
  type RegisterViaAdminResult,
  type RegisterRpParams,
} from './rp-client.js';
