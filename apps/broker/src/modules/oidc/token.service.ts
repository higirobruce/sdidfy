import { Injectable } from '@nestjs/common';
import type { AssuranceLevel, TokenResponse } from '@sdid/shared';
import { AMR_VALUES } from '@sdid/shared';
import { loadConfig } from '../../config.js';
import { KeysService } from '../../keys/keys.service.js';
import { PairwiseService } from '../../trust/pairwise.service.js';
import type { RelyingPartyRow } from '../rp/rp.service.js';

export interface MintTokensInput {
  rp: RelyingPartyRow;
  citizenId: string;
  scopes: string[];
  acr: AssuranceLevel;
  /** When the citizen actually authenticated (approval time). */
  authTime: Date;
  nonce?: string | null;
}

/**
 * Token minting (04 §4): pairwise `sub` (never a cross-RP identifier),
 * ES256-signed by the broker key, audience-bound to the RP (T9), short TTLs
 * (open decision #2 — conservative).
 */
@Injectable()
export class TokenService {
  constructor(
    private readonly keys: KeysService,
    private readonly pairwise: PairwiseService,
  ) {}

  async mint(input: MintTokensInput): Promise<TokenResponse> {
    const config = loadConfig();
    const sub = await this.pairwise.subjectFor(input.citizenId, input.rp.id, input.rp.pairwiseSalt);
    const authTimeEpoch = Math.floor(input.authTime.getTime() / 1000);
    const idToken = await this.keys.signJwt(
      {
        sub,
        acr: input.acr,
        amr: [...AMR_VALUES],
        auth_time: authTimeEpoch,
        ...(input.nonce ? { nonce: input.nonce } : {}),
      },
      { audience: input.rp.clientId, ttlSeconds: config.ID_TOKEN_TTL_SECONDS },
    );
    // NOTE: the access token deliberately carries NO global citizen identifier.
    // It is a signed JWT the RP holds and can decode, so any stable cross-RP id
    // here (e.g. citizens.id) would let two RPs correlate the same citizen and
    // defeat the pairwise `sub` (privacy non-negotiable, 04 §4 / 10). The broker
    // re-resolves the citizen at /userinfo from (client_id, pairwise sub).
    const accessToken = await this.keys.signJwt(
      {
        sub,
        scope: input.scopes.join(' '),
        acr: input.acr,
        token_use: 'access',
        client_id: input.rp.clientId,
      },
      { audience: input.rp.clientId, ttlSeconds: config.ACCESS_TOKEN_TTL_SECONDS },
    );
    return {
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: config.ACCESS_TOKEN_TTL_SECONDS,
      scope: input.scopes.join(' '),
    };
  }
}
