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
    const accessToken = await this.keys.signJwt(
      {
        sub,
        cid: input.citizenId,
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
