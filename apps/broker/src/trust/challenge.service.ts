import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import {
  BridgeError,
  buildChallengePayload,
  purposeString,
  type ChallengePurpose,
  type IssuedChallenge,
} from '@sdid/shared';
import { RedisService } from '../redis/redis.module.js';
import { loadConfig } from '../config.js';

/**
 * Single-use, short-TTL server challenges (T4 — replay defence).
 * Stored in Redis keyed by challengeId; consumed atomically with GETDEL so a
 * signature can never be replayed, even across concurrent requests.
 * The stored value binds the challenge to a purpose and a binding id.
 */
@Injectable()
export class ChallengeService {
  constructor(private readonly redis: RedisService) {}

  async issue(purpose: ChallengePurpose, bindingId: string): Promise<IssuedChallenge> {
    const ttl = loadConfig().CHALLENGE_TTL_SECONDS;
    const challengeId = randomBytes(16).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const payload = buildChallengePayload(purpose, challengeId, nonce);
    const record = JSON.stringify({ purpose: purposeString(purpose), nonce, bindingId });
    await this.redis.client.set(`challenge:${challengeId}`, record, 'EX', ttl);
    return {
      challengeId,
      nonce,
      payload,
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
    };
  }

  /**
   * Atomically consume a challenge. Throws challenge_invalid when unknown,
   * expired, already used, or bound to a different purpose/binding.
   * Returns the exact payload the device must have signed.
   */
  async consume(challengeId: string, expectedPurpose: ChallengePurpose, bindingId: string): Promise<string> {
    const raw = await this.redis.client.getdel(`challenge:${challengeId}`);
    if (!raw) throw new BridgeError('challenge_invalid', 'Unknown, expired, or already-used challenge', 400);
    const record = JSON.parse(raw) as { purpose: string; nonce: string; bindingId: string };
    if (record.purpose !== purposeString(expectedPurpose) || record.bindingId !== bindingId) {
      throw new BridgeError('challenge_invalid', 'Challenge purpose/binding mismatch', 400);
    }
    return buildChallengePayload(expectedPurpose, challengeId, record.nonce);
  }

  /**
   * CIBA needs approve/deny as alternative consumptions of ONE challenge.
   * Peek returns the nonce without consuming; the decision handler consumes.
   */
  async peekNonce(challengeId: string): Promise<string | null> {
    const raw = await this.redis.client.get(`challenge:${challengeId}`);
    if (!raw) return null;
    return (JSON.parse(raw) as { nonce: string }).nonce;
  }
}
