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
   * Mint a single-use attestation nonce (03 §2 step 1, T4). Unlike the signing
   * challenges above there is no binding yet — enrolment has not started — and
   * no `sdid-bridge:` payload: the nonce travels *inside* the Play Integrity /
   * App Attest token, under the platform's own signature. What it shares is
   * the property that matters: server-issued, single-use, short-TTL.
   *
   * Kept in its own key space (`attnonce:`) because its TTL differs from the
   * signing challenges' and an attestation nonce must never be usable as a
   * signing challenge (or vice versa); the stored purpose enforces that even
   * if the key spaces were ever merged.
   */
  async issueAttestationNonce(): Promise<{ nonceId: string; nonce: string; expiresAt: string }> {
    const ttl = loadConfig().ATTESTATION_NONCE_TTL_SECONDS;
    const nonceId = randomBytes(16).toString('base64url');
    // 32 bytes of CSPRNG — the floor both Play Integrity and App Attest
    // guidance assume for an unguessable server challenge.
    const nonce = randomBytes(32).toString('base64url');
    const record = JSON.stringify({ purpose: purposeString({ kind: 'attestation' }), nonce });
    await this.redis.client.set(`attnonce:${nonceId}`, record, 'EX', ttl);
    return { nonceId, nonce, expiresAt: new Date(Date.now() + ttl * 1000).toISOString() };
  }

  /**
   * Atomically consume an attestation nonce and return its value. GETDEL means
   * a second use of the same nonceId — a replay — finds nothing and throws,
   * even under concurrent requests.
   */
  async consumeAttestationNonce(nonceId: string): Promise<string> {
    const raw = await this.redis.client.getdel(`attnonce:${nonceId}`);
    if (!raw) {
      throw new BridgeError('challenge_invalid', 'Unknown, expired, or already-used attestation nonce', 400);
    }
    const record = JSON.parse(raw) as { purpose: string; nonce: string };
    if (record.purpose !== purposeString({ kind: 'attestation' })) {
      throw new BridgeError('challenge_invalid', 'Challenge purpose mismatch', 400);
    }
    return record.nonce;
  }

  /**
   * CIBA challenges allow two alternative consumptions of one nonce: the
   * device signs EITHER the approve payload OR the deny payload (so denials
   * are authentic too). Stored purpose is `ciba:<authReqId>`; consumption
   * names the decision and returns the payload the device must have signed.
   */
  async issueCiba(
    authReqId: string,
    bindingId: string,
  ): Promise<IssuedChallenge & { approvePayload: string; denyPayload: string }> {
    const ttl = loadConfig().CHALLENGE_TTL_SECONDS;
    const challengeId = randomBytes(16).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const record = JSON.stringify({ purpose: `ciba:${authReqId}`, nonce, bindingId });
    await this.redis.client.set(`challenge:${challengeId}`, record, 'EX', ttl);
    const approvePayload = buildChallengePayload({ kind: 'ciba-approve', authReqId }, challengeId, nonce);
    const denyPayload = buildChallengePayload({ kind: 'ciba-deny', authReqId }, challengeId, nonce);
    return {
      challengeId,
      nonce,
      payload: approvePayload,
      approvePayload,
      denyPayload,
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
    };
  }

  async consumeCiba(
    challengeId: string,
    authReqId: string,
    bindingId: string,
    decision: 'approve' | 'deny',
  ): Promise<string> {
    const raw = await this.redis.client.getdel(`challenge:${challengeId}`);
    if (!raw) throw new BridgeError('challenge_invalid', 'Unknown, expired, or already-used challenge', 400);
    const record = JSON.parse(raw) as { purpose: string; nonce: string; bindingId: string };
    if (record.purpose !== `ciba:${authReqId}` || record.bindingId !== bindingId) {
      throw new BridgeError('challenge_invalid', 'Challenge purpose/binding mismatch', 400);
    }
    const purpose: ChallengePurpose =
      decision === 'approve' ? { kind: 'ciba-approve', authReqId } : { kind: 'ciba-deny', authReqId };
    return buildChallengePayload(purpose, challengeId, record.nonce);
  }
}
