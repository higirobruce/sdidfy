import { Injectable } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import { RedisService } from '../redis/redis.module.js';

/**
 * Redis fixed-window rate limiting + failure lockout (06 §5, T14).
 * Scopes compose: callers pass keys like `enrol:nid:<pseudoNid>` or
 * `ciba:rp:<rpId>` — per-identity, per-device, per-IP, per-RP as needed.
 */
@Injectable()
export class RateLimitService {
  constructor(private readonly redis: RedisService) {}

  /** Throws rate_limited when `key` exceeds `limit` hits per `windowSeconds`. */
  async hit(key: string, limit: number, windowSeconds: number): Promise<void> {
    const redisKey = `rl:${key}`;
    const count = await this.redis.client.incr(redisKey);
    if (count === 1) await this.redis.client.expire(redisKey, windowSeconds);
    if (count > limit) throw new BridgeError('rate_limited', 'Too many requests', 429);
  }

  /**
   * Failure lockout with exponential backoff (03 §7): record a failure and
   * throw locked_out once `maxFailures` is reached within the window.
   */
  async recordFailure(key: string, maxFailures: number, windowSeconds: number): Promise<void> {
    const redisKey = `lockout:${key}`;
    const count = await this.redis.client.incr(redisKey);
    if (count === 1) await this.redis.client.expire(redisKey, windowSeconds);
    if (count >= maxFailures) {
      await this.redis.client.expire(redisKey, windowSeconds * 2 ** Math.min(count - maxFailures, 4));
    }
  }

  async assertNotLockedOut(key: string, maxFailures: number): Promise<void> {
    const count = await this.redis.client.get(`lockout:${key}`);
    if (count && Number(count) >= maxFailures) {
      throw new BridgeError('locked_out', 'Temporarily locked out', 429);
    }
  }

  async clearFailures(key: string): Promise<void> {
    await this.redis.client.del(`lockout:${key}`);
  }
}
