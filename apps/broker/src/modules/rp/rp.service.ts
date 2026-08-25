import { Injectable } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import { eq } from 'drizzle-orm';
import type { Request } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';
import { DbService } from '../../db/db.module.js';
import { relyingParties } from '../../db/schema.js';

export type RelyingPartyRow = typeof relyingParties.$inferSelect;

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Constant-time compare of two hex digests (avoids secret-comparison timing leaks). */
function digestsEqual(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, 'hex');
  const b = Buffer.from(bHex, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Relying-party registry + OAuth2 client authentication (04 §6, T9).
 * Supports client_secret_basic and client_secret_post; secrets are stored
 * only as SHA-256 hashes. Failures are uniformly `invalid_client` so an
 * attacker cannot distinguish unknown client / wrong secret / suspended RP.
 */
@Injectable()
export class RpService {
  constructor(private readonly dbService: DbService) {}

  async loadByClientId(clientId: string): Promise<RelyingPartyRow | null> {
    const rows = await this.dbService.db
      .select()
      .from(relyingParties)
      .where(eq(relyingParties.clientId, clientId));
    return rows[0] ?? null;
  }

  async loadById(rpId: string): Promise<RelyingPartyRow | null> {
    const rows = await this.dbService.db
      .select()
      .from(relyingParties)
      .where(eq(relyingParties.id, rpId));
    return rows[0] ?? null;
  }

  /**
   * Authenticate the RP behind an OAuth2 endpoint request.
   * client_secret_basic: Authorization: Basic base64(client_id:client_secret)
   * client_secret_post:  client_id + client_secret in the form body
   */
  async authenticateClient(req: Request): Promise<RelyingPartyRow> {
    const creds = this.extractCredentials(req);
    if (!creds) {
      throw new BridgeError('invalid_client', 'Client authentication required', 401);
    }
    const rp = await this.loadByClientId(creds.clientId);
    if (!rp || !rp.clientSecretHash) {
      throw new BridgeError('invalid_client', 'Client authentication failed', 401);
    }
    if (!digestsEqual(sha256Hex(creds.clientSecret), rp.clientSecretHash)) {
      throw new BridgeError('invalid_client', 'Client authentication failed', 401);
    }
    if (rp.status !== 'active') {
      throw new BridgeError('invalid_client', 'Client authentication failed', 401);
    }
    return rp;
  }

  private extractCredentials(req: Request): { clientId: string; clientSecret: string } | null {
    const header = req.headers.authorization ?? '';
    if (header.startsWith('Basic ')) {
      let decoded: string;
      try {
        decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      } catch {
        return null;
      }
      const sep = decoded.indexOf(':');
      if (sep < 0) return null;
      const rawId = decoded.slice(0, sep);
      const rawSecret = decoded.slice(sep + 1);
      try {
        // RFC 6749 §2.3.1: values are form-urlencoded inside the Basic pair.
        return { clientId: decodeURIComponent(rawId), clientSecret: decodeURIComponent(rawSecret) };
      } catch {
        return { clientId: rawId, clientSecret: rawSecret };
      }
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    if (typeof body['client_id'] === 'string' && typeof body['client_secret'] === 'string') {
      return { clientId: body['client_id'], clientSecret: body['client_secret'] };
    }
    return null;
  }
}
