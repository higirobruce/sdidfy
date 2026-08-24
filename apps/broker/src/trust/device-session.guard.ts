import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import { eq } from 'drizzle-orm';
import type { Request } from 'express';
import { DbService } from '../db/db.module.js';
import { deviceBindings } from '../db/schema.js';
import { KeysService } from '../keys/keys.service.js';

export const DEVICE_SESSION_AUDIENCE = 'device-backchannel';

export interface DeviceSession {
  citizenId: string;
  bindingId: string;
}

/**
 * Authenticates the device backchannel (04 §3 step 5, 05): a short-lived
 * first-party session JWT minted at direct login, bound to the device key.
 * Revocation must be fast (06 §4), so the binding's live status is checked
 * on EVERY request — a revoked device loses access immediately, not at
 * session expiry.
 */
@Injectable()
export class DeviceSessionGuard implements CanActivate {
  constructor(
    private readonly keys: KeysService,
    private readonly dbService: DbService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request & { deviceSession?: DeviceSession }>();
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) throw new BridgeError('access_denied', 'Missing device session', 401);
    let payload;
    try {
      payload = await this.keys.verifyJwt(token, { audience: DEVICE_SESSION_AUDIENCE });
    } catch {
      throw new BridgeError('access_denied', 'Invalid device session', 401);
    }
    const citizenId = payload.sub;
    const bindingId = payload['binding_id'];
    if (typeof citizenId !== 'string' || typeof bindingId !== 'string') {
      throw new BridgeError('access_denied', 'Invalid device session', 401);
    }
    const rows = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.id, bindingId));
    const binding = rows[0];
    if (!binding || binding.status !== 'active' || binding.citizenId !== citizenId) {
      throw new BridgeError('binding_not_active', 'Device binding is not active', 401);
    }
    req.deviceSession = { citizenId, bindingId };
    return true;
  }
}
