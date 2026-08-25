import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import type { Request } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { loadConfig } from '../../config.js';

/**
 * Admin API gate (04 §6: registration is admin-gated and audited — T9, T12).
 * Bearer token must equal ADMIN_API_TOKEN (prod: KMS-held, never a dev default).
 */
@Injectable()
export class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const expected = loadConfig().ADMIN_API_TOKEN;
    if (!token || !constantTimeEquals(token, expected)) {
      throw new BridgeError('access_denied', 'Admin authentication required', 401);
    }
    return true;
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
