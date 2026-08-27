import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import type { Request } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { loadConfig } from '../config.js';

/**
 * Gate on `/metrics` (06 §7 — operational telemetry is not public).
 *
 * DEPLOYMENT CHOICE (documented in docs/runbook.md §11): the endpoint is
 * served on the SAME port as the protocol surface and protected by a bearer
 * token, rather than bound to a second listener. Rationale: a second port is
 * only a control if the network actually enforces it, and the GoR deployment
 * target and its ingress rules are not settled (01 §3) — a token is a control
 * we can guarantee today, and it composes with a network policy later.
 *
 * The token is `METRICS_TOKEN` when set, else `ADMIN_API_TOKEN`. Preferring a
 * DEDICATED token matters: a Prometheus scrape job is long-lived, widely
 * readable infrastructure config, and handing it `ADMIN_API_TOKEN` would give
 * every operator of the monitoring stack the ability to onboard a relying
 * party (T12). Production refuses to boot on the shared token (see config.ts).
 *
 * Even so, `/metrics` carries NO citizen data: label vocabularies are bounded
 * enums by construction (see metrics.registry.ts). The token protects against
 * an attacker reading operational shape (enrolment volumes, failure spikes,
 * whether an attack is being detected), not against identity disclosure.
 */
@Injectable()
export class MetricsGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const config = loadConfig();
    if (!config.METRICS_ENABLED) {
      // Disabled means gone, not "unprotected": same shape as any other
      // unknown route to an unauthenticated caller.
      throw new BridgeError('access_denied', 'Not found', 404);
    }
    const req = context.switchToHttp().getRequest<Request>();
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const expected =
      config.METRICS_TOKEN.trim() !== '' ? config.METRICS_TOKEN : config.ADMIN_API_TOKEN;
    if (!token || !constantTimeEquals(token, expected)) {
      throw new BridgeError('access_denied', 'Metrics authentication required', 401);
    }
    return true;
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
