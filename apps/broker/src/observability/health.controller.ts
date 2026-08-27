import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import { HealthService, type ReadinessReport } from './health.service.js';

/**
 * Liveness and readiness probes (09 §2 Phase 3).
 *
 * Both are UNAUTHENTICATED on purpose: a kubelet, load-balancer health check
 * or systemd watchdog cannot hold a credential, and gating a probe behind one
 * turns a config mistake into a crash-loop. What makes that safe is that the
 * bodies carry no secrets and no internal detail — only per-dependency `ok` /
 * `fail`, which is the minimum an operator needs and tells an attacker nothing
 * they could not learn by watching the service fail.
 *
 * The distinction matters to an orchestrator and is not cosmetic:
 *   - `/healthz` — is this PROCESS alive? Never touches a dependency, so a
 *     Postgres blip cannot get every replica killed and restarted (which would
 *     turn a recoverable dependency outage into a total one).
 *   - `/readyz` — can this replica SERVE? Checks Postgres, Redis and the
 *     signing key, and answers 503 when it cannot, so the load balancer
 *     removes it from rotation while leaving the process alive to recover.
 */
@Controller()
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get('healthz')
  liveness(): { status: 'ok' } {
    // Reaching this handler IS the liveness signal: the event loop is turning
    // and the HTTP stack is answering. Deliberately no dependency checks.
    return { status: 'ok' };
  }

  @Get('readyz')
  async readiness(@Res() res: Response): Promise<void> {
    const report: ReadinessReport = await this.health.readiness();
    // 200 ready / 503 not-ready are the only two codes an orchestrator needs;
    // 503 (not 500) says "try me again", which is what a dependency blip is.
    res
      .status(report.ready ? 200 : 503)
      .header('Cache-Control', 'no-store')
      .json({ status: report.ready ? 'ready' : 'not_ready', checks: report.checks });
  }
}
