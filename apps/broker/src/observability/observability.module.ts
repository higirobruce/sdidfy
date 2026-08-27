import { Global, Module } from '@nestjs/common';
import { HealthController } from './health.controller.js';
import { HealthService } from './health.service.js';
import { MetricsController } from './metrics.controller.js';
import { MetricsGuard } from './metrics.guard.js';
import { MetricsService } from './metrics.service.js';

/**
 * Operational observability (09 §2 Phase 3): the Prometheus registry, the
 * `/metrics` scrape endpoint, and the liveness/readiness probes.
 *
 * Global because MetricsService is injected across the whole broker — audit,
 * trust, protocol and push all record into it, and threading a non-global
 * module through every feature module would add imports without adding
 * safety. It has no dependencies of its own beyond the infra modules, so
 * there is no import-order hazard.
 */
@Global()
@Module({
  controllers: [MetricsController, HealthController],
  providers: [MetricsService, MetricsGuard, HealthService],
  exports: [MetricsService],
})
export class ObservabilityModule {}
