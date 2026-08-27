import { Controller, Get, Header, UseGuards } from '@nestjs/common';
import { MetricsGuard } from './metrics.guard.js';
import { MetricsService } from './metrics.service.js';

/** Prometheus scrape endpoint. Admin/metrics-token gated — see MetricsGuard. */
@Controller('metrics')
@UseGuards(MetricsGuard)
export class MetricsController {
  constructor(private readonly metrics: MetricsService) {}

  @Get()
  // text/plain; version=0.0.4 is the content type Prometheus expects for the
  // classic exposition format. `charset=utf-8` is part of the contract.
  @Header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  @Header('Cache-Control', 'no-store')
  scrape(): string {
    return this.metrics.render();
  }
}
