import { Global, Module } from '@nestjs/common';
import { AnomalyService } from './anomaly.service.js';

/**
 * Abuse/anomaly monitoring (06 §5). Global because the source-IP detectors are
 * called from the request path (enrolment) while the rest subscribe to the
 * audit stream — the service has to be reachable from both without every
 * feature module importing it.
 */
@Global()
@Module({
  providers: [AnomalyService],
  exports: [AnomalyService],
})
export class AnomalyModule {}
