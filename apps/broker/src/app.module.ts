import { Module } from '@nestjs/common';
import { AnomalyModule } from './anomaly/anomaly.module.js';
import { LoggingModule } from './logging/logging.module.js';
import { ObservabilityModule } from './observability/observability.module.js';
import { DbModule } from './db/db.module.js';
import { RedisModule } from './redis/redis.module.js';
import { KeysModule } from './keys/keys.service.js';
import { AuditModule } from './audit/audit.service.js';
import { TrustModule } from './trust/trust.module.js';
import { PushModule } from './push/push.service.js';
import { SdidModule } from './sdid/sdid.module.js';
import { EnrolmentModule } from './modules/enrolment/enrolment.module.js';
import { DevicesModule } from './modules/devices/devices.module.js';
import { ConsentModule } from './modules/consent/consent.module.js';
import { OidcModule } from './modules/oidc/oidc.module.js';
import { CibaModule } from './modules/ciba/ciba.module.js';
import { RpModule } from './modules/rp/rp.module.js';

@Module({
  imports: [
    // Infra (global). Observability and logging come first so metrics and the
    // request-logging interceptor exist before anything that records into them.
    ObservabilityModule,
    LoggingModule,
    DbModule,
    RedisModule,
    KeysModule,
    AuditModule,
    AnomalyModule,
    TrustModule,
    PushModule,
    SdidModule,
    // Citizen domain
    EnrolmentModule,
    DevicesModule,
    ConsentModule,
    // Protocol domain
    RpModule,
    OidcModule,
    CibaModule,
  ],
})
export class AppModule {}
