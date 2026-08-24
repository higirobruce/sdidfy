import { Module } from '@nestjs/common';
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
    // Infra (global)
    DbModule,
    RedisModule,
    KeysModule,
    AuditModule,
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
