import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller.js';
import { AdminGuard } from './admin.guard.js';
import { RpService } from './rp.service.js';

/**
 * Relying-party registry + admin onboarding API (spec 04 §6).
 * RpService is exported for the OIDC/CIBA protocol endpoints (client auth).
 */
@Module({
  controllers: [AdminController],
  providers: [RpService, AdminGuard],
  exports: [RpService],
})
export class RpModule {}
