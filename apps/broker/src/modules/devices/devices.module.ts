import { Module } from '@nestjs/common';
import { ConsentModule } from '../consent/consent.module.js';
import { DevicesController } from './devices.controller.js';
import { DevicesService } from './devices.service.js';

/**
 * Direct login + citizen device management (spec 01 §2.2, 05 §2, 06 §4).
 * Consent list/revoke endpoints ride on the same authenticated backchannel,
 * delegating to ConsentService.
 */
@Module({
  imports: [ConsentModule],
  controllers: [DevicesController],
  providers: [DevicesService],
  exports: [DevicesService],
})
export class DevicesModule {}
