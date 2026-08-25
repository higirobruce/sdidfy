import { Module } from '@nestjs/common';
import { RpModule } from '../rp/rp.module.js';
import { CibaDeviceController } from './ciba-device.controller.js';
import { CibaController } from './ciba.controller.js';

/**
 * CIBA decoupled authentication (spec 04 §3): the RP-facing backchannel
 * initiation endpoint plus the device backchannel where the citizen's phone
 * pulls pending requests and returns signed approve/deny decisions.
 */
@Module({
  imports: [RpModule],
  controllers: [CibaController, CibaDeviceController],
})
export class CibaModule {}
