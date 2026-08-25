import { Module } from '@nestjs/common';
import { EnrolmentController } from './enrolment.controller.js';
import { EnrolmentService } from './enrolment.service.js';

/**
 * Enrolment + device binding (spec 03): the once-per-device biometric
 * proofing flow that turns a phone into an authenticator. Depends only on
 * the global infra modules (Db/Redis/Keys/Audit/Trust/Sdid).
 */
@Module({
  controllers: [EnrolmentController],
  providers: [EnrolmentService],
  exports: [EnrolmentService],
})
export class EnrolmentModule {}
