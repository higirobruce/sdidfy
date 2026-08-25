import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import {
  enrolActivateRequestSchema,
  enrolStartRequestSchema,
  type EnrolActivateRequest,
  type EnrolActivateResponse,
  type EnrolStartRequest,
  type EnrolStartResponse,
} from '@sdid/shared';
import { ZodPipe } from '../../common/zod.pipe.js';
import { EnrolmentService } from './enrolment.service.js';

/** Enrolment + device binding endpoints (spec 03 §2). */
@Controller('v1/enrol')
export class EnrolmentController {
  constructor(private readonly enrolment: EnrolmentService) {}

  @Post('start')
  @HttpCode(200)
  async start(
    @Body(new ZodPipe(enrolStartRequestSchema)) body: EnrolStartRequest,
    @Req() req: Request,
  ): Promise<EnrolStartResponse> {
    return this.enrolment.start(body, req.ip ?? 'unknown');
  }

  @Post('activate')
  @HttpCode(200)
  async activate(
    @Body(new ZodPipe(enrolActivateRequestSchema)) body: EnrolActivateRequest,
  ): Promise<EnrolActivateResponse> {
    return this.enrolment.activate(body);
  }
}
