import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import {
  enrolActivateRequestSchema,
  enrolStartRequestSchema,
  type EnrolActivateRequest,
  type EnrolActivateResponse,
  type EnrolStartRequest,
  type EnrolStartResponse,
  type AttestationChallengeResponse,
} from '@sdid/shared';
import { ZodPipe } from '../../common/zod.pipe.js';
import { EnrolmentService } from './enrolment.service.js';

/** Enrolment + device binding endpoints (spec 03 §2). */
@Controller('v1/enrol')
export class EnrolmentController {
  constructor(private readonly enrolment: EnrolmentService) {}

  /**
   * Mint the single-use nonce the app must embed in its Play Integrity /
   * App Attest token (03 §2 step 1, T4). Unauthenticated — it necessarily
   * precedes enrolment — and therefore rate-limited per IP in the service.
   */
  @Post('attestation-challenge')
  @HttpCode(200)
  async attestationChallenge(@Req() req: Request): Promise<AttestationChallengeResponse> {
    return this.enrolment.attestationChallenge(req.ip ?? 'unknown');
  }

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
