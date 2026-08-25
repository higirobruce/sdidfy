import { Body, Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { z } from 'zod';
import {
  loginChallengeRequestSchema,
  loginRequestSchema,
  revokeDeviceRequestSchema,
  type DeviceListItem,
  type IssuedChallenge,
  type LoginChallengeRequest,
  type LoginRequest,
  type LoginResponse,
  type RevokeDeviceRequest,
} from '@sdid/shared';
import { ZodPipe } from '../../common/zod.pipe.js';
import { DeviceSessionGuard, type DeviceSession } from '../../trust/device-session.guard.js';
import { ConsentService, type ConsentListItem } from '../consent/consent.service.js';
import { DevicesService, type ActivityItem } from './devices.service.js';

const revokeConsentRequestSchema = z.object({ consentId: z.string().uuid() });
type RevokeConsentRequest = z.infer<typeof revokeConsentRequestSchema>;

type AuthedRequest = Request & { deviceSession: DeviceSession };

/**
 * Direct login + the authenticated device backchannel (01 §2.2, 05 §2).
 * Backchannel routes are guarded by DeviceSessionGuard, which re-checks the
 * binding's live status on every request (06 §4 — revocation is immediate).
 */
@Controller('v1/device')
export class DevicesController {
  constructor(
    private readonly devices: DevicesService,
    private readonly consents: ConsentService,
  ) {}

  @Post('login/challenge')
  @HttpCode(200)
  async loginChallenge(
    @Body(new ZodPipe(loginChallengeRequestSchema)) body: LoginChallengeRequest,
  ): Promise<IssuedChallenge> {
    return this.devices.issueLoginChallenge(body.bindingId);
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body(new ZodPipe(loginRequestSchema)) body: LoginRequest): Promise<LoginResponse> {
    return this.devices.login(body);
  }

  @Get('bindings')
  @UseGuards(DeviceSessionGuard)
  async listBindings(@Req() req: AuthedRequest): Promise<{ devices: DeviceListItem[] }> {
    return { devices: await this.devices.listBindings(req.deviceSession.citizenId) };
  }

  @Post('bindings/revoke')
  @HttpCode(200)
  @UseGuards(DeviceSessionGuard)
  async revokeBinding(
    @Body(new ZodPipe(revokeDeviceRequestSchema)) body: RevokeDeviceRequest,
    @Req() req: AuthedRequest,
  ): Promise<{ status: 'revoked' }> {
    return this.devices.revokeBinding(req.deviceSession.citizenId, body.bindingId, body.reason);
  }

  @Get('consents')
  @UseGuards(DeviceSessionGuard)
  async listConsents(@Req() req: AuthedRequest): Promise<{ consents: ConsentListItem[] }> {
    return { consents: await this.consents.listGrants(req.deviceSession.citizenId) };
  }

  @Post('consents/revoke')
  @HttpCode(200)
  @UseGuards(DeviceSessionGuard)
  async revokeConsent(
    @Body(new ZodPipe(revokeConsentRequestSchema)) body: RevokeConsentRequest,
    @Req() req: AuthedRequest,
  ): Promise<{ status: 'revoked' }> {
    await this.consents.revokeGrant(req.deviceSession.citizenId, body.consentId);
    return { status: 'revoked' };
  }

  @Get('activity')
  @UseGuards(DeviceSessionGuard)
  async activity(@Req() req: AuthedRequest): Promise<{ events: ActivityItem[] }> {
    return { events: await this.devices.recentActivity(req.deviceSession.citizenId) };
  }
}
