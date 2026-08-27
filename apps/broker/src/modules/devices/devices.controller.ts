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

/**
 * Push-token registration (05 §5). Validated at the boundary like every other
 * body: the platform is a closed enum and the token is length-bounded, because
 * this value is written to a column and later handed verbatim to Google/Apple.
 * FCM registration tokens run to ~200 chars and APNs device tokens are 64 hex
 * characters; 4096 is a generous ceiling that still refuses a blob.
 */
const registerPushTokenSchema = z.object({
  platform: z.enum(['fcm', 'apns']),
  token: z.string().min(1).max(4096),
});
type RegisterPushTokenRequest = z.infer<typeof registerPushTokenSchema>;

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

  /**
   * Register or ROTATE this device's wake-only push address (05 §5).
   *
   * Authenticated by the device session and scoped to the session's OWN
   * binding — the body carries no binding id, so one device can never point
   * another citizen's wake notifications at itself. Rotation is the same call:
   * FCM/APNs reissue tokens without warning, so the app re-registers whatever
   * it currently holds and the newest value wins.
   */
  @Post('push-token')
  @HttpCode(200)
  @UseGuards(DeviceSessionGuard)
  async registerPushToken(
    @Body(new ZodPipe(registerPushTokenSchema)) body: RegisterPushTokenRequest,
    @Req() req: AuthedRequest,
  ): Promise<{ status: 'registered' }> {
    await this.devices.registerPushToken(req.deviceSession.bindingId, body.platform, body.token);
    return { status: 'registered' };
  }

  /** Remove this device's push address (app logout / notifications disabled). */
  @Post('push-token/remove')
  @HttpCode(200)
  @UseGuards(DeviceSessionGuard)
  async removePushToken(@Req() req: AuthedRequest): Promise<{ status: 'removed' }> {
    await this.devices.removePushToken(req.deviceSession.bindingId);
    return { status: 'removed' };
  }

  @Get('activity')
  @UseGuards(DeviceSessionGuard)
  async activity(@Req() req: AuthedRequest): Promise<{ events: ActivityItem[] }> {
    return { events: await this.devices.recentActivity(req.deviceSession.citizenId) };
  }
}
