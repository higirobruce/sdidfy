import { Global, Injectable, Logger, Module } from '@nestjs/common';

/**
 * Wake-only push (05 §5, T6): the payload carries NO auth data — the device
 * pulls pending requests over the authenticated backchannel. Dev/sim
 * implementation logs the wake; FCM/APNs transports plug in behind this
 * interface in Phase 2 without touching callers.
 */
@Injectable()
export class PushService {
  private readonly logger = new Logger('PushService');

  async wake(citizenId: string): Promise<void> {
    // Deliberately no transaction detail in the payload — wake-only (T6).
    this.logger.log(`wake citizen=${citizenId}`);
  }
}

@Global()
@Module({
  providers: [PushService],
  exports: [PushService],
})
export class PushModule {}
