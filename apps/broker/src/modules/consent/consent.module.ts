import { Module } from '@nestjs/common';
import { ConsentService } from './consent.service.js';

/**
 * Consent domain (spec 04 §5): shared consent registry service. Devices
 * endpoints (list/revoke) and the protocol modules record grants through —
 * or alongside — this service; the audit trail is the source of truth.
 */
@Module({
  providers: [ConsentService],
  exports: [ConsentService],
})
export class ConsentModule {}
