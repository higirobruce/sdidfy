import { Global, Module } from '@nestjs/common';
import { ChallengeService } from './challenge.service.js';
import { SignatureService } from './signature.service.js';
import { PairwiseService } from './pairwise.service.js';
import { RateLimitService } from './rate-limit.service.js';
import { AttestationService } from './attestation.service.js';
import {
  ATTESTATION_VERIFIERS,
  attestationVerifiersProvider,
} from './attestation-verifiers.provider.js';
import { DeviceSessionGuard } from './device-session.guard.js';
import { ReverificationService } from './reverification.service.js';

@Global()
@Module({
  providers: [
    attestationVerifiersProvider,
    ChallengeService,
    SignatureService,
    PairwiseService,
    RateLimitService,
    AttestationService,
    DeviceSessionGuard,
    ReverificationService,
  ],
  exports: [
    ATTESTATION_VERIFIERS,
    ChallengeService,
    SignatureService,
    PairwiseService,
    RateLimitService,
    AttestationService,
    DeviceSessionGuard,
    ReverificationService,
  ],
})
export class TrustModule {}
