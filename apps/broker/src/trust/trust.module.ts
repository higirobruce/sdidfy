import { Global, Module } from '@nestjs/common';
import { ChallengeService } from './challenge.service.js';
import { SignatureService } from './signature.service.js';
import { PairwiseService } from './pairwise.service.js';
import { RateLimitService } from './rate-limit.service.js';
import { AttestationService } from './attestation.service.js';

@Global()
@Module({
  providers: [ChallengeService, SignatureService, PairwiseService, RateLimitService, AttestationService],
  exports: [ChallengeService, SignatureService, PairwiseService, RateLimitService, AttestationService],
})
export class TrustModule {}
