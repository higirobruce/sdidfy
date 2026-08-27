import { Inject, Injectable } from '@nestjs/common';
import { and, eq, ne, sql } from 'drizzle-orm';
import {
  BridgeError,
  uuidv7,
  zeroize,
  type BiometricSample,
  type EnrolActivateRequest,
  type EnrolActivateResponse,
  type EnrolStartRequest,
  type EnrolStartResponse,
  type AttestationChallengeResponse,
  type MatchEngine,
  type MatchResult,
  type ReferenceBiometricResult,
  type SdidProvider,
} from '@sdid/shared';
import { AnomalyService } from '../../anomaly/anomaly.service.js';
import { DbService } from '../../db/db.module.js';
import { citizens, deviceBindings } from '../../db/schema.js';
import { AuditService } from '../../audit/audit.service.js';
import { MetricsService } from '../../observability/metrics.service.js';
import {
  AttestationRejectionError,
  AttestationService,
  type AttestationVerdict,
} from '../../trust/attestation.service.js';
import { ChallengeService } from '../../trust/challenge.service.js';
import { PairwiseService } from '../../trust/pairwise.service.js';
import { RateLimitService } from '../../trust/rate-limit.service.js';
import { SignatureService } from '../../trust/signature.service.js';
import { MATCH_ENGINE, SDID_PROVIDER } from '../../sdid/sdid.module.js';

/** Multi-device cap (decision #3: N capped, 3–5 → we use 5). */
export const MAX_ACTIVE_BINDINGS = 5;

/** Enrolment failure lockout: 5 failures / 15 min window (03 §7). */
const ENROL_MAX_FAILURES = 5;
const ENROL_FAILURE_WINDOW_SECONDS = 900;

/**
 * Attestation-nonce mints per IP per hour. Deliberately above the 20/h
 * enrolment ceiling (a genuine app may mint and then abandon — user cancels,
 * attestation fails locally, network drops) but bounded: an unauthenticated
 * mint is free work for the broker.
 */
const ATTESTATION_NONCE_IP_LIMIT = 60;

/**
 * Detect adapter errors defensively by error name (duck-typed), so this module
 * never hard-depends on adapter internals beyond the SdidProvider contract —
 * any provider (the real adapter, a test fake, a future strategy) matches by
 * name alone. `SdidUnavailableError` has three subtypes — timeout, circuit-open,
 * malformed-response (02 §4) — each of which OVERRIDES `.name`, so all four
 * names must be recognised here; matching only the base name would mis-map the
 * common outage paths (timeout / open breaker / malformed response) to HTTP 500
 * instead of 503. Keep this list in sync with the adapter's unavailable subtypes.
 */
const SDID_UNAVAILABLE_ERROR_NAMES = new Set([
  'SdidUnavailableError',
  'SdidTimeoutError',
  'SdidCircuitOpenError',
  'SdidMalformedResponseError',
]);
function isSdidUnknownIdentityError(err: unknown): boolean {
  return err instanceof Error && err.name === 'SdidUnknownIdentityError';
}
function isSdidUnavailableError(err: unknown): boolean {
  return err instanceof Error && SDID_UNAVAILABLE_ERROR_NAMES.has(err.name);
}

/**
 * Enrolment + device binding (spec 03 §2): the one moment the bridge handles
 * biometric bytes. CARDINAL RULE (07 §1): the decoded sample and NIDA's
 * reference exist in memory for this single request only — never logged,
 * never audited, never persisted — and are zeroized on every exit path.
 */
@Injectable()
export class EnrolmentService {
  constructor(
    private readonly dbService: DbService,
    private readonly audit: AuditService,
    private readonly attestation: AttestationService,
    private readonly challenges: ChallengeService,
    private readonly pairwise: PairwiseService,
    private readonly rateLimit: RateLimitService,
    private readonly signatures: SignatureService,
    private readonly metrics: MetricsService,
    private readonly anomaly: AnomalyService,
    @Inject(SDID_PROVIDER) private readonly sdid: SdidProvider,
    @Inject(MATCH_ENGINE) private readonly matchEngine: MatchEngine,
  ) {}

  /**
   * Mint a single-use attestation nonce (03 §2 step 1, T4). Unauthenticated by
   * necessity — it precedes every enrolment — which makes it a free-work
   * endpoint (Redis write + audit row per call), so it is rate-limited per IP
   * exactly like `/v1/enrol/start`. No identity exists yet, so nothing here is
   * bound to a citizen and the audit row carries no subject.
   */
  async attestationChallenge(ip: string): Promise<AttestationChallengeResponse> {
    await this.rateLimit.hit(`enrol:attest:ip:${ip}`, ATTESTATION_NONCE_IP_LIMIT, 3600);
    const nonce = await this.challenges.issueAttestationNonce();
    await this.audit.append({
      actor: { type: 'citizen' },
      action: 'auth.challenge_issued',
      result: 'success',
      // The nonce VALUE is never audited — only that one was minted.
      context: { purpose: 'attestation', nonceId: nonce.nonceId },
    });
    return nonce;
  }

  async start(req: EnrolStartRequest, ip: string): Promise<EnrolStartResponse> {
    const pseudoNid = this.pairwise.pseudoNid(req.nid);

    // Anomaly signal BEFORE the rate limits (06 §5, T14): probing is measured
    // in DISTINCT identities per source, and a limit that refuses the 21st
    // attempt would otherwise hide the 30 different NIDs behind it. Detection
    // only — nothing here refuses anything.
    await this.anomaly.recordEnrolmentAttempt(ip, pseudoNid);

    // Anti-automation (T14): per-NID and per-IP fixed windows, plus the
    // failure lockout accumulated by recordFailure below.
    await this.rateLimit.hit(`enrol:nid:${pseudoNid}`, 5, 3600);
    await this.rateLimit.hit(`enrol:ip:${ip}`, 20, 3600);
    await this.rateLimit.assertNotLockedOut(`enrol:nid:${pseudoNid}`, ENROL_MAX_FAILURES);

    // Attestation gate (03 §2 step 1) — failures are audited with the pseudo
    // ref (no citizen row exists yet) and rethrown as-is. The device public
    // key goes in because the verdict is only meaningful if the hardware key
    // attestation covers THE KEY WE ARE ABOUT TO BIND: without that check an
    // attacker attests a real hardware key and enrols a software-held one.
    let verdict: AttestationVerdict;
    try {
      verdict = await this.attestation.verify(req.attestation, req.devicePublicKeyJwk);
    } catch (err) {
      await this.audit.append({
        actor: { type: 'citizen' },
        action: 'enrolment.failed',
        subjectRef: pseudoNid,
        result: 'failure',
        context: {
          reason: 'attestation_rejected',
          platform: req.attestation.platform,
          // The client saw one uniform message (03 §7); the trail gets the
          // precise verifier code and detail, which is where they belong.
          ...(err instanceof AttestationRejectionError
            ? { code: err.rejectionCode, detail: err.rejectionDetail }
            : { detail: err instanceof BridgeError ? err.message : 'attestation error' }),
        },
      });
      if (err instanceof AttestationRejectionError) {
        this.metrics.recordEnrolmentAttempt('attestation_rejected');
        // T2/T3: a source producing rejection after rejection is a rooted-
        // device farm — or a broken app release. Detection only.
        await this.anomaly.recordAttestationRejection(ip, err.rejectionCode);
      } else if (err instanceof BridgeError && err.code === 'attestation_unavailable') {
        // OUR outage, not their attack: never counted as an abuse signal.
        this.metrics.recordEnrolmentAttempt('attestation_unavailable');
      } else {
        this.metrics.recordEnrolmentAttempt('error');
      }
      throw err;
    }

    // v1 is face-only self-service (appendix D1): phone fingerprint sensors
    // cannot produce a print matchable against NIDA.
    if (req.sample.modality === 'fingerprint') {
      this.metrics.recordEnrolmentAttempt('modality_unsupported');
      throw new BridgeError(
        'invalid_request',
        'Fingerprint enrolment is not supported; use face',
        400,
      );
    }

    // --- Biometric window opens: bytes live only inside this block (07 §1). ---
    const sampleBytes = new Uint8Array(Buffer.from(req.sample.data, 'base64'));
    let reference: ReferenceBiometricResult | undefined;
    let matchResult: MatchResult;
    let sdidTxnRef: string | undefined;
    try {
      const sample: BiometricSample = {
        modality: req.sample.modality,
        data: sampleBytes,
        liveness: req.sample.liveness,
      };
      try {
        reference = await this.sdid.getReferenceBiometric({
          nid: req.nid,
          modality: req.sample.modality,
        });
      } catch (err) {
        if (isSdidUnknownIdentityError(err)) {
          // Anti-probing (03 §7): an unknown NID is indistinguishable from a
          // failed match — same audit action, same lockout, same generic error.
          throw await this.failEnrolment(pseudoNid, 'sdid_identity_not_matchable');
        }
        if (isSdidUnavailableError(err)) {
          this.metrics.recordEnrolmentAttempt('sdid_unavailable');
          throw new BridgeError('sdid_unavailable', 'Identity authority unavailable', 503);
        }
        throw err;
      }
      sdidTxnRef = reference.txnRef;
      // The match engine zeroizes sample + reference bytes before resolving;
      // we retain no references to them past this call.
      matchResult = await this.matchEngine.match(sample, reference.reference);
    } finally {
      // Defensive belt-and-braces: on any exit path (including errors before
      // the engine ran) the buffers are overwritten. Zeroizing twice is a no-op.
      zeroize(sampleBytes, reference?.reference.data);
    }
    // --- Biometric window closed: only MatchResult + txnRef survive. ---

    // Score BAND only, and with no subject label of any kind (07 §4, T18):
    // band distribution over time is how a matching-engine regression or an
    // evasion campaign becomes visible, and it is the most that can be
    // published about a biometric comparison without publishing a biometric.
    this.metrics.recordBiometricMatch(matchResult);

    await this.audit.append({
      actor: { type: 'citizen' },
      action: 'enrolment.match_completed',
      subjectRef: pseudoNid,
      matchResult: {
        matched: matchResult.matched,
        scoreBand: matchResult.scoreBand,
        padPassed: matchResult.padPassed,
      },
      sdidTxnRef,
      result: matchResult.matched && matchResult.padPassed ? 'success' : 'failure',
    });

    if (!matchResult.matched || !matchResult.padPassed) {
      throw await this.failEnrolment(
        pseudoNid,
        matchResult.padPassed ? 'match_failed' : 'pad_failed',
        sdidTxnRef,
      );
    }

    // Upsert the citizen reference row (07 §2 — pseudo_nid only, no PII).
    const [citizen] = await this.dbService.db
      .insert(citizens)
      .values({ id: uuidv7(), pseudoNid, sdidSubject: reference!.sdidSubject })
      .onConflictDoUpdate({
        target: citizens.pseudoNid,
        set: { sdidSubject: reference!.sdidSubject, updatedAt: new Date() },
      })
      .returning({ id: citizens.id });
    const citizenId = citizen!.id;

    // Multi-device cap (decision #3): max 5 non-revoked bindings.
    const [{ count }] = (await this.dbService.db
      .select({ count: sql<number>`count(*)::int` })
      .from(deviceBindings)
      .where(
        and(eq(deviceBindings.citizenId, citizenId), ne(deviceBindings.status, 'revoked')),
      )) as [{ count: number }];
    if (count >= MAX_ACTIVE_BINDINGS) {
      this.metrics.recordEnrolmentAttempt('device_limit_reached');
      await this.audit.append({
        actor: { type: 'citizen', id: citizenId },
        action: 'enrolment.failed',
        subjectRef: citizenId,
        result: 'failure',
        context: { reason: 'device_limit_reached', limit: MAX_ACTIVE_BINDINGS },
      });
      throw new BridgeError('invalid_request', 'Device limit reached', 409);
    }

    const bindingId = uuidv7();
    const assuranceLevel = verdict.assuranceCap;
    await this.dbService.db.insert(deviceBindings).values({
      id: bindingId,
      citizenId,
      devicePubkeyJwk: req.devicePublicKeyJwk,
      attestation: {
        platform: verdict.platform,
        hardwareBacked: verdict.hardwareBacked,
        assuranceCap: verdict.assuranceCap,
        detail: verdict.detail,
        // Verifier evidence (verdict strings, key security level, app
        // version) — never the raw token or any certificate (07 §1/§3).
        ...(verdict.evidence !== undefined ? { evidence: verdict.evidence } : {}),
      },
      assuranceLevel,
      status: 'pending',
      deviceLabel: req.deviceLabel,
    });

    await this.audit.append({
      actor: { type: 'citizen', id: citizenId },
      action: 'enrolment.binding_created',
      subjectRef: citizenId,
      deviceBindingId: bindingId,
      assurance: assuranceLevel,
      sdidTxnRef,
      result: 'success',
    });

    // Proof-of-possession challenge (03 §2 steps 8–10).
    const activationChallenge = await this.challenges.issue({ kind: 'activation' }, bindingId);
    // The binding exists and the challenge is out; activation is a separate
    // request, so `success` here means "the biometric proofing leg passed".
    this.metrics.recordEnrolmentAttempt('success');

    return {
      bindingId,
      assuranceLevel,
      activationChallenge: {
        challengeId: activationChallenge.challengeId,
        nonce: activationChallenge.nonce,
        payload: activationChallenge.payload,
        expiresAt: activationChallenge.expiresAt,
      },
    };
  }

  /**
   * Shared failure path for no-match / PAD-fail / unknown NID: audit, count
   * toward lockout, and return the ONE generic user-facing error (03 §7 —
   * the server-side audit carries the specifics, the citizen never does).
   */
  private async failEnrolment(
    pseudoNid: string,
    reason: 'match_failed' | 'pad_failed' | 'sdid_identity_not_matchable',
    sdidTxnRef?: string,
  ): Promise<BridgeError> {
    this.metrics.recordEnrolmentAttempt(
      reason === 'sdid_identity_not_matchable' ? 'identity_not_matchable' : reason,
    );
    await this.audit.append({
      actor: { type: 'citizen' },
      action: 'enrolment.failed',
      subjectRef: pseudoNid,
      sdidTxnRef,
      result: 'failure',
      context: { reason },
    });
    await this.rateLimit.recordFailure(
      `enrol:nid:${pseudoNid}`,
      ENROL_MAX_FAILURES,
      ENROL_FAILURE_WINDOW_SECONDS,
    );
    return new BridgeError('enrolment_failed', 'Enrolment could not be completed', 403);
  }

  /** Activation: proof of possession of the enrolled private key (03 §2 step 9–10). */
  async activate(req: EnrolActivateRequest): Promise<EnrolActivateResponse> {
    const rows = await this.dbService.db
      .select()
      .from(deviceBindings)
      .where(eq(deviceBindings.id, req.bindingId));
    const binding = rows[0];
    if (!binding) throw new BridgeError('binding_not_found', 'Unknown device binding', 404);
    if (binding.status !== 'pending') {
      throw new BridgeError('binding_not_active', 'Binding is not awaiting activation', 409);
    }

    // Single-use challenge (T4) — consumed atomically before verification.
    const payload = await this.challenges.consume(
      req.challengeId,
      { kind: 'activation' },
      req.bindingId,
    );
    await this.signatures.verifyDeviceSignature(
      binding.devicePubkeyJwk as { kty: string; crv: string; x: string; y: string },
      payload,
      req.signature,
      'activation',
    );

    await this.dbService.db
      .update(deviceBindings)
      .set({ status: 'active', activatedAt: new Date() })
      .where(eq(deviceBindings.id, req.bindingId));

    await this.audit.append({
      actor: { type: 'citizen', id: binding.citizenId },
      action: 'enrolment.binding_activated',
      subjectRef: binding.citizenId,
      deviceBindingId: binding.id,
      assurance: binding.assuranceLevel as 'AL1' | 'AL2' | 'AL3',
      result: 'success',
    });

    return { bindingId: binding.id, status: 'active' };
  }
}
