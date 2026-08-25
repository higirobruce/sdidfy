// @sdid/device-sim — simulated citizen phone (SPEC 05, Phase 0–2 stand-in):
// hardware-style keypair, mock attestation + biometric capture, enrolment,
// direct login and CIBA approvals against the broker.
export {
  SimDevice,
  buildChallengePayload,
  type SimDeviceOptions,
  type BiometricSampleDto,
  type CaptureOverrides,
  type MockAttestationDto,
  type AttestationClaimOverrides,
  type EnrolOptions,
  type EnrolResult,
  type DecideOptions,
  type DecisionResult,
  type PublicKeyJwk,
} from './sim-device.js';
