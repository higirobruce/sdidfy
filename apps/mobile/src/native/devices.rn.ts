/**
 * Attestation, biometric prompt and face capture backed by their native
 * modules. RN-only. Native requirements: ./CONTRACT.md §2–§4.
 */
import type { AttestInput, Attestation, AttestationPlatform } from '../core/attestation.js';
import type {
  BiometricCapabilities,
  BiometricConfirmSpec,
  BiometricPrompt,
  BiometryKind,
  EnrolmentSample,
  FaceCapture,
  FaceCaptureOptions,
} from '../core/biometrics.js';
import { MobileError } from '../core/errors.js';
import type { AttestationPayload, BiometricSampleDto } from '../core/wire.js';
import type {
  SdidAttestationNativeModule,
  SdidBiometricsNativeModule,
  SdidFaceCaptureNativeModule,
} from './contract.js';
import { nativeCall, requireModule } from './modules.rn.js';

// ── Attestation (CONTRACT.md §2) ────────────────────────────────────────────

export class NativeAttestation implements Attestation {
  private readonly module: SdidAttestationNativeModule;

  constructor(
    private readonly platformId: AttestationPlatform,
    module?: SdidAttestationNativeModule,
  ) {
    this.module = module ?? requireModule<SdidAttestationNativeModule>('SdidAttestation');
  }

  platform(): AttestationPlatform {
    return this.platformId;
  }

  async attest(input: AttestInput): Promise<Omit<AttestationPayload, 'nonceId'>> {
    const result = await nativeCall(
      () => this.module.attest(input.nonce, input.keyAlias),
      'attestation_failed_local',
    );
    if (result.platform !== 'android' && result.platform !== 'ios') {
      // `sim` is mock-only and is refused by the broker in strict mode; a
      // native module claiming it would be a build mistake, not a device fact.
      throw MobileError.local('attestation_failed_local', {
        detail: `unexpected_platform=${result.platform}`,
      });
    }
    return {
      platform: result.platform,
      token: result.token,
      // Android forwards the chain from key generation; iOS has none — the
      // App Attest object IS the key attestation.
      ...(result.keyAttestation ?? input.keyAttestation
        ? { keyAttestation: (result.keyAttestation ?? input.keyAttestation)! }
        : {}),
    };
  }
}

// ── Biometric prompt (CONTRACT.md §3) ───────────────────────────────────────

const KNOWN_KINDS: BiometryKind[] = ['face', 'fingerprint', 'iris'];

export class NativeBiometricPrompt implements BiometricPrompt {
  private readonly module: SdidBiometricsNativeModule;

  constructor(module?: SdidBiometricsNativeModule) {
    this.module = module ?? requireModule<SdidBiometricsNativeModule>('SdidBiometrics');
  }

  async capabilities(): Promise<BiometricCapabilities> {
    const caps = await nativeCall(() => this.module.capabilities(), 'biometric_unavailable');
    return {
      available: caps.available,
      enrolled: caps.enrolled,
      strong: caps.strong,
      kinds: caps.kinds.filter((k): k is BiometryKind =>
        (KNOWN_KINDS as string[]).includes(k),
      ),
    };
  }

  /** Presentation only — never authorisation for a signature (05 §3). */
  async confirm(spec: BiometricConfirmSpec): Promise<boolean> {
    return nativeCall(
      () => this.module.confirm(spec.title, spec.subtitle ?? '', spec.cancelLabel),
      'biometric_failed',
    );
  }

  /** 05 §9: warn on screen recording / overlay during approval. */
  async isScreenCompromised(): Promise<boolean> {
    try {
      return await this.module.isScreenCompromised();
    } catch {
      // Unknown is not "compromised": a fabricated warning trains citizens to
      // ignore the real one. The platform-can't-tell case is documented.
      return false;
    }
  }
}

// ── Face capture (CONTRACT.md §4) ───────────────────────────────────────────

/**
 * Wraps one native capture. `dispose()` calls `release()` so the NATIVE buffer
 * is zeroed — the JS-side base64 string cannot be zeroed (JS strings are
 * immutable); see CONTRACT.md §4 for that stated limitation.
 */
class NativeEnrolmentSample implements EnrolmentSample {
  private disposed = false;

  constructor(
    private readonly dto: BiometricSampleDto,
    private readonly module: SdidFaceCaptureNativeModule,
  ) {}

  toDto(): BiometricSampleDto {
    if (this.disposed) {
      throw MobileError.local('unknown', { detail: 'sample_used_after_dispose' });
    }
    return this.dto;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    // Fire-and-forget: the caller is in a `finally` and must not be blocked,
    // but the native buffer must go regardless of what happens above.
    void this.module.release().catch(() => undefined);
  }
}

export class NativeFaceCapture implements FaceCapture {
  private readonly module: SdidFaceCaptureNativeModule;

  constructor(module?: SdidFaceCaptureNativeModule) {
    this.module = module ?? requireModule<SdidFaceCaptureNativeModule>('SdidFaceCapture');
  }

  async capture(options: FaceCaptureOptions): Promise<EnrolmentSample> {
    const result = await nativeCall(
      () => this.module.capture(options.instruction, options.cancelLabel),
      'biometric_unavailable',
    );
    return new NativeEnrolmentSample(
      {
        modality: 'face',
        data: result.data,
        liveness: { method: result.livenessMethod, score: result.livenessScore },
      },
      this.module,
    );
  }
}
