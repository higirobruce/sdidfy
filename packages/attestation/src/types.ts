/**
 * Attestation verification contract (SPEC 05 §4, 06 T2/T3, decision 10 #4).
 *
 * Two independent questions are answered here, and conflating them is a
 * security bug:
 *
 *   1. **Platform attestation** — is this a genuine, unmodified build of our
 *      app, running on a device that is not rooted, jailbroken or emulated?
 *      (Play Integrity on Android, App Attest on iOS.)
 *   2. **Hardware key attestation** — does the specific keypair being enrolled
 *      actually live in secure hardware (StrongBox / TEE / Secure Enclave),
 *      non-exportable?
 *
 * A device can pass (1) and fail (2): a genuine app on a sound phone can still
 * hand us a software-held key. AL2 requires both (03 §3), so the verdict
 * reports them separately and the assurance cap is derived, never asserted by
 * the caller.
 *
 * Three bindings must hold for a verdict to mean anything. Each has defeated
 * real deployments when omitted:
 *
 *   - **Nonce binding** (T4): the attestation must carry a single-use,
 *     server-issued nonce. Without it, a token harvested from one genuine
 *     device replays from an attacker's device forever.
 *   - **Key binding**: the hardware key attestation must be over *the public
 *     key being enrolled*. Without it, an attacker attests a real hardware key
 *     and then enrols a different, software-held one.
 *   - **Identity binding**: the token must name *our* app — package name +
 *     signing-certificate digest on Android, App ID on iOS. Without it, any
 *     app's valid attestation is accepted.
 *
 * Verifiers are pure with respect to time and network: the clock arrives via
 * `now`, and any remote call (Play Integrity's decode API) sits behind an
 * injected seam. That keeps the security logic deterministically testable.
 */

/** Hardware protection level for the enrolled key, in ascending order of trust. */
export type KeySecurityLevel =
  /** No credible evidence the key is in hardware — treat as software-held. */
  | 'software'
  /** Trusted Execution Environment (Android TEE, iOS Secure Enclave). */
  | 'trusted-environment'
  /** Dedicated secure element (Android StrongBox). */
  | 'strongbox';

/** Why an attestation was refused. Stable codes — audited and alerted on. */
export type AttestationRejectionCode =
  /** Structurally unparseable: bad CBOR/DER/JWT/base64. */
  | 'malformed'
  /** Nonce absent, mismatched, or not the one we issued (replay). */
  | 'nonce_mismatch'
  /** Attestation is for a different app than ours. */
  | 'app_mismatch'
  /** Certificate chain did not verify to the expected platform root. */
  | 'chain_invalid'
  /** Device is rooted, jailbroken, emulated, or otherwise fails integrity. */
  | 'device_integrity'
  /** App binary is not the Play/App Store recognised build. */
  | 'app_integrity'
  /** Key attestation does not cover the public key being enrolled. */
  | 'key_mismatch'
  /** Token is older than the freshness window. */
  | 'stale'
  /** Verifier could not reach the platform service (fail closed, retryable). */
  | 'verifier_unavailable';

export interface AttestationRejected {
  ok: false;
  code: AttestationRejectionCode;
  /**
   * Operator-facing detail. NEVER surfaced to the client verbatim: a precise
   * reason tells an attacker which control to work around next (03 §7 keeps
   * client-visible enrolment failures uniform).
   */
  detail: string;
}

export interface AttestationAccepted {
  ok: true;
  platform: 'android' | 'ios';
  /** Passed platform integrity: genuine app, sound device. */
  appGenuine: true;
  /** Proven protection level of the enrolled key. */
  keySecurityLevel: KeySecurityLevel;
  /**
   * Highest assurance this device may carry from attestation alone (03 §3,
   * 06 §6). AL3 additionally needs SDID re-assertion at auth time, so the cap
   * here is AL2 at most. A software-held key caps at AL1 even on a sound
   * device.
   */
  assuranceCap: 'AL1' | 'AL2';
  /**
   * Non-sensitive facts worth persisting on the binding for audit and later
   * policy review (07): verdict strings, security level, app version. Never
   * contains the raw token, certificates, or any citizen identifier.
   */
  evidence: Record<string, unknown>;
}

export type AttestationResult = AttestationAccepted | AttestationRejected;

/** What the verifier is asked to prove, and against what. */
export interface AttestationRequest {
  /** Platform token: Play Integrity JWE/JWS (Android) or base64 CBOR (iOS). */
  token: string;
  /**
   * Hardware key attestation, where the platform supplies it separately:
   * Android returns an X.509 chain (base64 DER, leaf first). On iOS the key
   * attestation is inseparable from the App Attest object itself, so this is
   * omitted and `token` carries both.
   */
  keyAttestation?: string;
  /**
   * The exact single-use nonce this broker issued for this enrolment. The
   * verifier compares it against the value inside the signed token — it never
   * trusts a nonce echoed back outside the signature.
   */
  expectedNonce: string;
  /**
   * The public key about to be bound (03 §2 step 7). Hardware key attestation
   * is checked to cover THIS key; a mismatch is `key_mismatch`, never a
   * downgrade to AL1.
   */
  devicePublicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  /** Injected clock (epoch ms) so freshness checks are deterministic in tests. */
  now: number;
}

/**
 * One platform's verifier. Implementations MUST fail closed: any doubt is a
 * rejection, never a downgrade, and no exception escapes as an acceptance.
 */
export interface AttestationVerifier {
  readonly platform: 'android' | 'ios';
  verify(request: AttestationRequest): Promise<AttestationResult>;
}

/** How long after issuance a platform token is still accepted (T4). */
export const DEFAULT_MAX_TOKEN_AGE_MS = 5 * 60 * 1000;

/**
 * Decodes a Play Integrity token into its verdict payload. Google's
 * `playintegrity.googleapis.com/v1/{pkg}:decodeIntegrityToken` is the
 * supported path and needs service-account credentials, so it is injected
 * rather than dialled directly: unit tests supply a fake, and the broker
 * supplies a real client once GoR service-account credentials exist. Returning
 * an unvalidated `unknown` is deliberate — the verifier owns schema validation
 * so a compromised or changed upstream shape cannot walk straight into a
 * verdict.
 */
export type PlayIntegrityTokenDecoder = (token: string) => Promise<unknown>;

export interface AndroidVerifierConfig {
  /** Our app's package name; anything else is `app_mismatch`. */
  packageName: string;
  /**
   * base64 SHA-256 digests of the app-signing certificates we accept.
   * Empty is a configuration error, not "accept any".
   */
  certificateDigests: readonly string[];
  decodeToken: PlayIntegrityTokenDecoder;
  /**
   * Require StrongBox rather than any TEE for AL2. Off by default: StrongBox
   * is absent on much of the Android install base and a hard requirement would
   * exclude many citizens (08 inclusion).
   */
  requireStrongBox?: boolean;
}

export interface IosVerifierConfig {
  /** Apple App ID: `<teamId>.<bundleId>`; anything else is `app_mismatch`. */
  appId: string;
  /**
   * false accepts the development aaguid (`appattestdevelop`). Production
   * config must set true, or a dev-provisioned build attests successfully
   * against production.
   */
  production: boolean;
  /**
   * PEM roots for the App Attest chain. Defaults to Apple's published App
   * Attest root CA when omitted.
   */
  rootCertificatesPem?: readonly string[];
}

export interface AttestationVerifierConfig {
  android: AndroidVerifierConfig;
  ios: IosVerifierConfig;
  /** Overrides DEFAULT_MAX_TOKEN_AGE_MS. */
  maxTokenAgeMs?: number;
}

/** Verifier set, keyed by the platform the client declares. */
export interface AttestationVerifiers {
  android: AttestationVerifier;
  ios: AttestationVerifier;
}
