/**
 * `KeyStore` backed by the `SdidKeyStore` native module. RN-only.
 * Native requirements: ./CONTRACT.md §1. None of that Swift/Kotlin exists yet.
 */
import type {
  GenerateKeyOptions,
  GeneratedKey,
  KeySecurityLevel,
  KeyStore,
  KeyStoreCapabilities,
  SignPromptSpec,
} from '../core/keystore.js';
import type { PublicKeyJwk } from '../core/types.js';
import type { SdidKeyStoreNativeModule } from './contract.js';
import { nativeCall, requireModule } from './modules.rn.js';

/** Anything the native side does not report as hardware is `software` — fail closed. */
function toSecurityLevel(value: string): KeySecurityLevel {
  return value === 'strongbox' || value === 'tee' ? value : 'software';
}

export class NativeKeyStore implements KeyStore {
  private readonly module: SdidKeyStoreNativeModule;

  constructor(module?: SdidKeyStoreNativeModule) {
    this.module = module ?? requireModule<SdidKeyStoreNativeModule>('SdidKeyStore');
  }

  async capabilities(): Promise<KeyStoreCapabilities> {
    const caps = await nativeCall(
      () => this.module.capabilities(),
      'secure_hardware_unavailable',
    );
    return {
      available: caps.available,
      securityLevel: toSecurityLevel(caps.securityLevel),
      supportsKeyAttestation: caps.supportsKeyAttestation,
    };
  }

  async hasKey(alias: string): Promise<boolean> {
    return nativeCall(() => this.module.hasKey(alias), 'keystore_failed');
  }

  async generate(options: GenerateKeyOptions): Promise<GeneratedKey> {
    // The challenge crosses as the nonce STRING; the native side takes its
    // UTF-8 bytes for setAttestationChallenge (runbook §10). '' means none.
    const result = await nativeCall(
      () => this.module.generate(options.alias, options.attestationChallenge ?? ''),
      'keystore_failed',
    );
    return {
      alias: options.alias,
      publicJwk: { kty: 'EC', crv: 'P-256', x: result.publicKeyX, y: result.publicKeyY },
      securityLevel: toSecurityLevel(result.securityLevel),
      ...(result.keyAttestation !== undefined ? { keyAttestation: result.keyAttestation } : {}),
    };
  }

  async exportPublicJwk(alias: string): Promise<PublicKeyJwk> {
    const { publicKeyX, publicKeyY } = await nativeCall(
      () => this.module.exportPublicKey(alias),
      'keystore_failed',
    );
    return { kty: 'EC', crv: 'P-256', x: publicKeyX, y: publicKeyY };
  }

  /**
   * One prompt, one signature, one payload (05 §3, T1). The prompt is raised
   * by the platform inside this call — there is no separate unlock step.
   * Returns base64url raw r||s; the native side is responsible for the
   * DER → r||s conversion (CONTRACT.md §1.4).
   */
  async sign(alias: string, payload: string, prompt: SignPromptSpec): Promise<string> {
    return nativeCall(
      () =>
        this.module.sign(
          alias,
          payload,
          prompt.title,
          prompt.subtitle ?? '',
          prompt.cancelLabel,
        ),
      'keystore_failed',
    );
  }

  async delete(alias: string): Promise<void> {
    await nativeCall(() => this.module.deleteKey(alias), 'keystore_failed');
  }
}
