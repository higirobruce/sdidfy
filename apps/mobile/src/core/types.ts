/**
 * Shapes the core client passes around. Wire DTOs live in @sdid/shared and are
 * re-used directly — the app and the broker must never drift on those.
 */
import { z } from 'zod';
import { publicKeyJwkSchema, type AssuranceLevel } from '@sdid/shared';

/** EC P-256 public key, exactly the shape `enrolStartRequestSchema` accepts. */
export type PublicKeyJwk = z.infer<typeof publicKeyJwkSchema>;

/**
 * What the app persists between launches.
 *
 * Note what is ABSENT: the citizen's NID (never written to the device — it is
 * used once, in one request, at enrolment: 07 §1/§3 in spirit), the biometric
 * sample, and the session token (short-lived, kept in memory only, so a stolen
 * backup or a filesystem dump yields nothing usable). The device private key
 * is not here either — it lives in secure hardware and is referenced by alias.
 */
export interface PersistedBinding {
  bindingId: string;
  keyAlias: string;
  deviceLabel: string;
  assuranceLevel: AssuranceLevel;
  enrolledAt: string;
}

/**
 * Where `PersistedBinding` is kept. On device this is the platform keychain /
 * EncryptedSharedPreferences, not AsyncStorage — none of it is secret, but it
 * is identity-linked, so it should be excluded from cloud backup along with
 * the key itself (05 §3).
 */
export interface BindingStore {
  load(): Promise<PersistedBinding | null>;
  save(binding: PersistedBinding): Promise<void>;
  clear(): Promise<void>;
}

/** In-memory BindingStore — tests, and the "not yet enrolled" default. */
export class MemoryBindingStore implements BindingStore {
  private value: PersistedBinding | null = null;

  async load(): Promise<PersistedBinding | null> {
    return this.value;
  }

  async save(binding: PersistedBinding): Promise<void> {
    this.value = { ...binding };
  }

  async clear(): Promise<void> {
    this.value = null;
  }
}

/** Injectable clock so TTL/countdown logic is testable without fake timers. */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };
