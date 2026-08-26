/**
 * NativeModules lookup + error translation. RN-only (excluded from tsconfig).
 *
 * A missing native module is a HARD failure, not a soft fallback: the whole
 * point of this app is that signing happens in secure hardware, so an app that
 * quietly runs without `SdidKeyStore` would be a security theatre build.
 */
import { NativeModules } from 'react-native';
import { MobileError, type LocalErrorCode } from '../core/errors.js';
import { NATIVE_ERROR_MAP, type NativeRejection } from './contract.js';

export function requireModule<T>(name: string): T {
  const found = (NativeModules as Record<string, unknown>)[name];
  if (!found) {
    // Fail closed and say exactly which module is absent — this is a build
    // error a developer sees, never a citizen-facing string.
    throw MobileError.local('unknown', {
      detail: `native module ${name} is not linked; see src/native/CONTRACT.md`,
    });
  }
  return found as T;
}

/**
 * Translate a native rejection into a MobileError. An unrecognised code maps
 * to `fallback` — never optimistically to something benign.
 */
export function translateNativeError(error: unknown, fallback: LocalErrorCode): MobileError {
  const code = (error as NativeRejection | undefined)?.code;
  const mapped =
    typeof code === 'string'
      ? (NATIVE_ERROR_MAP as Record<string, LocalErrorCode | undefined>)[code]
      : undefined;
  return MobileError.local(mapped ?? fallback, {
    // The native code string is a fixed enum, so it is safe to keep for the
    // developer log. The native `message` is NOT kept — it is free text that
    // could name a control (03 §7).
    detail: typeof code === 'string' ? `native:${code}` : 'native:unknown',
    cause: error,
  });
}

/** Wrap a native call so every rejection leaves as a MobileError. */
export async function nativeCall<T>(
  fn: () => Promise<T>,
  fallback: LocalErrorCode,
): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    throw translateNativeError(error, fallback);
  }
}
