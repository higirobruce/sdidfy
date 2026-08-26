/**
 * Tiny type-safe i18n lookup (05 §7).
 *
 * Deliberately dependency-free: no i18next, no Intl.MessageFormat. The whole
 * surface is three flat string tables and one interpolator, which keeps the
 * security path free of third-party code (05 §8: "minimal dependencies on the
 * security path") and keeps this module runnable under vitest with no RN.
 *
 * Kinyarwanda is the default AND the fallback: a missing key in `en`/`fr` is
 * impossible (they are typed `Messages`), but a missing *locale* falls back to
 * `rw` rather than to English.
 */
import { en } from './en.js';
import { fr } from './fr.js';
import { rw } from './rw.js';
import {
  DEFAULT_LOCALE,
  isLocale,
  LOCALES,
  type Locale,
  type MessageKey,
  type MessageParams,
  type Messages,
} from './types.js';

export { DEFAULT_LOCALE, isLocale, LOCALES };
export type { Locale, MessageKey, MessageParams, Messages };

export const RESOURCES: Record<Locale, Messages> = {
  rw: rw as unknown as Messages,
  en,
  fr,
};

/** Human names for the locale picker, always shown in their own language. */
export const LOCALE_NAMES: Record<Locale, string> = {
  rw: 'Ikinyarwanda',
  en: 'English',
  fr: 'Français',
};

const PLACEHOLDER = /\{(\w+)\}/g;

/**
 * Substitute `{name}` slots. An unknown placeholder is left verbatim rather
 * than replaced with "undefined" — a visible `{name}` is a bug report; a
 * silent "undefined" on a security prompt is a hazard.
 */
export function interpolate(template: string, params?: MessageParams): string {
  if (!params) return template;
  return template.replace(PLACEHOLDER, (match, key: string) => {
    const value = params[key];
    return value === undefined ? match : String(value);
  });
}

export interface Translator {
  readonly locale: Locale;
  t(key: MessageKey, params?: MessageParams): string;
}

export function createTranslator(locale: Locale = DEFAULT_LOCALE): Translator {
  const table = RESOURCES[locale] ?? RESOURCES[DEFAULT_LOCALE];
  return {
    locale,
    t(key: MessageKey, params?: MessageParams): string {
      // `key` is a compile-time union, so the only way `table[key]` is empty is
      // a runtime value that bypassed the types (e.g. a persisted key from an
      // older build). Fall back to Kinyarwanda, then to the key itself.
      const template = table[key] ?? RESOURCES[DEFAULT_LOCALE][key] ?? key;
      return interpolate(template, params);
    },
  };
}

/**
 * Resolve the device's preferred locale against what we support. Accepts the
 * BCP-47 tags RN's `NativeModules.SettingsManager` / `expo-localization`
 * return (e.g. `rw-RW`, `en-GB`, `fr_FR`), case-insensitively.
 * Anything unsupported → Kinyarwanda (05 §7), never English.
 */
export function resolveLocale(preferred: readonly string[] | undefined): Locale {
  for (const tag of preferred ?? []) {
    const primary = tag.toLowerCase().replace('_', '-').split('-')[0];
    if (isLocale(primary)) return primary;
  }
  return DEFAULT_LOCALE;
}

/**
 * Plain-language scope rendering (04 §3, T7). The broker also sends
 * `scopeDescriptions`, but those are English strings produced server-side —
 * showing them to the citizen would be exactly the "raw server string" the
 * approval screen must not display. So we localise every scope we know here,
 * and only fall back to the raw scope token for one we do not.
 */
export function scopeMessageKey(scope: string): MessageKey | null {
  switch (scope) {
    case 'openid':
      return 'scope.openid';
    case 'profile':
      return 'scope.profile';
    case 'address':
      return 'scope.address';
    default:
      return null;
  }
}

/** Localised scope label, falling back to the raw scope token (never server prose). */
export function describeScope(t: Translator, scope: string): string {
  const key = scopeMessageKey(scope);
  return key ? t.t(key) : scope;
}
