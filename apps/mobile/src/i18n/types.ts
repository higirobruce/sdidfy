import { rw } from './rw.js';

/**
 * The canonical message-key union, derived from the Kinyarwanda table so that
 * Kinyarwanda is structurally first (05 §7) and every other locale is checked
 * against it at compile time.
 */
export type MessageKey = keyof typeof rw;

/** A complete locale table. `Record` (not Partial) — no locale may be short. */
export type Messages = Record<MessageKey, string>;

export const LOCALES = ['rw', 'en', 'fr'] as const;
export type Locale = (typeof LOCALES)[number];

/** Kinyarwanda is the default and the fallback for any missing string. */
export const DEFAULT_LOCALE: Locale = 'rw';

export function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && (LOCALES as readonly string[]).includes(value);
}

/** Values substituted into `{placeholder}` slots. */
export type MessageParams = Record<string, string | number>;
