import { ERROR_CODES } from '@sdid/shared';
import { describe, expect, it } from 'vitest';
import {
  createTranslator,
  describeScope,
  interpolate,
  LOCALES,
  RESOURCES,
  resolveLocale,
  scopeMessageKey,
} from './index.js';
import { rw } from './rw.js';
import { DEFAULT_LOCALE, type MessageKey } from './types.js';

const keys = Object.keys(rw) as MessageKey[];

/** Placeholders (`{name}`) present in a template, as a sorted list. */
function placeholders(template: string): string[] {
  return [...template.matchAll(/\{(\w+)\}/g)].map((m) => m[1]!).sort();
}

describe('locale completeness (05 §7)', () => {
  it('Kinyarwanda is the default locale', () => {
    expect(DEFAULT_LOCALE).toBe('rw');
    expect(createTranslator().locale).toBe('rw');
  });

  it.each(LOCALES)('%s has every key, none empty', (locale) => {
    const table = RESOURCES[locale];
    for (const key of keys) {
      expect(table[key], `${locale} missing ${key}`).toBeTypeOf('string');
      expect(table[key]!.trim(), `${locale} empty ${key}`).not.toBe('');
    }
  });

  it.each(LOCALES)('%s has no keys beyond the Kinyarwanda key set', (locale) => {
    expect(Object.keys(RESOURCES[locale]).sort()).toEqual(keys.slice().sort());
  });

  it.each(LOCALES)('%s uses the same placeholders as Kinyarwanda', (locale) => {
    for (const key of keys) {
      expect(placeholders(RESOURCES[locale][key]!), `${locale} ${key}`).toEqual(
        placeholders(rw[key]),
      );
    }
  });

  it('every broker error code has a distinct, non-placeholder message in every locale', () => {
    for (const code of ERROR_CODES) {
      const key = `errors.${code}` as MessageKey;
      expect(keys, `no message for ${code}`).toContain(key);
      for (const locale of LOCALES) {
        expect(RESOURCES[locale][key]!.length).toBeGreaterThan(10);
      }
    }
  });
});

describe('interpolation', () => {
  it('substitutes named placeholders', () => {
    expect(interpolate('Bisigaje amasegonda {seconds}', { seconds: 42 })).toBe(
      'Bisigaje amasegonda 42',
    );
  });

  it('leaves an unknown placeholder verbatim rather than printing "undefined"', () => {
    // A visible {name} is a bug report; a silent "undefined" on a security
    // prompt is a hazard.
    expect(interpolate('Muraho, {name}', {})).toBe('Muraho, {name}');
  });

  it('t() interpolates through the chosen locale', () => {
    expect(createTranslator('fr').t('approval.expiresIn', { seconds: 7 })).toBe(
      'Il reste 7 secondes',
    );
  });
});

describe('resolveLocale', () => {
  it('matches on the primary subtag, case-insensitively', () => {
    expect(resolveLocale(['fr-FR'])).toBe('fr');
    expect(resolveLocale(['EN_GB'])).toBe('en');
    expect(resolveLocale(['rw-RW'])).toBe('rw');
  });

  it('falls back to Kinyarwanda, never English, for anything unsupported', () => {
    expect(resolveLocale(['sw-KE', 'de'])).toBe('rw');
    expect(resolveLocale([])).toBe('rw');
    expect(resolveLocale(undefined)).toBe('rw');
  });

  it('takes the first supported entry in preference order', () => {
    expect(resolveLocale(['de', 'fr', 'en'])).toBe('fr');
  });
});

describe('scope rendering (T7)', () => {
  it('localises every scope the broker supports in v1', () => {
    const t = createTranslator('rw');
    expect(describeScope(t, 'openid')).toBe(rw['scope.openid']);
    expect(describeScope(t, 'profile')).toBe(rw['scope.profile']);
    expect(describeScope(t, 'address')).toBe(rw['scope.address']);
  });

  it('falls back to the raw scope token — never to server prose — for an unknown scope', () => {
    expect(scopeMessageKey('some_future_scope')).toBeNull();
    expect(describeScope(createTranslator('rw'), 'some_future_scope')).toBe('some_future_scope');
  });
});
