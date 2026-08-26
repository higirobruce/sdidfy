/**
 * App-wide context: the locale and the protocol client. RN-only.
 *
 * There is exactly one `ProtocolClient` per app instance — it owns the
 * in-memory session and the binding store, so a second instance would mean a
 * second session and a second set of biometric prompts.
 */
import React, { createContext, useContext, useMemo, useState } from 'react';
import type { ProtocolClient } from '../core/client.js';
import { createTranslator, DEFAULT_LOCALE, type Locale, type Translator } from '../i18n/index.js';

interface AppContextValue {
  client: ProtocolClient;
  t: Translator;
  locale: Locale;
  setLocale: (locale: Locale) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export interface AppProviderProps {
  client: ProtocolClient;
  /** Resolved from the device at start-up via `resolveLocale`. */
  initialLocale?: Locale;
  children: React.ReactNode;
}

export function AppProvider({
  client,
  initialLocale = DEFAULT_LOCALE,
  children,
}: AppProviderProps): React.ReactElement {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const value = useMemo<AppContextValue>(
    () => ({ client, locale, setLocale, t: createTranslator(locale) }),
    [client, locale],
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp(): AppContextValue {
  const value = useContext(AppContext);
  if (!value) throw new Error('useApp must be used inside <AppProvider>');
  return value;
}

/** Convenience: just the translator. */
export function useT(): Translator {
  return useApp().t;
}
