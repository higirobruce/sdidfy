/**
 * Visual tokens (05 §7 accessibility).
 *
 * Chosen for contrast, not brand — citizen-facing branding is still open
 * decision #10. Every foreground/background pair below is >= 4.5:1 (WCAG AA);
 * the approve/deny pair is additionally distinguished by shape and position,
 * never by colour alone, because colour-blind citizens must be able to tell
 * "approve" from "deny" (T7).
 *
 * `danger`, `dangerText`, `warning`, `warningSurface`, `success` and `code`
 * are load-bearing on that guarantee and are UNCHANGED from the values
 * originally verified — do not retune them without re-checking contrast.
 * `background`, `surface`, `border`, `text`, `textMuted` and `primary` are
 * refined neutrals/blue with the same contrast profile as before. `accent`
 * is new: a decorative colour for the "horizon arc" motif (capture progress,
 * the fingerprint mark) and nothing else — it never carries meaning on its
 * own, so it is exempt from the never-colour-alone rule above.
 */
export const colors = {
  background: '#F3F6F8',
  surface: '#E7EDF0',
  border: '#D2DBE0',
  text: '#12181F',
  textMuted: '#55636B',
  primary: '#0B5A82',
  primaryText: '#FFFFFF',
  /** Light tint of `primary` — a selected-but-not-a-submit-action state (SelectableCard), distinct from the accent's decorative-only role below. */
  primarySurface: '#E4EEF3',
  accent: '#3F8F6E',
  accentSurface: '#E3F1EA',
  danger: '#A31515',
  dangerText: '#FFFFFF',
  warning: '#8A5A00',
  warningSurface: '#FFF4D6',
  success: '#136B3C',
  code: '#101418',
} as const;

export const spacing = { xs: 4, sm: 8, md: 16, lg: 24, xl: 32 } as const;

/** Corner radii. `pill` is large enough to round any button height fully. */
export const radius = { sm: 8, md: 12, lg: 16, pill: 999 } as const;

/**
 * Plus Jakarta Sans, across every text role — not just titles. Three weights
 * cover the whole app; nothing here falls back to the OS system font anymore.
 *
 * These family names only resolve once something in the app has loaded them
 * via `expo-font`'s `useFonts` (see the app entry point, not this file) — an
 * unloaded family name falls back to the system font silently, so nothing
 * here breaks before that wiring exists.
 *
 * Never combine one of these with `fontWeight` — the named family already
 * bakes in its weight, and pairing both makes the OS fake-bold/fake-lighten a
 * face that doesn't have that variant. Reach for `fonts.semiBold`/`fonts.bold`
 * directly instead of `{ fontWeight: '600' }` on top of a regular family.
 */
export const fonts = {
  regular: 'PlusJakartaSans_400Regular',
  semiBold: 'PlusJakartaSans_600SemiBold',
  bold: 'PlusJakartaSans_700Bold',
} as const;

/**
 * Base sizes. Every Text in the app must allow the OS large-text setting to
 * scale these (RN honours `allowFontScaling` by default — do not disable it).
 */
export const typography = {
  display: { fontFamily: fonts.bold, fontSize: 30, lineHeight: 36, letterSpacing: -0.2 },
  title: { fontFamily: fonts.semiBold, fontSize: 25, lineHeight: 32 },
  heading: { fontFamily: fonts.semiBold, fontSize: 19, lineHeight: 26 },
  body: { fontFamily: fonts.regular, fontSize: 17, lineHeight: 25 },
  small: { fontFamily: fonts.regular, fontSize: 15, lineHeight: 22 },
  /** The binding-message code: deliberately huge (T7). */
  code: { fontFamily: fonts.bold, fontSize: 36, letterSpacing: 3 },
} as const;

/** Minimum touch target, both platforms' accessibility guidance. */
export const MIN_TOUCH_TARGET = 48;
