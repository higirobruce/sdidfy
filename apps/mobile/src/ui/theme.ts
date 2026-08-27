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
 * Base sizes. Every Text in the app must allow the OS large-text setting to
 * scale these (RN honours `allowFontScaling` by default — do not disable it).
 */
export const typography = {
  display: { fontSize: 28, fontWeight: '800' as const, lineHeight: 34, letterSpacing: -0.3 },
  title: { fontSize: 24, fontWeight: '700' as const, lineHeight: 32 },
  heading: { fontSize: 19, fontWeight: '600' as const, lineHeight: 26 },
  body: { fontSize: 17, lineHeight: 25 },
  small: { fontSize: 15, lineHeight: 22 },
  /** The binding-message code: deliberately huge and monospaced (T7). */
  code: { fontSize: 34, fontWeight: '700' as const, letterSpacing: 3 },
} as const;

/** Minimum touch target, both platforms' accessibility guidance. */
export const MIN_TOUCH_TARGET = 48;
