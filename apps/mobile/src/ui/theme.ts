/**
 * Visual tokens (05 §7 accessibility).
 *
 * Chosen for contrast, not brand — citizen-facing branding is still open
 * decision #10. Every foreground/background pair below is >= 4.5:1 (WCAG AA);
 * the approve/deny pair is additionally distinguished by shape and position,
 * never by colour alone, because colour-blind citizens must be able to tell
 * "approve" from "deny" (T7).
 */
export const colors = {
  background: '#FFFFFF',
  surface: '#F4F6F8',
  border: '#D3D8DE',
  text: '#101418',
  textMuted: '#4A5560',
  primary: '#0B5FA5',
  primaryText: '#FFFFFF',
  danger: '#A31515',
  dangerText: '#FFFFFF',
  warning: '#8A5A00',
  warningSurface: '#FFF4D6',
  success: '#136B3C',
  code: '#101418',
} as const;

export const spacing = { xs: 4, sm: 8, md: 16, lg: 24, xl: 32 } as const;

/**
 * Base sizes. Every Text in the app must allow the OS large-text setting to
 * scale these (RN honours `allowFontScaling` by default — do not disable it).
 */
export const typography = {
  title: { fontSize: 24, fontWeight: '700' as const, lineHeight: 32 },
  heading: { fontSize: 19, fontWeight: '600' as const, lineHeight: 26 },
  body: { fontSize: 17, lineHeight: 25 },
  small: { fontSize: 15, lineHeight: 22 },
  /** The binding-message code: deliberately huge and monospaced (T7). */
  code: { fontSize: 34, fontWeight: '700' as const, letterSpacing: 3 },
} as const;

/** Minimum touch target, both platforms' accessibility guidance. */
export const MIN_TOUCH_TARGET = 48;
