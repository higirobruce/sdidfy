/**
 * Shared UI primitives. RN-only.
 *
 * Every one of these takes ALREADY-LOCALISED text. Nothing in `src/ui`
 * contains an English literal a citizen can see — the i18n test enforces the
 * tables are complete, and review enforces this rule.
 */
import React, { useEffect, useRef, useState } from 'react';
import {
  AccessibilityInfo,
  Animated,
  ActivityIndicator,
  Easing,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import type { MobileError } from '../core/errors.js';
import { useT } from './context.js';
import { colors, MIN_TOUCH_TARGET, radius, spacing, typography } from './theme.js';

export type ButtonVariant = 'primary' | 'danger' | 'secondary';

export interface ButtonProps {
  label: string;
  onPress: () => void;
  variant?: ButtonVariant;
  disabled?: boolean;
  /** Screen-reader hint, already localised. */
  accessibilityHint?: string;
  style?: StyleProp<ViewStyle>;
}

export function Button({
  label,
  onPress,
  variant = 'primary',
  disabled = false,
  accessibilityHint,
  style,
}: ButtonProps): React.ReactElement {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      {...(accessibilityHint ? { accessibilityHint } : {})}
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        variant === 'primary' && styles.buttonPrimary,
        variant === 'danger' && styles.buttonDanger,
        variant === 'secondary' && styles.buttonSecondary,
        disabled && styles.buttonDisabled,
        pressed && styles.buttonPressed,
        style,
      ]}
    >
      <Text
        style={[
          styles.buttonLabel,
          variant === 'secondary' ? styles.buttonLabelDark : styles.buttonLabelLight,
        ]}
      >
        {label}
      </Text>
    </Pressable>
  );
}

export interface ScreenProps {
  title: string;
  children: React.ReactNode;
  scroll?: boolean;
}

export function Screen({ title, children, scroll = true }: ScreenProps): React.ReactElement {
  const body = (
    <View style={styles.screenBody}>
      <Text accessibilityRole="header" style={styles.screenTitle}>
        {title}
      </Text>
      {children}
    </View>
  );
  return scroll ? (
    <ScrollView style={styles.screen} contentContainerStyle={styles.screenContent}>
      {body}
    </ScrollView>
  ) : (
    <View style={[styles.screen, styles.screenContent]}>{body}</View>
  );
}

/**
 * Renders a `MobileError` through i18n. The error's `message`/`detail` are
 * developer strings and are NEVER shown (03 §7) — only `messageKey`.
 */
export function ErrorBanner({
  error,
  onRetry,
}: {
  error: MobileError | null;
  onRetry?: () => void;
}): React.ReactElement | null {
  const t = useT();
  if (!error) return null;
  return (
    <View accessibilityRole="alert" style={styles.errorBanner}>
      <Text style={styles.errorTitle}>{t.t('common.errorTitle')}</Text>
      <Text style={styles.errorBody}>{t.t(error.messageKey)}</Text>
      {error.userRetryable && onRetry ? (
        <Button label={t.t('common.retry')} variant="secondary" onPress={onRetry} />
      ) : null}
    </View>
  );
}

export function Busy({ label }: { label: string }): React.ReactElement {
  return (
    <View accessibilityRole="progressbar" accessibilityLabel={label} style={styles.busy}>
      <ActivityIndicator />
      <Text style={styles.busyLabel}>{label}</Text>
    </View>
  );
}

export function Card({
  children,
  style,
}: {
  children: React.ReactNode;
  style?: StyleProp<ViewStyle>;
}): React.ReactElement {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function Row({
  label,
  value,
}: {
  label: string;
  value: string;
}): React.ReactElement {
  return (
    <View style={styles.row} accessible accessibilityLabel={`${label}: ${value}`}>
      <Text style={styles.rowLabel}>{label}</Text>
      <Text style={styles.rowValue}>{value}</Text>
    </View>
  );
}

/**
 * Progress through a fixed sequence of screens (e.g. enrolment's
 * NID → consent → verify → done). Purely decorative reinforcement of
 * something the screen title already says, so it is hidden from screen
 * readers rather than announced twice.
 */
export function StepIndicator({
  steps,
  current,
}: {
  steps: number;
  /** 0-based index of the step in progress. */
  current: number;
}): React.ReactElement {
  return (
    <View
      style={styles.stepRow}
      accessibilityElementsHidden
      importantForAccessibility="no-hide-descendants"
    >
      {Array.from({ length: steps }, (_, i) => (
        <View
          key={i}
          style={[styles.step, i < current && styles.stepDone, i === current && styles.stepCurrent]}
        />
      ))}
    </View>
  );
}

/**
 * A code rendered as one box per character (T7's binding-message compare).
 * Purely visual: wrap this in a View carrying `accessible` +
 * `accessibilityLabel` with the spelled-out string, exactly as the plain-text
 * version did, so VoiceOver/TalkBack behaviour is unchanged.
 */
export function CodeChips({ code }: { code: string }): React.ReactElement {
  return (
    <View style={styles.codeRow} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
      {code.split('').map((char, i) => (
        <View key={i} style={styles.codeChip}>
          <Text style={styles.codeChipText}>{char}</Text>
        </View>
      ))}
    </View>
  );
}

const ARC_TICKS = 28;
const ARC_INDETERMINATE_FLOOR = 34;

/** Angle-and-push-out placement for one tick of {@link HorizonArc}. */
function tickStyle(index: number, total: number, radius_: number): ViewStyle {
  const degrees = (index / total) * 360;
  return { transform: [{ rotate: `${degrees}deg` }, { translateY: -radius_ }] };
}

/**
 * Loops a value from {@link ARC_INDETERMINATE_FLOOR} to 100 for as long as
 * `active` is true. Used when there is no real progress fraction to show
 * (the native enrolment call has no phase-by-phase signal — see
 * EnrolmentScreen) so the arc never claims a precision it doesn't have.
 * Skips the animation entirely when the OS reports reduced motion.
 */
function useIndeterminateArc(active: boolean): number {
  const [value, setValue] = useState(ARC_INDETERMINATE_FLOOR);
  const reduceMotion = useRef(false);

  useEffect(() => {
    let mounted = true;
    void AccessibilityInfo.isReduceMotionEnabled().then((reduced) => {
      if (mounted) reduceMotion.current = reduced;
    });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!active || reduceMotion.current) return undefined;
    const animated = new Animated.Value(ARC_INDETERMINATE_FLOOR);
    const subscription = animated.addListener(({ value: next }) => setValue(next));
    const loop = Animated.loop(
      Animated.timing(animated, {
        toValue: 100,
        duration: 2400,
        easing: Easing.inOut(Easing.quad),
        useNativeDriver: false,
      }),
    );
    loop.start();
    return () => {
      loop.stop();
      animated.removeListener(subscription);
    };
  }, [active]);

  return active ? value : 100;
}

export interface HorizonArcProps {
  size?: number;
  /**
   * 0–100. Omit for an indeterminate "still working" animation rather than
   * guessing a fraction the app doesn't actually know.
   */
  progress?: number;
  /** Already-localised caption below the arc. */
  label?: string;
}

/**
 * The app's one decorative signature: a ring of ticks that fills as
 * `progress` rises, standing in for the camera-frame/percentage HUD every
 * reference design reached for. Built from `View` + `Animated` only — no new
 * dependency, no SVG.
 */
export function HorizonArc({ size = 132, progress, label }: HorizonArcProps): React.ReactElement {
  const animated = useIndeterminateArc(progress === undefined);
  const value = Math.max(0, Math.min(100, progress ?? animated));
  const lit = Math.round((value / 100) * ARC_TICKS);
  const outerRadius = size / 2 - 6;

  // With a label, this is a progressbar announced once as a whole. Without
  // one (e.g. the fully-risen arc on the enrolment "done" screen, where the
  // surrounding text already says what happened) it's pure decoration and
  // must not surface 28 unlabeled tick views to a screen reader.
  const accessibilityProps = label
    ? { accessible: true as const, accessibilityRole: 'progressbar' as const, accessibilityLabel: label }
    : { accessibilityElementsHidden: true as const, importantForAccessibility: 'no-hide-descendants' as const };

  return (
    <View style={[styles.arcWrap, { width: size }]} {...accessibilityProps}>
      <View style={styles.arcFace}>
        {Array.from({ length: ARC_TICKS }, (_, i) => (
          <View
            key={i}
            style={[
              styles.arcTick,
              tickStyle(i, ARC_TICKS, outerRadius),
              { backgroundColor: i < lit ? colors.accent : colors.border },
            ]}
          />
        ))}
      </View>
      {label ? <Text style={styles.arcLabel}>{label}</Text> : null}
    </View>
  );
}

export type DeviceStatus = 'active' | 'pending' | 'revoked';

/**
 * Status as shape + label, never colour alone (the same rule the approve/deny
 * buttons follow) — a filled dot, a dashed ring, or a short dash, each paired
 * with its own text.
 */
export function StatusPill({ status, label }: { status: DeviceStatus; label: string }): React.ReactElement {
  const pillStyle =
    status === 'active' ? styles.pillActive : status === 'pending' ? styles.pillPending : styles.pillRevoked;
  const markStyle =
    status === 'active'
      ? styles.pillMarkActive
      : status === 'pending'
        ? styles.pillMarkPending
        : styles.pillMarkRevoked;
  const textStyle =
    status === 'active'
      ? styles.pillTextActive
      : status === 'pending'
        ? styles.pillTextPending
        : styles.pillTextRevoked;
  return (
    <View style={[styles.pill, pillStyle]} accessible accessibilityLabel={label}>
      <View style={[styles.pillMark, markStyle]} />
      <Text style={[styles.pillText, textStyle]}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.background },
  screenContent: { padding: spacing.md, paddingBottom: spacing.xl },
  screenBody: { gap: spacing.md },
  screenTitle: { ...typography.title, color: colors.text },
  button: {
    minHeight: MIN_TOUCH_TARGET,
    borderRadius: radius.pill,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
  },
  buttonPrimary: { backgroundColor: colors.primary },
  buttonDanger: { backgroundColor: colors.danger },
  buttonSecondary: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border },
  buttonDisabled: { opacity: 0.5 },
  buttonPressed: { opacity: 0.85 },
  buttonLabel: { ...typography.heading },
  buttonLabelLight: { color: colors.primaryText },
  buttonLabelDark: { color: colors.text },
  errorBanner: {
    backgroundColor: colors.warningSurface,
    borderColor: colors.warning,
    borderWidth: 1,
    borderRadius: radius.md,
    padding: spacing.md,
    gap: spacing.sm,
  },
  errorTitle: { ...typography.heading, color: colors.warning },
  errorBody: { ...typography.body, color: colors.text },
  busy: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  busyLabel: { ...typography.body, color: colors.textMuted },
  card: {
    backgroundColor: colors.surface,
    borderRadius: radius.lg,
    padding: spacing.md,
    gap: spacing.sm,
    borderWidth: 1,
    borderColor: colors.border,
  },
  row: { flexDirection: 'row', justifyContent: 'space-between', gap: spacing.md },
  rowLabel: { ...typography.small, color: colors.textMuted, flexShrink: 1 },
  rowValue: { ...typography.small, color: colors.text, fontWeight: '600', flexShrink: 1 },

  stepRow: { flexDirection: 'row', gap: spacing.xs },
  step: { flex: 1, height: 4, borderRadius: 3, backgroundColor: colors.border },
  stepDone: { backgroundColor: colors.primary },
  stepCurrent: { backgroundColor: colors.accent },

  codeRow: { flexDirection: 'row', gap: spacing.sm, justifyContent: 'center' },
  codeChip: {
    minWidth: 40,
    height: 52,
    borderRadius: radius.md,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: spacing.xs,
  },
  codeChipText: { ...typography.code, fontSize: 24, color: colors.code },

  arcWrap: { alignItems: 'center', justifyContent: 'center', gap: spacing.sm },
  arcFace: { width: '100%', aspectRatio: 1, alignItems: 'center', justifyContent: 'center' },
  arcTick: {
    position: 'absolute',
    width: 4,
    height: 10,
    borderRadius: 2,
    left: '50%',
    top: '50%',
    marginLeft: -2,
    marginTop: -5,
  },
  arcLabel: { ...typography.small, color: colors.textMuted, textAlign: 'center' },

  pill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    alignSelf: 'flex-start',
    paddingVertical: 3,
    paddingHorizontal: spacing.sm,
    borderRadius: radius.pill,
  },
  pillMark: { width: 7, height: 7, borderRadius: 4 },
  pillText: { ...typography.small, fontSize: 12, fontWeight: '700' as const },
  pillActive: { backgroundColor: colors.accentSurface },
  pillMarkActive: { backgroundColor: colors.accent },
  pillTextActive: { color: colors.success },
  pillPending: { backgroundColor: colors.surface },
  pillMarkPending: {
    backgroundColor: 'transparent',
    borderWidth: 1.5,
    borderStyle: 'dashed',
    borderColor: colors.textMuted,
    width: 6,
    height: 6,
  },
  pillTextPending: { color: colors.textMuted },
  pillRevoked: { backgroundColor: colors.surface },
  pillMarkRevoked: { backgroundColor: colors.danger, width: 7, height: 2, borderRadius: 1 },
  pillTextRevoked: { color: colors.danger },
});
