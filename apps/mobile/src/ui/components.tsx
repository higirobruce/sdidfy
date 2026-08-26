/**
 * Shared UI primitives. RN-only.
 *
 * Every one of these takes ALREADY-LOCALISED text. Nothing in `src/ui`
 * contains an English literal a citizen can see — the i18n test enforces the
 * tables are complete, and review enforces this rule.
 */
import React from 'react';
import {
  ActivityIndicator,
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
import { colors, MIN_TOUCH_TARGET, spacing, typography } from './theme.js';

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

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.background },
  screenContent: { padding: spacing.md, paddingBottom: spacing.xl },
  screenBody: { gap: spacing.md },
  screenTitle: { ...typography.title, color: colors.text },
  button: {
    minHeight: MIN_TOUCH_TARGET,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: spacing.md,
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
    borderRadius: 10,
    padding: spacing.md,
    gap: spacing.sm,
  },
  errorTitle: { ...typography.heading, color: colors.warning },
  errorBody: { ...typography.body, color: colors.text },
  busy: { flexDirection: 'row', alignItems: 'center', gap: spacing.sm },
  busyLabel: { ...typography.body, color: colors.textMuted },
  card: {
    backgroundColor: colors.surface,
    borderRadius: 12,
    padding: spacing.md,
    gap: spacing.sm,
    borderWidth: 1,
    borderColor: colors.border,
  },
  row: { flexDirection: 'row', justifyContent: 'space-between', gap: spacing.md },
  rowLabel: { ...typography.small, color: colors.textMuted, flexShrink: 1 },
  rowValue: { ...typography.small, color: colors.text, fontWeight: '600', flexShrink: 1 },
});
