/**
 * Settings: language, about, help/report (05 §2, 05 §7). RN-only.
 *
 * The language picker is also the FIRST screen a new install shows, before
 * anything else, so a citizen who reads only Kinyarwanda is never asked to
 * navigate an English screen to find it (05 §7).
 */
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { LOCALE_NAMES, LOCALES, type Locale } from '../../i18n/index.js';
import { Button, Card, HorizonArc, Screen, SelectableCard } from '../components.js';
import { useApp } from '../context.js';
import { colors, fonts, spacing, typography } from '../theme.js';

export interface SettingsScreenProps {
  appVersion: string;
  onBack: () => void;
  onOpenHelp: () => void;
}

export function SettingsScreen({
  appVersion,
  onBack,
  onOpenHelp,
}: SettingsScreenProps): React.ReactElement {
  const { t, locale, setLocale } = useApp();

  return (
    <Screen title={t.t('settings.title')}>
      <Card>
        <Text accessibilityRole="header" style={styles.heading}>
          {t.t('settings.language')}
        </Text>
        <View style={styles.choices}>
          {LOCALES.map((code: Locale) => (
            <SelectableCard
              key={code}
              label={LOCALE_NAMES[code]}
              selected={code === locale}
              onPress={() => setLocale(code)}
            />
          ))}
        </View>
      </Card>

      <Card>
        <Text accessibilityRole="header" style={styles.heading}>
          {t.t('settings.about')}
        </Text>
        <Text style={styles.body}>{t.t('settings.version', { version: appVersion })}</Text>
        <Text style={styles.body}>{t.t('settings.privacy')}</Text>
        <Text style={styles.muted}>{t.t('enrol.consent.point.noStore')}</Text>
        <Text style={styles.muted}>{t.t('enrol.consent.point.deviceKey')}</Text>
      </Card>

      <View style={styles.actions}>
        <Button label={t.t('settings.help')} variant="secondary" onPress={onOpenHelp} />
        <Button label={t.t('common.back')} variant="secondary" onPress={onBack} />
      </View>
    </Screen>
  );
}

/**
 * The very first screen on a fresh install — the one moment every citizen
 * sees before anything else, so it gets its own layout rather than the
 * generic list-screen `Screen` wrapper: a mark, a headline, the choice
 * itself, and a single unmistakable action pinned to the bottom.
 */
export function LanguageScreen({
  onChosen,
}: {
  onChosen: () => void;
}): React.ReactElement {
  const { t, locale, setLocale } = useApp();
  return (
    <View style={languageStyles.root}>
      <View style={languageStyles.header}>
        <HorizonArc size={64} progress={70} />
        <Text style={languageStyles.eyebrow}>{t.t('common.appName')}</Text>
        <Text accessibilityRole="header" style={languageStyles.title}>
          {t.t('language.title')}
        </Text>
      </View>

      <View style={languageStyles.choices}>
        {LOCALES.map((code: Locale) => (
          <SelectableCard
            key={code}
            label={LOCALE_NAMES[code]}
            selected={code === locale}
            onPress={() => setLocale(code)}
          />
        ))}
      </View>

      <View style={languageStyles.spacer} />

      <Button label={t.t('common.continue')} onPress={onChosen} />
    </View>
  );
}

const styles = StyleSheet.create({
  heading: { ...typography.heading, color: colors.text },
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  choices: { gap: spacing.sm },
  actions: { gap: spacing.sm, marginTop: spacing.md },
});

const languageStyles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background, padding: spacing.lg },
  header: { alignItems: 'center', gap: spacing.sm, marginTop: spacing.xl, marginBottom: spacing.xl },
  eyebrow: {
    ...typography.small,
    fontFamily: fonts.bold,
    color: colors.textMuted,
    textTransform: 'uppercase',
    letterSpacing: 1.5,
    marginTop: spacing.sm,
  },
  title: { ...typography.display, color: colors.text, textAlign: 'center' },
  choices: { gap: spacing.sm },
  spacer: { flex: 1 },
});
