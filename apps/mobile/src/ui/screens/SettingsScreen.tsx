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
import { Button, Card, Screen } from '../components.js';
import { useApp } from '../context.js';
import { colors, spacing, typography } from '../theme.js';

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
        {LOCALES.map((code: Locale) => (
          <Button
            key={code}
            label={LOCALE_NAMES[code]}
            variant={code === locale ? 'primary' : 'secondary'}
            accessibilityHint={code === locale ? t.t('common.done') : undefined}
            onPress={() => setLocale(code)}
          />
        ))}
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

/** The very first screen on a fresh install. */
export function LanguageScreen({
  onChosen,
}: {
  onChosen: () => void;
}): React.ReactElement {
  const { t, locale, setLocale } = useApp();
  return (
    <Screen title={t.t('language.title')}>
      {LOCALES.map((code: Locale) => (
        <Button
          key={code}
          label={LOCALE_NAMES[code]}
          variant={code === locale ? 'primary' : 'secondary'}
          onPress={() => setLocale(code)}
        />
      ))}
      <Button label={t.t('common.continue')} onPress={onChosen} />
    </Screen>
  );
}

const styles = StyleSheet.create({
  heading: { ...typography.heading, color: colors.text },
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  actions: { gap: spacing.sm, marginTop: spacing.md },
});
