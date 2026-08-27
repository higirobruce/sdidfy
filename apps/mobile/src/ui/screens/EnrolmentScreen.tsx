/**
 * Enrolment: language → NID → consent → capture → progress → done (03 §2,
 * 05 §2). RN-only.
 *
 * Data-protection notes that are load-bearing, not cosmetic:
 *  - the NID lives in component state for the length of one enrolment and is
 *    never persisted, never logged, and never put in an analytics event (07 §1);
 *  - the face capture itself happens inside the native module — this screen
 *    never touches image bytes;
 *  - consent is explicit and itemised before any capture (08 §4);
 *  - on failure the citizen is told what to do next, never why the check failed
 *    (03 §7).
 */
import React, { useCallback, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';
import { toMobileError, type MobileError } from '../../core/errors.js';
import { Busy, Button, Card, ErrorBanner, Screen } from '../components.js';
import { useApp } from '../context.js';
import { colors, spacing, typography } from '../theme.js';

type Step = 'nid' | 'consent' | 'working' | 'done';

export interface EnrolmentScreenProps {
  deviceLabel: string;
  onEnrolled: () => void;
}

export function EnrolmentScreen({
  deviceLabel,
  onEnrolled,
}: EnrolmentScreenProps): React.ReactElement {
  const { t, client } = useApp();
  const [step, setStep] = useState<Step>('nid');
  const [nid, setNid] = useState('');
  const [assurance, setAssurance] = useState<string | null>(null);
  const [error, setError] = useState<MobileError | null>(null);

  const nidValid = /^\d{16}$/.test(nid);

  const run = useCallback(async () => {
    setStep('working');
    setError(null);
    try {
      const result = await client.enrol({ nid, deviceLabel });
      setAssurance(result.assuranceLevel);
      // Drop the NID from state the moment it is no longer needed.
      setNid('');
      setStep('done');
    } catch (caught) {
      setError(toMobileError(caught));
      setStep('consent');
    }
  }, [client, nid, deviceLabel]);

  if (step === 'working') {
    return (
      <Screen title={t.t('onboarding.welcomeTitle')}>
        {/* The steps are announced in order; the citizen sees that a security
            check, a key, a match and an activation are happening — not a
            featureless spinner. */}
        <Busy label={t.t('enrol.progress.attesting')} />
        <Text style={styles.muted}>{t.t('enrol.progress.generatingKey')}</Text>
        <Text style={styles.muted}>{t.t('enrol.progress.matching')}</Text>
        <Text style={styles.muted}>{t.t('enrol.progress.activating')}</Text>
      </Screen>
    );
  }

  if (step === 'done') {
    return (
      <Screen title={t.t('enrol.done.title')}>
        <Text style={styles.body}>{t.t('enrol.done.body')}</Text>
        {assurance ? (
          <Text style={styles.body}>{t.t('enrol.done.assurance', { level: assurance })}</Text>
        ) : null}
        <Button label={t.t('common.continue')} onPress={onEnrolled} />
      </Screen>
    );
  }

  if (step === 'consent') {
    return (
      <Screen title={t.t('enrol.consent.title')}>
        <Text style={styles.body}>{t.t('enrol.consent.body')}</Text>
        <Card>
          <Text style={styles.body}>{`• ${t.t('enrol.consent.point.match')}`}</Text>
          <Text style={styles.body}>{`• ${t.t('enrol.consent.point.noStore')}`}</Text>
          <Text style={styles.body}>{`• ${t.t('enrol.consent.point.deviceKey')}`}</Text>
          <Text style={styles.body}>{`• ${t.t('enrol.consent.point.revoke')}`}</Text>
        </Card>
        <Text style={styles.body}>{t.t('enrol.capture.instruction')}</Text>
        <Text style={styles.muted}>{t.t('enrol.capture.liveness')}</Text>
        <ErrorBanner error={error} onRetry={() => void run()} />
        <View style={styles.actions}>
          <Button label={t.t('enrol.consent.agree')} onPress={() => void run()} />
          <Button
            label={t.t('enrol.consent.decline')}
            variant="secondary"
            onPress={() => setStep('nid')}
          />
        </View>
      </Screen>
    );
  }

  return (
    <Screen title={t.t('enrol.nid.title')}>
      <Text style={styles.body}>{t.t('onboarding.welcomeBody')}</Text>
      <View>
        <Text style={styles.label} nativeID="nid-label">
          {t.t('enrol.nid.label')}
        </Text>
        <TextInput
          accessibilityLabel={t.t('enrol.nid.label')}
          accessibilityLabelledBy="nid-label"
          accessibilityHint={t.t('enrol.nid.help')}
          keyboardType="number-pad"
          maxLength={16}
          value={nid}
          onChangeText={(value) => setNid(value.replace(/\D/g, ''))}
          style={styles.input}
          // Never offer to remember or autofill a national ID number.
          autoComplete="off"
          textContentType="none"
        />
        <Text style={styles.muted}>{t.t('enrol.nid.help')}</Text>
        <Text style={styles.muted}>{t.t('enrol.nid.privacyNote')}</Text>
        {nid.length > 0 && !nidValid ? (
          <Text accessibilityRole="alert" style={styles.invalid}>
            {t.t('enrol.nid.invalid')}
          </Text>
        ) : null}
      </View>
      <Button
        label={t.t('common.continue')}
        disabled={!nidValid}
        onPress={() => setStep('consent')}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  label: { ...typography.small, color: colors.textMuted, marginBottom: spacing.xs },
  invalid: { ...typography.small, color: colors.danger, marginTop: spacing.xs },
  input: {
    ...typography.body,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    padding: spacing.md,
    color: colors.text,
    letterSpacing: 2,
  },
  actions: { gap: spacing.sm },
});
