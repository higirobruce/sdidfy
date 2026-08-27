/**
 * Activity log — the citizen's view of the append-only audit trail
 * (05 §2, 07 §4, 08 §5 "access"). RN-only.
 *
 * The broker sends raw audit action strings (`auth.login_succeeded`). Those are
 * machine identifiers, not citizen-facing prose: they are mapped to localised
 * labels here and an unknown one falls back to a generic label rather than
 * being printed raw (03 §7).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { toMobileError, type MobileError } from '../../core/errors.js';
import type { ActivityItem } from '../../core/wire.js';
import type { MessageKey } from '../../i18n/types.js';
import { Button, Card, ErrorBanner, ResultPill, Screen, type ActivityResult } from '../components.js';
import { useApp } from '../context.js';
import { formatTime } from './HomeScreen.js';
import { colors, spacing, typography } from '../theme.js';

/** Broker audit action (packages/shared/src/audit.ts) → localised label. */
export function activityActionKey(action: string): MessageKey {
  switch (action) {
    case 'enrolment.binding_created':
    case 'enrolment.binding_activated':
      return 'activity.action.enrolled';
    case 'auth.login_succeeded':
    case 'auth.login_failed':
      return 'activity.action.login';
    case 'ciba.request_approved':
      return 'activity.action.approved';
    case 'ciba.request_denied':
      return 'activity.action.denied';
    case 'device.revoked':
      return 'activity.action.revoked';
    case 'consent.granted':
      return 'activity.action.consentGranted';
    case 'consent.revoked':
      return 'activity.action.consentRevoked';
    default:
      return 'activity.action.other';
  }
}

export function activityResultKey(result: string): MessageKey {
  switch (result) {
    case 'success':
      return 'activity.result.success';
    case 'denied':
      return 'activity.result.denied';
    default:
      return 'activity.result.failure';
  }
}

/** Same three-way funnel as {@link activityResultKey}, for the pill's tone. */
function activityResult(result: string): ActivityResult {
  switch (result) {
    case 'success':
      return 'success';
    case 'denied':
      return 'denied';
    default:
      return 'failure';
  }
}

export interface ActivityScreenProps {
  onBack: () => void;
}

export function ActivityScreen({ onBack }: ActivityScreenProps): React.ReactElement {
  const { t, client } = useApp();
  const [events, setEvents] = useState<ActivityItem[]>([]);
  const [error, setError] = useState<MobileError | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setEvents(await client.activity());
    } catch (caught) {
      setError(toMobileError(caught));
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Screen title={t.t('activity.title')}>
      <ErrorBanner error={error} onRetry={() => void load()} />
      {events.length === 0 && !error ? <Text style={styles.muted}>{t.t('activity.empty')}</Text> : null}
      {events.map((event) => (
        <Card key={`${event.ts}-${event.action}-${event.result}`}>
          <View style={styles.eventHeader}>
            <Text style={styles.heading}>{t.t(activityActionKey(event.action))}</Text>
            <ResultPill result={activityResult(event.result)} label={t.t(activityResultKey(event.result))} />
          </View>
          <Text style={styles.muted}>{formatTime(event.ts)}</Text>
          {event.rpName ? <Text style={styles.body}>{event.rpName}</Text> : null}
        </Card>
      ))}
      <View style={styles.actions}>
        <Button label={t.t('common.back')} variant="secondary" onPress={onBack} />
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  heading: { ...typography.heading, color: colors.text, flexShrink: 1 },
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  eventHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: spacing.sm,
  },
  actions: { marginTop: spacing.md },
});
