/**
 * Home: device status, pending approvals, recent activity (05 §2). RN-only.
 *
 * Pending requests are discovered by PULLING over the authenticated
 * backchannel — a push wake just triggers the same pull (T6). Until the broker
 * exposes a device-token endpoint, this poll IS the delivery mechanism
 * (runbook §1).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { RefreshControl, ScrollView, StyleSheet, Text, View } from 'react-native';
import type { ActivityItem } from '../../core/wire.js';
import { toMobileError, type MobileError } from '../../core/errors.js';
import { collapsePending, type PendingGroup } from '../../core/pending.js';
import type { PersistedBinding } from '../../core/types.js';
import { Button, Card, ErrorBanner, Screen } from '../components.js';
import { useApp } from '../context.js';
import { activityActionKey } from './ActivityScreen.js';
import { colors, spacing, typography } from '../theme.js';

/** How often to pull while the app is in the foreground. */
const POLL_INTERVAL_MS = 5_000;

export interface HomeScreenProps {
  onOpenApproval: (group: PendingGroup, totalGroups: number) => void;
  onOpenDevices: () => void;
  onOpenActivity: () => void;
  onOpenSettings: () => void;
}

export function HomeScreen({
  onOpenApproval,
  onOpenDevices,
  onOpenActivity,
  onOpenSettings,
}: HomeScreenProps): React.ReactElement {
  const { t, client } = useApp();
  const [binding, setBinding] = useState<PersistedBinding | null>(null);
  const [groups, setGroups] = useState<PendingGroup[]>([]);
  const [recent, setRecent] = useState<ActivityItem[]>([]);
  const [error, setError] = useState<MobileError | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      setBinding(await client.currentBinding());
      setGroups(collapsePending(await client.pullPending(), Date.now()));
      setRecent((await client.activity()).slice(0, 5));
    } catch (caught) {
      setError(toMobileError(caught));
    }
  }, [client]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <ScrollView
      style={styles.container}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          onRefresh={() => {
            setRefreshing(true);
            void refresh().finally(() => setRefreshing(false));
          }}
        />
      }
    >
      <Screen title={t.t('home.title')} scroll={false}>
        <ErrorBanner error={error} onRetry={() => void refresh()} />

        <Card>
          <Text style={styles.body}>
            {binding ? t.t('home.deviceStatus.active') : t.t('errors.not_enrolled')}
          </Text>
          {binding ? (
            <Text style={styles.muted}>
              {`${t.t('home.assuranceLabel')}: ${binding.assuranceLevel}`}
            </Text>
          ) : null}
        </Card>

        {groups.length === 0 ? (
          <Text style={styles.muted}>{t.t('home.noPending')}</Text>
        ) : (
          <View style={styles.pending}>
            <Text accessibilityRole="header" style={styles.heading}>
              {t.t('home.pendingCount', { count: groups.length })}
            </Text>
            {groups.map((group) => (
              <Card key={group.primary.authReqId} style={styles.pendingCard}>
                <Text style={styles.heading}>{group.primary.rpName}</Text>
                {group.primary.bindingMessage ? (
                  <Text style={styles.body}>{group.primary.bindingMessage}</Text>
                ) : null}
                <Button
                  label={t.t('common.continue')}
                  onPress={() => onOpenApproval(group, groups.length)}
                />
              </Card>
            ))}
          </View>
        )}

        <Text accessibilityRole="header" style={styles.heading}>
          {t.t('home.recentActivity')}
        </Text>
        {recent.length === 0 ? (
          <Text style={styles.muted}>{t.t('activity.empty')}</Text>
        ) : (
          recent.map((event) => (
            <Text key={`${event.ts}-${event.action}`} style={styles.body}>
              {`${formatTime(event.ts)} · ${t.t(activityActionKey(event.action))}`}
            </Text>
          ))
        )}

        <View style={styles.actions}>
          <Button label={t.t('home.viewAll')} variant="secondary" onPress={onOpenActivity} />
          <Button label={t.t('home.devices')} variant="secondary" onPress={onOpenDevices} />
          <Button label={t.t('home.settings')} variant="secondary" onPress={onOpenSettings} />
        </View>
      </Screen>
    </ScrollView>
  );
}

/**
 * Dates and times follow the device locale (05 §7: "full localisation …
 * dates"). `Intl` is available in Hermes with `intl` enabled — see README.
 */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.background },
  heading: { ...typography.heading, color: colors.text },
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  pending: { gap: spacing.sm },
  pendingCard: { borderColor: colors.accent },
  actions: { gap: spacing.sm, marginTop: spacing.md },
});
