/**
 * Devices + consents: list, revoke (03 §4/§5, 04 §5, 05 §2). RN-only.
 *
 * Revocation is a two-tap, explicitly-confirmed action because it is
 * irreversible for this device — the private key is destroyed and recovery is
 * a full re-enrolment with a live biometric (03 §5). That is a feature, and the
 * confirmation text says so.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import type { DeviceListItem } from '@sdid/shared';
import { toMobileError, type MobileError } from '../../core/errors.js';
import type { ConsentListItem } from '../../core/wire.js';
import type { PersistedBinding } from '../../core/types.js';
import { describeScope } from '../../i18n/index.js';
import type { MessageKey } from '../../i18n/types.js';
import { Button, Card, ErrorBanner, Row, Screen } from '../components.js';
import { useApp } from '../context.js';
import { formatTime } from './HomeScreen.js';
import { colors, spacing, typography } from '../theme.js';

function statusKey(status: DeviceListItem['status']): MessageKey {
  switch (status) {
    case 'active':
      return 'devices.status.active';
    case 'revoked':
      return 'devices.status.revoked';
    default:
      return 'devices.status.pending';
  }
}

export interface DevicesScreenProps {
  onBack: () => void;
  /** Called when the citizen revokes THIS device — the app returns to enrolment. */
  onSelfRevoked: () => void;
}

export function DevicesScreen({ onBack, onSelfRevoked }: DevicesScreenProps): React.ReactElement {
  const { t, client } = useApp();
  const [devices, setDevices] = useState<DeviceListItem[]>([]);
  const [consents, setConsents] = useState<ConsentListItem[]>([]);
  const [self, setSelf] = useState<PersistedBinding | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<MobileError | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSelf(await client.currentBinding());
      setDevices(await client.listBindings());
      setConsents(await client.listConsents());
    } catch (caught) {
      setError(toMobileError(caught));
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = useCallback(
    async (bindingId: string) => {
      setConfirming(null);
      try {
        const wasSelf = self?.bindingId === bindingId;
        await client.revokeBinding(bindingId);
        if (wasSelf) {
          onSelfRevoked();
          return;
        }
        await load();
      } catch (caught) {
        setError(toMobileError(caught));
      }
    },
    [client, self, load, onSelfRevoked],
  );

  return (
    <Screen title={t.t('devices.title')}>
      <ErrorBanner error={error} onRetry={() => void load()} />

      {devices.map((device) => {
        const isSelf = device.bindingId === self?.bindingId;
        return (
          <Card key={device.bindingId}>
            <Text style={styles.heading}>
              {isSelf ? `${device.deviceLabel} · ${t.t('devices.thisDevice')}` : device.deviceLabel}
            </Text>
            <Row label={t.t('home.assuranceLabel')} value={device.assuranceLevel} />
            <Row label={t.t('devices.enrolledOn', { date: '' }).trim()} value={formatTime(device.enrolledAt)} />
            <Row
              label={t.t('devices.lastUsed', { date: '' }).trim()}
              value={device.lastUsedAt ? formatTime(device.lastUsedAt) : t.t('devices.neverUsed')}
            />
            <Text style={styles.muted}>{t.t(statusKey(device.status))}</Text>

            {device.status !== 'revoked' ? (
              confirming === device.bindingId ? (
                <View style={styles.confirm}>
                  <Text style={styles.heading}>
                    {t.t('devices.revokeConfirmTitle', { label: device.deviceLabel })}
                  </Text>
                  <Text style={styles.body}>{t.t('devices.revokeConfirmBody')}</Text>
                  <Button
                    label={t.t('devices.revoke')}
                    variant="danger"
                    onPress={() => void revoke(device.bindingId)}
                  />
                  <Button
                    label={t.t('common.cancel')}
                    variant="secondary"
                    onPress={() => setConfirming(null)}
                  />
                </View>
              ) : (
                <Button
                  label={t.t('devices.revoke')}
                  variant="secondary"
                  onPress={() => setConfirming(device.bindingId)}
                />
              )
            ) : null}
          </Card>
        );
      })}

      <Card>
        <Text style={styles.heading}>{t.t('devices.addNew')}</Text>
        <Text style={styles.body}>{t.t('devices.addNewBody')}</Text>
      </Card>

      <Text accessibilityRole="header" style={styles.heading}>
        {t.t('consents.title')}
      </Text>
      {consents.length === 0 ? <Text style={styles.muted}>{t.t('consents.empty')}</Text> : null}
      {consents.map((consent) => (
        <Card key={consent.id}>
          <Text style={styles.heading}>{consent.rpName}</Text>
          {consent.scopes.map((scope) => (
            <Text key={scope} style={styles.body}>{`• ${describeScope(t, scope)}`}</Text>
          ))}
          <Text style={styles.muted}>
            {t.t('consents.grantedOn', { date: formatTime(consent.grantedAt) })}
          </Text>
          {consent.revokedAt === null ? (
            <Button
              label={t.t('consents.revoke')}
              variant="secondary"
              onPress={() => {
                void client
                  .revokeConsent(consent.id)
                  .then(load)
                  .catch((caught: unknown) => setError(toMobileError(caught)));
              }}
            />
          ) : (
            <Text style={styles.muted}>{t.t('consents.revoked')}</Text>
          )}
        </Card>
      ))}

      <View style={styles.actions}>
        <Button label={t.t('common.back')} variant="secondary" onPress={onBack} />
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  heading: { ...typography.heading, color: colors.text },
  body: { ...typography.body, color: colors.text },
  muted: { ...typography.small, color: colors.textMuted },
  confirm: { gap: spacing.sm, marginTop: spacing.sm },
  actions: { marginTop: spacing.md },
});
