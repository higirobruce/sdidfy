/**
 * CIBA approval — THE security-critical screen (04 §3, 05 §2, T7). RN-only.
 *
 * Everything on it is a mitigation, not decoration:
 *
 *  - **Who is asking** is the first thing on the screen, in the largest type
 *    after the code, taken from the authenticated backchannel — never from a
 *    push payload (T6).
 *  - **The binding-message code** is rendered huge and spaced out, with the
 *    instruction to compare it with the screen the citizen is signing in on.
 *    This is the whole defence against a relayed "approve this" (T7).
 *    A request that arrives WITHOUT a code gets an explicit warning rather
 *    than a blank space — absence must be visible.
 *  - **Scopes in plain language**, localised on the device. The broker also
 *    sends English `scopeDescriptions`; showing those would be exactly the
 *    raw-server-string problem (03 §7), so they are ignored in favour of
 *    `describeScope`.
 *  - **Approve and deny are unmistakably different**: different colours,
 *    different labels, physically separated, and deny is not the primary
 *    button so a reflexive double-tap cannot approve.
 *  - **A countdown**, because the request is time-boxed (180 s), and both
 *    buttons disable when it or its signing challenge lapses.
 *  - **"I did not request this"** denies AND flags for the security team.
 *  - **A screen-recording / overlay warning** where the platform can tell
 *    (05 §9), which disables approval while it is showing.
 *  - **A "several requests waiting" banner** so a burst cannot be tapped
 *    through as if it were one (05 §9).
 */
import React, { useCallback, useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import type { PendingGroup } from '../../core/pending.js';
import { isDecidable, secondsRemaining } from '../../core/pending.js';
import { toMobileError, type MobileError } from '../../core/errors.js';
import { describeScope } from '../../i18n/index.js';
import { Button, Card, CodeChips, ErrorBanner, Screen } from '../components.js';
import { useApp } from '../context.js';
import { colors, radius, spacing, typography } from '../theme.js';

export interface ApprovalScreenProps {
  group: PendingGroup;
  /** How many DISTINCT requests are waiting, for the consent-fatigue banner. */
  totalGroups: number;
  /** True while the platform reports screen capture / an overlay (05 §9). */
  screenCompromised?: boolean;
  onResolved: (outcome: 'approved' | 'denied' | 'reported') => void;
}

type Phase = 'idle' | 'submitting' | 'confirm-report';

export function ApprovalScreen({
  group,
  totalGroups,
  screenCompromised = false,
  onResolved,
}: ApprovalScreenProps): React.ReactElement {
  const { t, client } = useApp();
  const txn = group.primary;
  const [now, setNow] = useState(() => Date.now());
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<MobileError | null>(null);

  // One-second countdown. Cheap, and the citizen must see the time pressure
  // rather than discover it as a failure after they authenticate.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const live = isDecidable(txn, now);
  const busy = phase === 'submitting';

  const submit = useCallback(
    async (decision: 'approve' | 'deny', report = false) => {
      setPhase('submitting');
      setError(null);
      try {
        if (decision === 'approve') {
          await client.approve(txn);
          onResolved('approved');
        } else if (report) {
          await client.reportNotMe(txn);
          onResolved('reported');
        } else {
          await client.deny(txn);
          onResolved('denied');
        }
      } catch (caught) {
        setError(toMobileError(caught));
        setPhase('idle');
      }
    },
    [client, txn, onResolved],
  );

  return (
    <Screen title={t.t('approval.title')}>
      {totalGroups > 1 ? (
        <View accessibilityRole="alert" style={styles.fatigueBanner}>
          <Text style={styles.warningText}>
            {t.t('approval.multiplePending', { count: totalGroups })}
          </Text>
        </View>
      ) : null}

      {screenCompromised ? (
        <View accessibilityRole="alert" style={styles.dangerBanner}>
          <Text style={styles.dangerText}>{t.t('approval.screenRecordingWarning')}</Text>
        </View>
      ) : null}

      {/* WHO is asking. */}
      <Card>
        <Text style={styles.label}>{t.t('approval.whoIsAsking')}</Text>
        <Text accessibilityRole="header" style={styles.rpName}>
          {txn.rpName}
        </Text>
      </Card>

      {/* THE CODE — the anti-relay control (T7). */}
      <Card style={styles.codeCard}>
        <Text style={styles.label}>{t.t('approval.codeLabel')}</Text>
        {txn.bindingMessage ? (
          <>
            <View accessible accessibilityLabel={spellOut(txn.bindingMessage)}>
              <CodeChips code={txn.bindingMessage} />
            </View>
            <Text style={styles.instruction}>{t.t('approval.codeInstruction')}</Text>
          </>
        ) : (
          // Absence of a code is itself information, and must be loud.
          <Text style={styles.warningText}>{t.t('approval.noCode')}</Text>
        )}
      </Card>

      {/* WHAT they are asking for, in the citizen's language. */}
      <Card>
        <Text style={styles.label}>{t.t('approval.scopesTitle')}</Text>
        {txn.scopes.map((scope) => (
          <Text key={scope} style={styles.scope}>
            {`• ${describeScope(t, scope)}`}
          </Text>
        ))}
        <Text style={styles.meta}>
          {`${t.t('approval.assuranceLabel')}: ${txn.requestedAssurance}`}
        </Text>
        {group.count > 1 ? (
          <Text style={styles.meta}>
            {t.t('approval.multiplePending', { count: group.count })}
          </Text>
        ) : null}
      </Card>

      <Text style={live ? styles.countdown : styles.countdownExpired}>
        {live
          ? t.t('approval.expiresIn', { seconds: secondsRemaining(txn, now) })
          : t.t('approval.expired')}
      </Text>

      <ErrorBanner error={error} />

      {phase === 'confirm-report' ? (
        <Card>
          <Text style={styles.instruction}>{t.t('approval.notMeBody')}</Text>
          <Button
            label={t.t('approval.notMeConfirm')}
            variant="danger"
            disabled={busy}
            onPress={() => void submit('deny', true)}
          />
          <Button
            label={t.t('common.cancel')}
            variant="secondary"
            onPress={() => setPhase('idle')}
          />
        </Card>
      ) : (
        <View style={styles.actions}>
          {/* Approve first and primary, deny visually separated below — never
              two similar buttons side by side. */}
          <Button
            label={t.t('approval.approve')}
            accessibilityHint={t.t('approval.approveHint')}
            disabled={!live || busy || screenCompromised}
            onPress={() => void submit('approve')}
          />
          <View style={styles.separator} />
          <Button
            label={t.t('approval.deny')}
            variant="danger"
            disabled={!live || busy}
            onPress={() => void submit('deny')}
          />
          <Button
            label={t.t('approval.notMeTitle')}
            variant="secondary"
            disabled={busy}
            onPress={() => setPhase('confirm-report')}
          />
        </View>
      )}
    </Screen>
  );
}

/**
 * Screen-reader rendering of the code: "7 Q 4 2" reads as four characters
 * instead of a mangled word, so a citizen using VoiceOver/TalkBack can
 * actually compare it (05 §7 accessibility, and T7 depends on the comparison).
 */
function spellOut(message: string): string {
  return message.split('').join(' ');
}

const styles = StyleSheet.create({
  label: { ...typography.small, color: colors.textMuted },
  rpName: { ...typography.title, color: colors.text },
  codeCard: { alignItems: 'center' },
  instruction: { ...typography.body, color: colors.text },
  scope: { ...typography.body, color: colors.text },
  meta: { ...typography.small, color: colors.textMuted },
  countdown: { ...typography.body, color: colors.textMuted, textAlign: 'center' },
  countdownExpired: { ...typography.body, color: colors.danger, textAlign: 'center' },
  actions: { gap: spacing.sm },
  separator: { height: spacing.md },
  fatigueBanner: {
    backgroundColor: colors.warningSurface,
    borderColor: colors.warning,
    borderWidth: 1,
    borderRadius: radius.md,
    padding: spacing.md,
  },
  dangerBanner: {
    backgroundColor: colors.danger,
    borderRadius: radius.md,
    padding: spacing.md,
  },
  warningText: { ...typography.body, color: colors.warning },
  dangerText: { ...typography.body, color: colors.dangerText },
});
