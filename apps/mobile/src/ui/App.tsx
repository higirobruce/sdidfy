/**
 * App shell + composition root. RN-only.
 *
 * Deliberately a hand-rolled screen switch rather than a navigation library:
 * the app has six screens, and every third-party dependency on the path
 * between "a request arrived" and "the citizen approved it" is a dependency
 * that has to be audited (05 §8). Swap in React Navigation if the screen count
 * grows — but keep the approval screen reachable without it.
 *
 * The composition root is `createApp()`: it is the ONLY place that decides
 * which KeyStore/Attestation/FaceCapture implementations are used, so a
 * release build cannot accidentally pick up a test double.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { SafeAreaView, StatusBar, StyleSheet } from 'react-native';
import { ProtocolClient } from '../core/client.js';
import type { PendingGroup } from '../core/pending.js';
import { assertPinnedTransport, type HttpTransport } from '../core/transport.js';
import type { BindingStore } from '../core/types.js';
import { resolveLocale, type Locale } from '../i18n/index.js';
import { NativeAttestation, NativeBiometricPrompt, NativeFaceCapture } from '../native/devices.rn.js';
import { NativeKeyStore } from '../native/keystore.rn.js';
import { AppProvider, useApp } from './context.js';
import { ActivityScreen } from './screens/ActivityScreen.js';
import { ApprovalScreen } from './screens/ApprovalScreen.js';
import { DevicesScreen } from './screens/DevicesScreen.js';
import { EnrolmentScreen } from './screens/EnrolmentScreen.js';
import { HomeScreen } from './screens/HomeScreen.js';
import { LanguageScreen, SettingsScreen } from './screens/SettingsScreen.js';
import { colors } from './theme.js';

type Route =
  | { name: 'language' }
  | { name: 'enrol' }
  | { name: 'home' }
  | { name: 'approval'; group: PendingGroup; totalGroups: number }
  | { name: 'devices' }
  | { name: 'activity' }
  | { name: 'settings' };

export interface CreateAppOptions {
  brokerUrl: string;
  /** Platform-pinned transport (T5). A release build refuses an unpinned one. */
  transport: HttpTransport;
  bindingStore: BindingStore;
  platform: 'android' | 'ios';
  deviceLabel: string;
  appVersion: string;
  /** BCP-47 tags from the OS, most-preferred first. */
  preferredLocales?: readonly string[];
  isRelease: boolean;
}

/**
 * Build the whole app. Native modules are constructed here and nowhere else.
 */
export function createApp(options: CreateAppOptions): React.ReactElement {
  // Fail closed on an unpinned transport in a release build (T5).
  assertPinnedTransport(options.transport, options.isRelease);

  const biometrics = new NativeBiometricPrompt();
  const client = new ProtocolClient({
    brokerUrl: options.brokerUrl,
    transport: options.transport,
    keyStore: new NativeKeyStore(),
    attestation: new NativeAttestation(options.platform),
    faceCapture: new NativeFaceCapture(),
    biometrics,
    bindingStore: options.bindingStore,
    // Hardware-backed keys only in a real build (06 §6).
    minKeySecurityLevel: options.isRelease ? 'tee' : 'software',
  });

  const initialLocale: Locale = resolveLocale(options.preferredLocales);
  return (
    <AppProvider client={client} initialLocale={initialLocale}>
      <Root
        deviceLabel={options.deviceLabel}
        appVersion={options.appVersion}
        biometrics={biometrics}
      />
    </AppProvider>
  );
}

function Root({
  deviceLabel,
  appVersion,
  biometrics,
}: {
  deviceLabel: string;
  appVersion: string;
  biometrics: NativeBiometricPrompt;
}): React.ReactElement {
  const { client } = useApp();
  const [route, setRoute] = useState<Route>({ name: 'language' });
  const [screenCompromised, setScreenCompromised] = useState(false);

  // 05 §9: warn (and block approval) while the screen is recorded or overlaid.
  useEffect(() => {
    if (route.name !== 'approval') return undefined;
    let cancelled = false;
    const check = (): void => {
      void biometrics.isScreenCompromised().then((value) => {
        if (!cancelled) setScreenCompromised(value);
      });
    };
    check();
    const timer = setInterval(check, 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [route.name, biometrics]);

  const goHomeOrEnrol = useCallback(() => {
    void client
      .isEnrolled()
      .then((enrolled) => setRoute({ name: enrolled ? 'home' : 'enrol' }));
  }, [client]);

  let screen: React.ReactElement;
  switch (route.name) {
    case 'language':
      screen = <LanguageScreen onChosen={goHomeOrEnrol} />;
      break;
    case 'enrol':
      screen = (
        <EnrolmentScreen deviceLabel={deviceLabel} onEnrolled={() => setRoute({ name: 'home' })} />
      );
      break;
    case 'approval':
      screen = (
        <ApprovalScreen
          group={route.group}
          totalGroups={route.totalGroups}
          screenCompromised={screenCompromised}
          onResolved={() => setRoute({ name: 'home' })}
        />
      );
      break;
    case 'devices':
      screen = (
        <DevicesScreen
          onBack={() => setRoute({ name: 'home' })}
          onSelfRevoked={() => setRoute({ name: 'enrol' })}
        />
      );
      break;
    case 'activity':
      screen = <ActivityScreen onBack={() => setRoute({ name: 'home' })} />;
      break;
    case 'settings':
      screen = (
        <SettingsScreen
          appVersion={appVersion}
          onBack={() => setRoute({ name: 'home' })}
          onOpenHelp={() => setRoute({ name: 'home' })}
        />
      );
      break;
    case 'home':
    default:
      screen = (
        <HomeScreen
          onOpenApproval={(group, totalGroups) =>
            setRoute({ name: 'approval', group, totalGroups })
          }
          onOpenDevices={() => setRoute({ name: 'devices' })}
          onOpenActivity={() => setRoute({ name: 'activity' })}
          onOpenSettings={() => setRoute({ name: 'settings' })}
        />
      );
      break;
  }

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar barStyle="dark-content" />
      {screen}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
});
