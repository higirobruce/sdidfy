/**
 * Transport contract for wake-only push (05 §5, T6).
 *
 * `send` takes ONLY the device token. That is the whole point: there is no
 * message parameter, so no caller — now or later — can put request detail into
 * a notification. The payload is built inside each transport from
 * `push-payload.ts` and carries nothing but a type and a version.
 */
export type PushPlatform = 'fcm' | 'apns';

export type PushOutcome =
  /** Accepted by the provider for delivery. */
  | { status: 'delivered' }
  /**
   * The provider says this token is dead (app uninstalled, token rotated).
   * The broker prunes it — a permanently undeliverable token is a row that
   * would otherwise be retried forever, and it is also a stale device address
   * we have no reason to keep (07 §6 minimisation).
   */
  | { status: 'unregistered' }
  /** Transient or unknown failure. Never fatal to the flow that triggered it. */
  | { status: 'failed'; detail: string };

export interface PushTransport {
  readonly platform: PushPlatform;
  /** True when credentials are present; false means `send` will throw the seam error. */
  readonly configured: boolean;
  send(deviceToken: string): Promise<PushOutcome>;
}

/**
 * Error thrown by an unconfigured transport. Distinct class so PushService can
 * report "not configured" separately from "provider rejected us" in metrics —
 * an operator must be able to tell a missing credential from an outage.
 */
export class PushNotConfiguredError extends Error {
  constructor(
    readonly platform: PushPlatform,
    detail: string,
  ) {
    super(detail);
    this.name = 'PushNotConfiguredError';
  }
}
