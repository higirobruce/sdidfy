import { connect, constants, type ClientHttp2Session } from 'node:http2';
import { randomUUID } from 'node:crypto';
import { apnsWakePayload } from './push-payload.js';
import { PushNotConfiguredError, type PushOutcome, type PushTransport } from './push-transport.js';
import { readCredentialMaterial, signEs256Jwt } from './credentials.js';

/**
 * Apple Push Notification service transport (05 §5), HTTP/2 + token auth.
 *
 * ============================ NOT YET DEPLOYABLE ==========================
 * No GoR Apple developer team, App ID or APNs auth key exists, so this
 * transport is UNCONFIGURED today and `send()` throws a descriptive
 * `PushNotConfiguredError` — same declared-seam discipline as
 * `trust/play-integrity.decoder.ts`. The protocol code below is complete but
 * has NEVER run against Apple's endpoints; treat the first real send as an
 * integration test.
 * ==========================================================================
 *
 * Token auth (a p8 key + team/key ids) rather than certificate auth: it does
 * not expire annually, it is one credential for every topic, and it is a key
 * we can keep in the same custody as the rest (decision #5).
 */

const PROD_ORIGIN = 'https://api.push.apple.com';
const SANDBOX_ORIGIN = 'https://api.sandbox.push.apple.com';
/**
 * Apple rejects a provider token older than 60 minutes and rate-limits tokens
 * minted more often than every 20 minutes. 40 is comfortably inside both.
 */
const PROVIDER_TOKEN_TTL_MS = 40 * 60 * 1000;

export interface ApnsTransportOptions {
  teamId: string;
  keyId: string;
  /** The `.p8` EC private key: a path, or the PEM inline. */
  privateKeyP8: string;
  /** APNs topic — the app's bundle id. */
  topic: string;
  production: boolean;
  /** `alert` (a loc-key only) or `background`. See push-payload.ts. */
  pushType: 'alert' | 'background';
  timeoutMs: number;
}

export function createApnsTransport(options: ApnsTransportOptions): PushTransport {
  const privateKey = readCredentialMaterial(options.privateKeyP8);
  const missing: string[] = [];
  if (options.teamId.trim() === '') missing.push('APNS_TEAM_ID');
  if (options.keyId.trim() === '') missing.push('APNS_KEY_ID');
  if (privateKey === '') missing.push('APNS_PRIVATE_KEY_P8');
  if (options.topic.trim() === '') missing.push('APNS_TOPIC');

  if (missing.length > 0) {
    return {
      platform: 'apns',
      configured: false,
      async send(): Promise<PushOutcome> {
        throw new PushNotConfiguredError(
          'apns',
          `APNs push is not configured: missing ${missing.join(', ')}. Needs an Apple ` +
            'developer team id, an APNs auth key (.p8, as a path or inline PEM) with its key ' +
            'id, and the app bundle id as the topic. No GoR Apple team exists yet — see ' +
            'docs/runbook.md §13.',
        );
      },
    };
  }

  const origin = options.production ? PROD_ORIGIN : SANDBOX_ORIGIN;
  let providerToken: { value: string; mintedAt: number } | null = null;
  let session: ClientHttp2Session | null = null;

  function currentToken(): string {
    const now = Date.now();
    if (providerToken && now - providerToken.mintedAt < PROVIDER_TOKEN_TTL_MS) {
      return providerToken.value;
    }
    const value = signEs256Jwt(
      { kid: options.keyId },
      { iss: options.teamId, iat: Math.floor(now / 1000) },
      privateKey,
    );
    providerToken = { value, mintedAt: now };
    return value;
  }

  /**
   * One HTTP/2 session, reused. APNs expects a long-lived connection and
   * penalises connection churn; a session per push would also add a TLS
   * handshake to every CIBA initiation.
   */
  function currentSession(): ClientHttp2Session {
    if (session && !session.closed && !session.destroyed) return session;
    const next = connect(origin);
    next.on('error', () => {
      // Drop the reference so the next send reconnects. Swallowing is correct:
      // an unhandled 'error' on an idle session would crash the broker, and a
      // push transport must never be able to take down authentication.
      if (session === next) session = null;
    });
    next.on('close', () => {
      if (session === next) session = null;
    });
    next.unref();
    session = next;
    return next;
  }

  return {
    platform: 'apns',
    configured: true,
    send(deviceToken: string): Promise<PushOutcome> {
      return new Promise<PushOutcome>((resolve) => {
        let settled = false;
        const done = (outcome: PushOutcome): void => {
          if (!settled) {
            settled = true;
            resolve(outcome);
          }
        };
        try {
          const body = JSON.stringify(apnsWakePayload(options.pushType));
          const stream = currentSession().request({
            [constants.HTTP2_HEADER_METHOD]: 'POST',
            [constants.HTTP2_HEADER_PATH]: `/3/device/${encodeURIComponent(deviceToken)}`,
            [constants.HTTP2_HEADER_AUTHORIZATION]: `bearer ${currentToken()}`,
            'apns-topic': options.topic,
            'apns-push-type': options.pushType,
            // 10 = immediate for an alert; a background push must use 5.
            'apns-priority': options.pushType === 'background' ? '5' : '10',
            // Do not keep retrying a wake past the CIBA window; a late wake is
            // a prompt for a request that has already expired (04 §3).
            'apns-expiration': String(Math.floor(Date.now() / 1000) + 120),
            'apns-id': randomUUID(),
            [constants.HTTP2_HEADER_CONTENT_TYPE]: 'application/json',
            [constants.HTTP2_HEADER_CONTENT_LENGTH]: Buffer.byteLength(body),
          });
          stream.setTimeout(options.timeoutMs, () => {
            stream.close(constants.NGHTTP2_CANCEL);
            done({ status: 'failed', detail: 'apns timeout' });
          });
          let status = 0;
          const chunks: Buffer[] = [];
          stream.on('response', (headers) => {
            status = Number(headers[constants.HTTP2_HEADER_STATUS] ?? 0);
          });
          stream.on('data', (c: Buffer) => chunks.push(c));
          stream.on('error', (err) => done({ status: 'failed', detail: `apns stream: ${err.message}` }));
          stream.on('end', () => {
            const reply = Buffer.concat(chunks).toString('utf8');
            if (status === 200) return done({ status: 'delivered' });
            // 410 Gone, or 400 BadDeviceToken/DeviceTokenNotForTopic: the
            // token is dead for us. Prune rather than retry.
            if (status === 410 || reply.includes('BadDeviceToken') || reply.includes('Unregistered')) {
              return done({ status: 'unregistered' });
            }
            // APNs error bodies are a bare `{"reason": "..."}` enum — safe to
            // surface, and the only way to diagnose a topic/token mismatch.
            return done({ status: 'failed', detail: `apns http ${status} ${reply.slice(0, 120)}` });
          });
          stream.end(body);
        } catch (err) {
          done({ status: 'failed', detail: err instanceof Error ? err.message : 'apns send failed' });
        }
      });
    },
  };
}
