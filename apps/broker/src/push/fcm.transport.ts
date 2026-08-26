import { request as httpsRequest } from 'node:https';
import { fcmWakeData } from './push-payload.js';
import { PushNotConfiguredError, type PushOutcome, type PushTransport } from './push-transport.js';
import { parseServiceAccount, readCredentialMaterial, signRs256Jwt } from './credentials.js';

/**
 * Firebase Cloud Messaging HTTP v1 transport (05 §5).
 *
 * ============================ NOT YET DEPLOYABLE ==========================
 * No GoR Firebase project or service account exists, so this transport is
 * UNCONFIGURED in every environment today and `send()` throws a descriptive
 * `PushNotConfiguredError` — the same declared-seam discipline as
 * `trust/play-integrity.decoder.ts`: refuse loudly rather than pretend to
 * deliver. `PushService` catches it, records `outcome="not_configured"` and
 * carries on, because push is a wake optimisation and the app also polls.
 *
 * The protocol code below is complete (service-account assertion → OAuth2
 * token → `messages:send`) but has NEVER been exercised against Google's
 * endpoints. Treat the first real run as an integration test, not a rollout:
 * verify with one device before enabling it for a cohort.
 * ==========================================================================
 */

const OAUTH_HOST = 'oauth2.googleapis.com';
const OAUTH_PATH = '/token';
const FCM_HOST = 'fcm.googleapis.com';
const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
/** Refresh a little before expiry so an in-flight send never races it. */
const TOKEN_SKEW_SECONDS = 120;

export interface FcmTransportOptions {
  projectId: string;
  /** Service-account JSON: a path, or the JSON inline. */
  credentialsJson: string;
  timeoutMs: number;
}

interface HttpReply {
  status: number;
  body: string;
}

function postJson(
  host: string,
  path: string,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<HttpReply> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host,
        path,
        method: 'POST',
        headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('timeout', () => req.destroy(new Error(`request to ${host} timed out`)));
    req.on('error', reject);
    req.end(body);
  });
}

export function createFcmTransport(options: FcmTransportOptions): PushTransport {
  const rawCredentials = readCredentialMaterial(options.credentialsJson);
  const account = rawCredentials === '' ? null : parseServiceAccount(rawCredentials);
  const projectId = options.projectId.trim() || account?.project_id || '';
  const configured = account !== null && projectId !== '';

  if (!configured) {
    // The declared seam. The message names exactly what is missing and where
    // to set it — an operator should never have to read this file to find out.
    return {
      platform: 'fcm',
      configured: false,
      async send(): Promise<PushOutcome> {
        throw new PushNotConfiguredError(
          'fcm',
          'FCM push is not configured: set FCM_PROJECT_ID and FCM_CREDENTIALS_JSON (a Google ' +
            'service-account key with the Firebase Cloud Messaging API enabled, as a path or ' +
            'inline JSON). No GoR Firebase project exists yet — see docs/runbook.md §13. ' +
            `(projectId=${projectId || '<unset>'}, credentials=${
              rawCredentials === '' ? 'unset' : account === null ? 'unparseable' : 'set'
            })`,
        );
      },
    };
  }

  const key = account;
  let cachedToken: { value: string; expiresAtEpoch: number } | null = null;

  async function accessToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (cachedToken && cachedToken.expiresAtEpoch - TOKEN_SKEW_SECONDS > now) return cachedToken.value;
    const assertion = signRs256Jwt(
      {},
      {
        iss: key.client_email,
        scope: FCM_SCOPE,
        aud: `https://${OAUTH_HOST}${OAUTH_PATH}`,
        iat: now,
        exp: now + 3600,
      },
      key.private_key,
    );
    const form =
      'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' +
      encodeURIComponent(assertion);
    const reply = await postJson(
      OAUTH_HOST,
      OAUTH_PATH,
      form,
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      options.timeoutMs,
    );
    if (reply.status !== 200) {
      // Never echo the reply body: an OAuth error response can quote the
      // assertion we just signed.
      throw new Error(`FCM OAuth exchange failed with HTTP ${reply.status}`);
    }
    const parsed = JSON.parse(reply.body) as { access_token?: string; expires_in?: number };
    if (typeof parsed.access_token !== 'string') throw new Error('FCM OAuth reply had no access_token');
    cachedToken = {
      value: parsed.access_token,
      expiresAtEpoch: now + (typeof parsed.expires_in === 'number' ? parsed.expires_in : 3600),
    };
    return cachedToken.value;
  }

  return {
    platform: 'fcm',
    configured: true,
    async send(deviceToken: string): Promise<PushOutcome> {
      const token = await accessToken();
      const message = {
        message: {
          token: deviceToken,
          // Data-only: no `notification` block, so the OS renders nothing the
          // broker supplied and the app decides what (if anything) to show.
          data: fcmWakeData(),
          android: { priority: 'HIGH' as const },
        },
      };
      const reply = await postJson(
        FCM_HOST,
        `/v1/projects/${encodeURIComponent(projectId)}/messages:send`,
        JSON.stringify(message),
        { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        options.timeoutMs,
      );
      if (reply.status >= 200 && reply.status < 300) return { status: 'delivered' };
      // UNREGISTERED / INVALID_ARGUMENT on the token means the app is gone or
      // the token rotated — prune rather than retry forever.
      if (reply.status === 404 || reply.body.includes('UNREGISTERED')) {
        return { status: 'unregistered' };
      }
      // Status only. An FCM error body echoes the message we sent, and while
      // our payload is content-free by construction, echoing provider bodies
      // into logs is exactly how payloads start leaking.
      return { status: 'failed', detail: `fcm http ${reply.status}` };
    },
  };
}
