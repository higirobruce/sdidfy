import { eq } from 'drizzle-orm';
import { MOCK_TEST_NIDS } from '@sdid/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deviceBindings } from '../db/schema.js';
import {
  cleanTestData,
  createTestApp,
  enrolAndActivate,
  login,
  SimDevice,
  type TestContext,
} from '../modules/enrolment/testkit.js';
import { createApnsTransport } from './apns.transport.js';
import { createFcmTransport } from './fcm.transport.js';
import {
  FORBIDDEN_PAYLOAD_KEYS,
  WAKE_PAYLOAD_TYPE,
  apnsWakePayload,
  fcmWakeData,
} from './push-payload.js';
import { PushNotConfiguredError } from './push-transport.js';
import { PushService } from './push.service.js';

/** Every key anywhere in a nested payload, for the "carries nothing" check. */
function allKeys(value: unknown, acc: string[] = []): string[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      acc.push(k);
      allKeys(v, acc);
    }
  }
  return acc;
}

describe('wake-only push payload (05 §5, T6)', () => {
  it('FCM data carries a type and a version and nothing else', () => {
    const data = fcmWakeData();
    expect(Object.keys(data).sort()).toEqual(['type', 'v']);
    expect(data['type']).toBe(WAKE_PAYLOAD_TYPE);
  });

  it('FCM is data-only — no server-supplied notification the OS would render', () => {
    expect(Object.keys(fcmWakeData())).not.toContain('notification');
  });

  it.each(['alert', 'background'] as const)(
    'APNs %s payload contains no request, RP or citizen field',
    (pushType) => {
      const payload = apnsWakePayload(pushType);
      const keys = allKeys(payload).map((k) => k.toLowerCase());
      for (const forbidden of FORBIDDEN_PAYLOAD_KEYS) {
        expect(keys).not.toContain(forbidden.toLowerCase());
      }
    },
  );

  it('APNs alert carries only a loc-key, never server-side display text (05 §7)', () => {
    const payload = apnsWakePayload('alert') as { aps: { alert: Record<string, unknown> } };
    expect(Object.keys(payload.aps.alert)).toEqual(['loc-key']);
    // No `title`/`body`: the app renders its own localised string, so nothing
    // about who is asking or what for can appear on a lock screen.
    expect(JSON.stringify(payload)).not.toMatch(/"title"|"body"|"alert":"/);
  });

  it('APNs background payload is entirely silent', () => {
    const payload = apnsWakePayload('background') as { aps: Record<string, unknown> };
    expect(Object.keys(payload.aps)).toEqual(['content-available']);
  });
});

describe('push transports are declared seams while GoR credentials do not exist', () => {
  it('FCM throws a descriptive, actionable error when unconfigured', async () => {
    const transport = createFcmTransport({ projectId: '', credentialsJson: '', timeoutMs: 1000 });
    expect(transport.configured).toBe(false);
    await expect(transport.send('device-token')).rejects.toBeInstanceOf(PushNotConfiguredError);
    await expect(transport.send('device-token')).rejects.toThrow(/FCM_PROJECT_ID/);
    await expect(transport.send('device-token')).rejects.toThrow(/FCM_CREDENTIALS_JSON/);
  });

  it('FCM stays unconfigured on unparseable credentials rather than half-working', async () => {
    const transport = createFcmTransport({
      projectId: 'p',
      credentialsJson: '{not json',
      timeoutMs: 1000,
    });
    expect(transport.configured).toBe(false);
    await expect(transport.send('t')).rejects.toThrow(/unparseable/);
  });

  it('APNs throws naming every missing setting', async () => {
    const transport = createApnsTransport({
      teamId: '',
      keyId: '',
      privateKeyP8: '',
      topic: '',
      production: false,
      pushType: 'alert',
      timeoutMs: 1000,
    });
    expect(transport.configured).toBe(false);
    const err = await transport.send('t').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PushNotConfiguredError);
    for (const name of ['APNS_TEAM_ID', 'APNS_KEY_ID', 'APNS_PRIVATE_KEY_P8', 'APNS_TOPIC']) {
      expect((err as Error).message).toContain(name);
    }
  });
});

describe('device push-token registration, rotation and removal (05 §5, 06 §4)', () => {
  let ctx: TestContext;
  let device: SimDevice;
  let bindingId: string;
  let sessionToken: string;

  const nid = MOCK_TEST_NIDS[1];

  beforeAll(async () => {
    ctx = await createTestApp();
    await cleanTestData(ctx);
    device = await SimDevice.create();
    bindingId = await enrolAndActivate(ctx, device, nid, 'Push phone');
    sessionToken = await login(ctx, device, bindingId);
  });

  afterAll(async () => {
    await cleanTestData(ctx);
    await ctx.app.close();
  });

  async function storedToken(): Promise<{ platform: string | null; token: string | null }> {
    const rows = await ctx.db.db
      .select({ platform: deviceBindings.pushPlatform, token: deviceBindings.pushToken })
      .from(deviceBindings)
      .where(eq(deviceBindings.id, bindingId));
    return rows[0] ?? { platform: null, token: null };
  }

  it('refuses registration without a device session', async () => {
    await ctx.http()
      .post('/v1/device/push-token')
      .send({ platform: 'fcm', token: 'abc' })
      .expect(401);
  });

  it('rejects an unknown platform at the boundary', async () => {
    await ctx.http()
      .post('/v1/device/push-token')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ platform: 'sms', token: 'abc' })
      .expect(400);
  });

  it('registers a token against the SESSION binding (not one named in the body)', async () => {
    await ctx.http()
      .post('/v1/device/push-token')
      .set('Authorization', `Bearer ${sessionToken}`)
      // A body binding id is ignored — the schema has no such field, so one
      // device can never point another citizen's wakes at itself.
      .send({ platform: 'fcm', token: 'fcm-token-one', bindingId: 'someone-else' })
      .expect(200);
    expect(await storedToken()).toEqual({ platform: 'fcm', token: 'fcm-token-one' });
  });

  it('rotation is the same call — the newest token wins', async () => {
    await ctx.http()
      .post('/v1/device/push-token')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ platform: 'apns', token: 'apns-token-two' })
      .expect(200);
    expect(await storedToken()).toEqual({ platform: 'apns', token: 'apns-token-two' });
  });

  it('the citizen can remove it explicitly', async () => {
    await ctx.http()
      .post('/v1/device/push-token/remove')
      .set('Authorization', `Bearer ${sessionToken}`)
      .expect(200);
    expect(await storedToken()).toEqual({ platform: null, token: null });
  });

  it('revoking the binding clears the push address in the same operation', async () => {
    await ctx.http()
      .post('/v1/device/push-token')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ platform: 'fcm', token: 'fcm-token-three' })
      .expect(200);
    await ctx.http()
      .post('/v1/device/bindings/revoke')
      .set('Authorization', `Bearer ${sessionToken}`)
      .send({ bindingId })
      .expect(200);
    expect(await storedToken()).toEqual({ platform: null, token: null });
  });

  it('wake() on a citizen with no registered token is a no-op, never an error', async () => {
    const push = ctx.app.get(PushService);
    // Push is an optimisation over the app's own polling — a missing token,
    // an outage or a missing credential must never fail an RP's request.
    await expect(push.wake(crypto.randomUUID())).resolves.toBeUndefined();
  });
});
