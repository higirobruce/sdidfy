/**
 * "Ghost login" narrated demo (SPEC 09 §6): the suggested first milestone,
 * told as a story. A pilot RP completes a full CIBA login of a simulated
 * citizen phone against mock SDID — genuine hardware-style signature, minted
 * tokens, pairwise privacy, tamper-evident audit — through the real broker.
 *
 * Run from the repo root:  pnpm demo:ghost-login
 */
import { createHmac, randomBytes } from 'node:crypto';
import { CIBA_GRANT_TYPE, MOCK_TEST_NIDS } from '@sdid/shared';
import { SimDevice } from '@sdid/device-sim';
import { RpClient } from '@sdid/test-rp';
import {
  ADMIN_TOKEN,
  BROKER_URL,
  BrokerHarness,
  NID_PEPPER,
  clearEnrolmentThrottles,
  revokeAllBindingsViaSql,
} from './harness.js';

// ---------------------------------------------------------------- ANSI bits
const ESC = '\u001b[';
const c = {
  reset: `${ESC}0m`,
  bold: `${ESC}1m`,
  dim: `${ESC}2m`,
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  cyan: `${ESC}36m`,
  magenta: `${ESC}35m`,
};
const OK = `${c.green}✓${c.reset}`;
function step(marker: string, text: string): void {
  console.log(`\n${c.cyan}${c.bold}${marker}${c.reset} ${text}`);
}
function detail(text: string): void {
  console.log(`   ${c.dim}${text}${c.reset}`);
}
function kv(key: string, value: string): void {
  console.log(`   ${c.yellow}${key.padEnd(10)}${c.reset} ${value}`);
}

function pseudoNidOf(nid: string): string {
  return createHmac('sha256', NID_PEPPER).update(nid).digest('hex');
}

async function tokenPollOnce(
  clientId: string,
  clientSecret: string,
  authReqId: string,
): Promise<string> {
  const form = new URLSearchParams();
  form.set('grant_type', CIBA_GRANT_TYPE);
  form.set('auth_req_id', authReqId);
  const res = await fetch(`${BROKER_URL}/oidc/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
  });
  const body = (await res.json()) as { error?: string };
  return body.error ?? `http_${res.status}`;
}

const NID = MOCK_TEST_NIDS[1];
const BINDING_MESSAGE = 'Login to IFMIS · code 7Q42';

async function main(): Promise<void> {
  console.log(
    `${c.bold}${c.magenta}SDID Auth Bridge — “ghost login” (SPEC 09 §6)${c.reset}\n` +
      `${c.dim}A pilot RP completes a full CIBA login of a simulated phone against mock SDID:\n` +
      `the entire trust chain — device binding → signature auth → token issuance — end to end.${c.reset}`,
  );

  const harness = new BrokerHarness();
  const cleanups: Array<() => Promise<unknown>> = [];
  try {
    detail(`starting broker (node apps/broker/dist/main.js) on ${BROKER_URL} …`);
    await harness.start();
    await clearEnrolmentThrottles();
    detail(`broker up — migrations ran, OIDC discovery answering ${OK}`);

    // ① Pilot RP registration (admin-gated onboarding, 04 §6)
    const rp = await RpClient.registerViaAdmin(BROKER_URL, ADMIN_TOKEN, {
      name: 'Irembo (pilot)',
      allowedFlows: ['ciba', 'code'],
      allowedScopes: ['openid', 'profile', 'address'],
      maxAssurance: 'AL2',
      redirectUris: ['http://localhost:9450/cb'],
    });
    step('①', `Pilot RP ${c.bold}'Irembo'${c.reset} registered (client_id ${rp.clientId})`);
    detail(`allowed flows [ciba, code] · scopes [openid, profile, address] · max assurance AL2`);

    // ② Citizen enrolment: attestation + face match + key binding + activation
    const device = new SimDevice({
      brokerUrl: BROKER_URL,
      nid: NID,
      deviceLabel: `demo-phone-${randomBytes(4).toString('hex')}`,
    });
    let enrolled;
    try {
      enrolled = await device.enrol();
    } catch (err) {
      if (err instanceof Error && err.message.includes('Device limit reached')) {
        detail('5-device cap reached from earlier runs — revoking this citizen’s old bindings …');
        await revokeAllBindingsViaSql(pseudoNidOf(NID));
        await clearEnrolmentThrottles();
        enrolled = await device.enrol();
      } else {
        throw err;
      }
    }
    await device.login();
    cleanups.push(() => device.revokeBinding(device.bindingId!, 'demo-finished'));
    step(
      '②',
      `Citizen enrols: mock attestation ${OK}, face sample matched against mock-NIDA ` +
        `reference (in memory, zeroized) ${OK}, hardware-backed P-256 key bound, ` +
        `activation signature ${OK} — assurance ${c.bold}${enrolled.assuranceLevel}${c.reset}`,
    );
    detail(`binding ${enrolled.bindingId} · device label '${device.deviceLabel}'`);
    // 5-device cap hygiene: keep only this run's binding active (device API).
    const bindings = await device.listBindings();
    const older = bindings.filter((b) => b.bindingId !== device.bindingId && b.status !== 'revoked');
    for (const b of older) await device.revokeBinding(b.bindingId, 'demo-cap-hygiene');
    if (older.length > 0) detail(`revoked ${older.length} older binding(s) via the device API (5-device cap)`);

    // Onboarding hands the RP its pairwise login_hint for the citizen.
    const subject = await RpClient.provisionLoginHint(BROKER_URL, ADMIN_TOKEN, rp.rpId, pseudoNidOf(NID));
    detail(`RP provisioned with pairwise login_hint ${subject} (pseudo-NID in, never a raw NID)`);

    // ③ RP initiates CIBA
    const initiated = await rp.client.initiateCiba({
      loginHint: subject,
      scope: 'openid profile',
      bindingMessage: BINDING_MESSAGE,
    });
    step('③', `RP initiates CIBA: ${c.bold}'${BINDING_MESSAGE}'${c.reset}`);
    detail(`auth_req_id ${initiated.authReqId.slice(0, 12)}… · expires in ${initiated.expiresIn}s`);
    const early = await tokenPollOnce(rp.clientId, rp.clientSecret, initiated.authReqId);
    detail(`RP polls /oidc/token before the citizen decided → '${early}' (as it should be)`);

    // ④ wake-only push → device pulls pending over the backchannel
    const pending = await device.pullPending();
    const txn = pending.find((t) => t.authReqId === initiated.authReqId);
    if (!txn) throw new Error('pending CIBA transaction did not reach the device');
    step('④', 'Wake-only push → device pulls pending request over the authenticated backchannel');
    detail(`who: ${txn.rpName} · message: '${txn.bindingMessage}'`);
    detail(`asks: ${txn.scopeDescriptions.join(' · ')}`);

    // ⑤ approve: biometric unlocks the key, device signs the challenge
    const decision = await device.decide(initiated.authReqId, 'approve');
    step('⑤', `Citizen approves — biometric unlocks the key, device signs the challenge (${decision.status})`);

    // ⑥ broker verifies the signature and mints tokens
    const tokens = await rp.client.pollForTokens(initiated.authReqId, { timeoutMs: 30_000 });
    step('⑥', `Broker verifies signature, mints tokens; consent recorded ${OK}`);
    detail(`id_token ${tokens.idToken.slice(0, 24)}… · access_token ${tokens.accessToken.slice(0, 24)}…`);

    // ⑦ RP verifies the ID token against the broker JWKS
    const claims = await rp.client.verifyIdToken(tokens.idToken);
    step('⑦', `RP verifies ID token against the broker JWKS ${OK}`);
    console.log('');
    kv('iss', String(claims.iss));
    kv('aud', String(claims.aud));
    kv('sub', String(claims.sub));
    kv('acr', String(claims.acr));
    kv('amr', JSON.stringify(claims.amr));
    kv('auth_time', `${String(claims.auth_time)} (${new Date(Number(claims.auth_time) * 1000).toISOString()})`);
    const userinfo = (await rp.client.userinfo(tokens.accessToken)) as { name?: string };
    detail(`/oidc/userinfo (under the 'profile' consent) → name: ${userinfo.name ?? '—'}`);

    // Pairwise privacy: a second RP sees a DIFFERENT sub for the same citizen.
    console.log(`\n${c.magenta}${c.bold}Pairwise privacy${c.reset} — one citizen, two RPs, two unlinkable subjects:`);
    const rp2 = await RpClient.registerViaAdmin(BROKER_URL, ADMIN_TOKEN, {
      name: 'RRA e-Tax (pilot)',
      allowedFlows: ['ciba'],
      allowedScopes: ['openid', 'profile'],
      maxAssurance: 'AL2',
      redirectUris: [],
    });
    const subject2 = await RpClient.provisionLoginHint(BROKER_URL, ADMIN_TOKEN, rp2.rpId, pseudoNidOf(NID));
    const initiated2 = await rp2.client.initiateCiba({
      loginHint: subject2,
      scope: 'openid',
      bindingMessage: 'Login to e-Tax · code K9X1',
    });
    await device.decide(initiated2.authReqId, 'approve');
    const tokens2 = await rp2.client.pollForTokens(initiated2.authReqId, { timeoutMs: 30_000 });
    const claims2 = await rp2.client.verifyIdToken(tokens2.idToken);
    kv('Irembo', `sub ${String(claims.sub)}`);
    kv('RRA e-Tax', `sub ${String(claims2.sub)}`);
    if (claims.sub === claims2.sub) throw new Error('pairwise violation: identical sub across RPs');
    detail(`different subjects ${OK} — RPs cannot correlate the citizen across services (04 §4)`);

    // Tamper-evident audit chain.
    const auditRes = await fetch(`${BROKER_URL}/admin/audit/verify`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    const audit = (await auditRes.json()) as { intact: boolean; count: number };
    if (!auditRes.ok || !audit.intact) {
      throw new Error(`audit chain verification failed: ${JSON.stringify(audit)}`);
    }
    console.log(
      `\n${OK} ${c.bold}Audit chain intact${c.reset} — ${audit.count} hash-chained, append-only events cover ` +
        `every step above (GET /admin/audit/verify).`,
    );

    console.log(
      `\n${c.green}${c.bold}Ghost login complete.${c.reset} The trust chain — device binding → ` +
        `signature auth → token issuance — is proven end to end against mock SDID.`,
    );
  } finally {
    for (const cleanup of cleanups.reverse()) {
      try {
        await cleanup();
      } catch {
        // best-effort
      }
    }
    await harness.stop();
  }
}

main()
  .then(() => process.exit(0))
  .catch((err: unknown) => {
    console.error(`\n${c.red}${c.bold}Demo failed:${c.reset} ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
