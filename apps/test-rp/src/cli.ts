#!/usr/bin/env node
/**
 * Pilot RP CLI.
 *
 * Commands:
 *   login --hint <subject> [--message <text>] [--scope <scopes>] [--al <AL1|AL2|AL3>]
 *       Initiate CIBA, poll for tokens, verify the ID token, print claims.
 *       Env: BROKER_URL, CLIENT_ID, CLIENT_SECRET.
 *   register --name <name> [--scopes <s1,s2>] [--logo <uri>]
 *       Register this RP via the admin API. Env: BROKER_URL, ADMIN_API_TOKEN.
 *
 * Prints JSON.
 */
import { parseArgs } from 'node:util';
import type { AssuranceLevel } from '@sdid/shared';
import { RpClient } from './rp-client.js';

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      hint: { type: 'string' },
      message: { type: 'string' },
      scope: { type: 'string' },
      al: { type: 'string' },
      name: { type: 'string' },
      scopes: { type: 'string' },
      logo: { type: 'string' },
      timeout: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const command = positionals[0];
  if (values.help || !command) {
    printUsage();
    process.exitCode = command ? 0 : 1;
    return;
  }

  const brokerUrl = process.env.BROKER_URL ?? 'http://localhost:3000';

  switch (command) {
    case 'login': {
      const clientId = process.env.CLIENT_ID;
      const clientSecret = process.env.CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        fail('login requires env CLIENT_ID and CLIENT_SECRET');
        return;
      }
      if (!values.hint) {
        fail('login requires --hint <pairwise subject>');
        return;
      }
      const client = new RpClient({ brokerUrl, clientId, clientSecret });
      const initiated = await client.initiateCiba({
        loginHint: values.hint,
        ...(values.scope !== undefined ? { scope: values.scope } : {}),
        ...(values.message !== undefined ? { bindingMessage: values.message } : {}),
        ...(values.al !== undefined ? { requestedAl: values.al as AssuranceLevel } : {}),
      });
      console.error(
        `auth_req_id ${initiated.authReqId} — waiting for the citizen to approve on their phone…`,
      );
      const tokens = await client.pollForTokens(initiated.authReqId, {
        intervalMs: initiated.interval * 1000,
        ...(values.timeout !== undefined ? { timeoutMs: Number(values.timeout) } : {}),
      });
      const claims = await client.verifyIdToken(tokens.idToken);
      print({ authReqId: initiated.authReqId, claims, accessToken: tokens.accessToken });
      break;
    }
    case 'register': {
      const adminToken = process.env.ADMIN_API_TOKEN;
      if (!adminToken) {
        fail('register requires env ADMIN_API_TOKEN');
        return;
      }
      if (!values.name) {
        fail('register requires --name <RP name>');
        return;
      }
      const result = await RpClient.registerViaAdmin(brokerUrl, adminToken, {
        name: values.name,
        ...(values.scopes !== undefined ? { allowedScopes: values.scopes.split(',') } : {}),
        ...(values.logo !== undefined ? { logoUri: values.logo } : {}),
      });
      print({ rpId: result.rpId, clientId: result.clientId, clientSecret: result.clientSecret });
      break;
    }
    default:
      fail(`unknown command: ${command}`);
      printUsage();
  }
}

function print(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

function fail(message: string): void {
  console.error(`error: ${message}`);
  process.exitCode = 1;
}

function printUsage(): void {
  console.error(
    [
      'usage: test-rp <command>',
      '  login --hint <subject> [--message <text>] [--scope <scopes>] [--al <AL1|AL2|AL3>]',
      '        env: BROKER_URL, CLIENT_ID, CLIENT_SECRET',
      '  register --name <name> [--scopes <s1,s2>] [--logo <uri>]',
      '        env: BROKER_URL, ADMIN_API_TOKEN',
    ].join('\n'),
  );
}

main().catch((err: unknown) => {
  console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
