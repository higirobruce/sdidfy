#!/usr/bin/env node
/**
 * Thin CLI over SimDevice. Prints JSON results.
 *
 * Usage:
 *   device-sim <command> --nid <16-digit NID> [--broker <url>] [--label <text>]
 *
 * Commands:
 *   enrol                       enrol this simulated device
 *   login                       enrol + direct login (prints session token)
 *   pending                     list pending CIBA transactions
 *   approve [authReqId]         approve a pending transaction (first one if omitted)
 *   deny <authReqId> [--report] deny a pending transaction
 *   devices                     list this citizen's device bindings
 *
 * Broker URL from --broker or env BROKER_URL (default http://localhost:3000).
 *
 * Note: the simulated private key is non-exportable and lives only in this
 * process, so every invocation enrols a fresh binding before doing anything
 * that needs an authenticated session — exactly like a brand-new phone.
 */
import { parseArgs } from 'node:util';
import { SimDevice } from './sim-device.js';

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      nid: { type: 'string' },
      broker: { type: 'string' },
      label: { type: 'string' },
      report: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  const command = positionals[0];
  if (values.help || !command) {
    printUsage();
    process.exitCode = command ? 0 : 1;
    return;
  }

  const brokerUrl = values.broker ?? process.env.BROKER_URL ?? 'http://localhost:3000';
  const nid = values.nid;
  if (!nid) {
    fail('missing required --nid <16-digit NID>');
    return;
  }

  const device = new SimDevice({
    brokerUrl,
    nid,
    ...(values.label !== undefined ? { deviceLabel: values.label } : {}),
  });

  switch (command) {
    case 'enrol': {
      print(await device.enrol());
      break;
    }
    case 'login': {
      const enrolled = await device.enrol();
      const sessionToken = await device.login();
      print({ ...enrolled, sessionToken });
      break;
    }
    case 'pending': {
      await device.enrol();
      print(await device.pullPending());
      break;
    }
    case 'approve': {
      await device.enrol();
      const authReqId = positionals[1];
      if (authReqId) {
        print({ authReqId, ...(await device.decide(authReqId, 'approve')) });
      } else {
        print(await device.approveFirstPending());
      }
      break;
    }
    case 'deny': {
      const authReqId = positionals[1];
      if (!authReqId) {
        fail('deny requires an authReqId argument');
        return;
      }
      await device.enrol();
      print({
        authReqId,
        ...(await device.decide(authReqId, 'deny', {
          ...(values.report ? { reportSuspicious: true } : {}),
        })),
      });
      break;
    }
    case 'devices': {
      await device.enrol();
      print(await device.listBindings());
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
      'usage: device-sim <enrol|login|pending|approve|deny|devices> --nid <NID> [--broker <url>]',
      '  approve [authReqId]           approve a pending CIBA transaction (first if omitted)',
      '  deny <authReqId> [--report]   deny (optionally flag as suspicious)',
      '  env: BROKER_URL               broker base URL when --broker is not given',
    ].join('\n'),
  );
}

main().catch((err: unknown) => {
  console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
