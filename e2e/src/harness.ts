/**
 * E2E harness for the "ghost login" milestone (SPEC 09 §6): starts the real
 * broker (apps/broker/dist/main.js) as a child process on a dedicated port,
 * waits for OIDC discovery to come up, and tears it down again. The broker
 * boot auto-runs migrations, so a clean database Just Works.
 */
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Repo root: this file compiles to <root>/e2e/dist/harness.js. */
export const REPO_ROOT = path.resolve(__dirname, '..', '..');

export const BROKER_PORT = 3199;
export const BROKER_URL = `http://localhost:${BROKER_PORT}`;
export const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN ?? 'dev-admin-token';
export const NID_PEPPER = process.env.NID_PEPPER ?? 'dev-only-nid-pepper-change-me';
export const DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://sdid:sdid_dev@localhost:5432/sdid_bridge';

const DISCOVERY_URL = `${BROKER_URL}/.well-known/openid-configuration`;
const START_TIMEOUT_MS = 30_000;

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Build the broker once if its dist entrypoint is missing. */
export async function ensureBrokerBuilt(): Promise<void> {
  const entry = path.join(REPO_ROOT, 'apps', 'broker', 'dist', 'main.js');
  if (existsSync(entry)) return;
  await execFileAsync('pnpm', ['build'], { cwd: REPO_ROOT, timeout: 300_000 });
  if (!existsSync(entry)) {
    throw new Error(`pnpm build completed but ${entry} is still missing`);
  }
}

export class BrokerHarness {
  private child?: ChildProcess;
  private outputChunks: string[] = [];
  private exited = false;
  private exitInfo = '';

  readonly brokerUrl = BROKER_URL;

  /** Everything the broker wrote to stdout/stderr so far. */
  get output(): string {
    return this.outputChunks.join('');
  }

  async start(): Promise<void> {
    if (this.child) throw new Error('broker already started');
    await ensureBrokerBuilt();

    // Fail fast if something else is already answering on the e2e port.
    if (await this.discoveryUp()) {
      throw new Error(
        `something is already listening on ${BROKER_URL} — stop it before running the e2e harness`,
      );
    }

    const entry = path.join(REPO_ROOT, 'apps', 'broker', 'dist', 'main.js');
    this.outputChunks = [];
    this.exited = false;
    this.exitInfo = '';
    this.child = spawn(process.execPath, [entry], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        BROKER_PORT: String(BROKER_PORT),
        BROKER_ISSUER: BROKER_URL,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child.stdout?.on('data', (d: Buffer) => this.outputChunks.push(d.toString('utf8')));
    this.child.stderr?.on('data', (d: Buffer) => this.outputChunks.push(d.toString('utf8')));
    this.child.on('exit', (code, signal) => {
      this.exited = true;
      this.exitInfo = `exit code=${code} signal=${signal}`;
    });

    const deadline = Date.now() + START_TIMEOUT_MS;
    while (Date.now() < deadline) {
      if (this.exited) break;
      if (await this.discoveryUp()) return;
      await sleep(250);
    }
    const output = this.output;
    await this.stop();
    throw new Error(
      `broker did not answer on ${DISCOVERY_URL} within ${START_TIMEOUT_MS}ms` +
        (this.exitInfo ? ` (process ${this.exitInfo})` : '') +
        `\n--- broker output ---\n${output}`,
    );
  }

  async stop(): Promise<void> {
    const child = this.child;
    this.child = undefined;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const gone = new Promise<void>((resolve) => child.once('exit', () => resolve()));
    child.kill('SIGTERM');
    const timeout = sleep(5_000).then(() => 'timeout' as const);
    if ((await Promise.race([gone, timeout])) === 'timeout') {
      child.kill('SIGKILL');
      await gone;
    }
  }

  private async discoveryUp(): Promise<boolean> {
    try {
      const res = await fetch(DISCOVERY_URL);
      return res.status === 200;
    } catch {
      return false;
    }
  }
}

/**
 * Clear the broker's per-NID/per-IP enrolment rate-limit and lockout windows
 * in Redis (dev instance) so the suite and demo stay re-runnable — the broker
 * allows only 5 enrolment starts per NID per hour, which honest repeated runs
 * would otherwise exhaust. Touches only `rl:enrol:*` / `lockout:enrol:*` keys.
 */
export async function clearEnrolmentThrottles(): Promise<void> {
  const script = [
    "for k in $(redis-cli --scan --pattern 'rl:enrol:*'); do redis-cli del \"$k\" >/dev/null; done",
    "for k in $(redis-cli --scan --pattern 'lockout:enrol:*'); do redis-cli del \"$k\" >/dev/null; done",
  ].join('; ');
  try {
    await execFileAsync('sh', ['-c', script], { timeout: 15_000 });
  } catch {
    // Redis CLI unavailable — enrolment may hit the hourly window instead.
  }
}

/**
 * Last-resort cleanup for the 5-device cap: mark every binding of the citizen
 * behind `pseudoNid` revoked, via the psql CLI (the e2e package deliberately
 * has no direct DB dependency). Used only when enrolment reports the cap.
 */
export async function revokeAllBindingsViaSql(pseudoNid: string): Promise<void> {
  const sql =
    `UPDATE device_bindings SET status='revoked', revoked_at=now(), revoke_reason='e2e-cap-cleanup' ` +
    `WHERE status <> 'revoked' AND citizen_id = (SELECT id FROM citizens WHERE pseudo_nid = '${pseudoNid}')`;
  await execFileAsync('psql', [DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-c', sql], {
    timeout: 15_000,
  });
}
