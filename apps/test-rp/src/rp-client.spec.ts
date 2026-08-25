import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { CIBA_GRANT_TYPE } from '@sdid/shared';
import { afterEach, describe, expect, it } from 'vitest';
import { RpClient } from './rp-client.js';

interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
  body: string;
}

type ScriptedHandler = (req: RecordedRequest, res: ServerResponse) => void;

/** Stub broker: records every request and dispatches to scripted handlers by path. */
class StubBroker {
  readonly requests: RecordedRequest[] = [];
  private readonly handlers = new Map<string, ScriptedHandler>();
  private server?: Server;
  url = '';

  on(path: string, handler: ScriptedHandler): this {
    this.handlers.set(path, handler);
    return this;
  }

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => (body += chunk.toString('utf8')));
      req.on('end', () => {
        const recorded: RecordedRequest = {
          method: req.method ?? '',
          url: req.url ?? '',
          headers: req.headers,
          body,
        };
        this.requests.push(recorded);
        const handler = this.handlers.get((req.url ?? '').split('?')[0]!);
        if (!handler) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'not_found' }));
          return;
        }
        handler(recorded, res);
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const { port } = this.server!.address() as AddressInfo;
    this.url = `http://127.0.0.1:${port}`;
    return this.url;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve, reject) =>
      this.server!.close((err) => (err ? reject(err) : resolve())),
    );
    this.server = undefined;
  }
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

const TOKENS = {
  access_token: 'at-123',
  id_token: 'idt-456',
  token_type: 'Bearer' as const,
  expires_in: 300,
  scope: 'openid profile',
};

let broker: StubBroker;

afterEach(async () => {
  await broker?.stop();
});

function newClient(): RpClient {
  return new RpClient({
    brokerUrl: broker.url,
    clientId: 'client-abc',
    clientSecret: 's3cret',
  });
}

const EXPECTED_BASIC = `Basic ${Buffer.from('client-abc:s3cret').toString('base64')}`;

describe('RpClient.initiateCiba', () => {
  it('sends a client_secret_basic form-encoded request including binding_message and requested_al', async () => {
    broker = new StubBroker().on('/oidc/bc-authorize', (_req, res) =>
      json(res, 200, { auth_req_id: 'req-1', expires_in: 120, interval: 2 }),
    );
    await broker.start();

    const result = await newClient().initiateCiba({
      loginHint: 'pairwise-sub-1',
      bindingMessage: 'Login to IFMIS · code 7Q42',
      requestedAl: 'AL2',
    });

    expect(result).toEqual({ authReqId: 'req-1', expiresIn: 120, interval: 2 });

    const req = broker.requests[0]!;
    expect(req.method).toBe('POST');
    expect(req.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(req.headers['authorization']).toBe(EXPECTED_BASIC);

    const form = new URLSearchParams(req.body);
    expect(form.get('scope')).toBe('openid profile'); // default
    expect(form.get('login_hint')).toBe('pairwise-sub-1');
    expect(form.get('binding_message')).toBe('Login to IFMIS · code 7Q42');
    expect(form.get('requested_al')).toBe('AL2');
  });

  it('omits binding_message and requested_al when not given, honours a custom scope', async () => {
    broker = new StubBroker().on('/oidc/bc-authorize', (_req, res) =>
      json(res, 200, { auth_req_id: 'req-2', expires_in: 120, interval: 5 }),
    );
    await broker.start();

    await newClient().initiateCiba({ loginHint: 'sub-2', scope: 'openid address' });

    const form = new URLSearchParams(broker.requests[0]!.body);
    expect(form.get('scope')).toBe('openid address');
    expect(form.has('binding_message')).toBe(false);
    expect(form.has('requested_al')).toBe(false);
  });
});

describe('RpClient.pollForTokens', () => {
  it('keeps polling on authorization_pending, then resolves with the tokens', async () => {
    let calls = 0;
    broker = new StubBroker().on('/oidc/token', (_req, res) => {
      calls++;
      if (calls < 3) {
        json(res, 400, { error: 'authorization_pending' });
      } else {
        json(res, 200, TOKENS);
      }
    });
    await broker.start();

    const tokens = await newClient().pollForTokens('req-1', { intervalMs: 5, timeoutMs: 5000 });

    expect(calls).toBe(3);
    expect(tokens.idToken).toBe('idt-456');
    expect(tokens.accessToken).toBe('at-123');
    expect(tokens.raw).toEqual(TOKENS);

    // every poll used the CIBA grant + client_secret_basic
    for (const req of broker.requests) {
      expect(req.headers['authorization']).toBe(EXPECTED_BASIC);
      const form = new URLSearchParams(req.body);
      expect(form.get('grant_type')).toBe(CIBA_GRANT_TYPE);
      expect(form.get('auth_req_id')).toBe('req-1');
    }
  });

  it('backs off on slow_down and still resolves', async () => {
    let calls = 0;
    broker = new StubBroker().on('/oidc/token', (_req, res) => {
      calls++;
      if (calls === 1) json(res, 400, { error: 'slow_down' });
      else json(res, 200, TOKENS);
    });
    await broker.start();

    const tokens = await newClient().pollForTokens('req-1', { intervalMs: 1, timeoutMs: 10_000 });
    expect(calls).toBe(2);
    expect(tokens.accessToken).toBe('at-123');
  });

  it('throws on access_denied', async () => {
    broker = new StubBroker().on('/oidc/token', (_req, res) =>
      json(res, 400, { error: 'access_denied' }),
    );
    await broker.start();

    await expect(
      newClient().pollForTokens('req-1', { intervalMs: 5, timeoutMs: 5000 }),
    ).rejects.toThrow(/access_denied/);
  });

  it('throws on expired_token', async () => {
    broker = new StubBroker().on('/oidc/token', (_req, res) =>
      json(res, 400, { error: 'expired_token' }),
    );
    await broker.start();

    await expect(
      newClient().pollForTokens('req-1', { intervalMs: 5, timeoutMs: 5000 }),
    ).rejects.toThrow(/expired_token/);
  });

  it('throws on timeout while the request stays pending', async () => {
    broker = new StubBroker().on('/oidc/token', (_req, res) =>
      json(res, 400, { error: 'authorization_pending' }),
    );
    await broker.start();

    await expect(
      newClient().pollForTokens('req-1', { intervalMs: 20, timeoutMs: 60 }),
    ).rejects.toThrow(/timed out/);
  });
});

describe('RpClient admin statics', () => {
  it('registerViaAdmin posts JSON with the admin bearer and returns a ready client', async () => {
    broker = new StubBroker().on('/admin/rps', (_req, res) =>
      json(res, 201, {
        rpId: '3b241101-e2bb-4255-8caf-4136c566a962',
        clientId: 'rp-client-1',
        clientSecret: 'rp-secret-1',
      }),
    );
    await broker.start();

    const result = await RpClient.registerViaAdmin(broker.url, 'admin-token', {
      name: 'Pilot RP',
    });

    expect(result.rpId).toBe('3b241101-e2bb-4255-8caf-4136c566a962');
    expect(result.clientId).toBe('rp-client-1');
    expect(result.clientSecret).toBe('rp-secret-1');
    expect(result.client).toBeInstanceOf(RpClient);
    expect(result.client.clientId).toBe('rp-client-1');

    const req = broker.requests[0]!;
    expect(req.headers['authorization']).toBe('Bearer admin-token');
    expect(req.headers['content-type']).toBe('application/json');
    const body = JSON.parse(req.body);
    expect(body.name).toBe('Pilot RP');
    expect(body.allowedFlows).toEqual(['ciba']);
    expect(body.allowedScopes).toEqual(['openid', 'profile']);
    expect(body.authMethod).toBe('secret');
  });

  it('provisionLoginHint posts the pseudoNid and returns the subject', async () => {
    broker = new StubBroker().on('/admin/rps/rp-1/pairwise', (_req, res) =>
      json(res, 200, { subject: 'pairwise-xyz' }),
    );
    await broker.start();

    const subject = await RpClient.provisionLoginHint(broker.url, 'admin-token', 'rp-1', 'pn-77');
    expect(subject).toBe('pairwise-xyz');

    const req = broker.requests[0]!;
    expect(req.headers['authorization']).toBe('Bearer admin-token');
    expect(JSON.parse(req.body)).toEqual({ pseudoNid: 'pn-77' });
  });
});
