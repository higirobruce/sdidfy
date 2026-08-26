import { generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createSdidProvider, type SdidAuditHookEvent } from './index.js';
import {
  SdidCircuitOpenError,
  SdidConfigurationError,
  SdidMalformedResponseError,
  SdidTimeoutError,
  SdidUnavailableError,
  SdidUnknownIdentityError,
} from './errors.js';
import { OidcEsignetStrategy, type OidcEsignetStrategyOptions } from './oidc-esignet-strategy.js';
import { ResilientSdidProvider } from './resilience.js';
import { sdidSubjectForNid } from './pseudonym.js';
import { runSdidProviderContractTests } from './contract-tests.js';
import {
  FAKE_CLIENT_ID,
  FAKE_CLIENT_SECRET,
  FAKE_ISSUER,
  FAKE_KNOWN_NIDS,
  FAKE_UNKNOWN_NID,
  FakeSdid,
  fakeOidcAttributesConfig,
  fakeReassertChecker,
  fakeReferenceFetcher,
  fakeSubjectResolver,
  type FakeSdidOptions,
} from './fake-sdid.fixture.js';

/**
 * OidcEsignetStrategy tests. Everything here exercises behaviour that is
 * genuinely knowable from the OIDC/eSignet shape today (discovery, client
 * auth, token caching, boundary validation, error mapping) plus the
 * fail-loudly behaviour of the A1/A2 holes. The fake SDID is a stand-in, not
 * a claim about SDID's real shape (02 §3).
 */

const PEPPER = 'oidc-contract-test-pepper';
const KNOWN = FAKE_KNOWN_NIDS[0];

/** Assert a rejection and return the error, typed. */
async function rejection<T = Error>(p: Promise<unknown>): Promise<T> {
  return await p.then(
    () => {
      throw new Error('expected the call to reject');
    },
    (e: unknown) => e as T,
  );
}

function oidcOptions(
  fake: FakeSdid,
  overrides: Partial<OidcEsignetStrategyOptions> = {},
): OidcEsignetStrategyOptions {
  return {
    issuer: FAKE_ISSUER,
    clientId: FAKE_CLIENT_ID,
    clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
    tokenScopes: ['sdid.identity.read'],
    nidPepper: PEPPER,
    transport: fake.transport,
    referenceBiometric: fakeReferenceFetcher('/biometrics/reference'),
    attributes: fakeOidcAttributesConfig('/oidc/userinfo'),
    reassert: fakeReassertChecker('/identity/status'),
    subjectResolver: fakeSubjectResolver(PEPPER, FAKE_KNOWN_NIDS),
    ...overrides,
  };
}

const strategyOn = (
  opts: FakeSdidOptions = {},
  overrides: Partial<OidcEsignetStrategyOptions> = {},
): { fake: FakeSdid; strategy: OidcEsignetStrategy } => {
  const fake = new FakeSdid(opts);
  return { fake, strategy: new OidcEsignetStrategy(oidcOptions(fake, overrides)) };
};

// --- The point of the exercise (09 §3): the SAME contract suite the mock
// --- passes, driven against the real strategy over a fake HTTP transport.
runSdidProviderContractTests('OidcEsignetStrategy (fake SDID transport)', () => ({
  provider: strategyOn().strategy,
  knownNid: KNOWN,
  unknownNid: FAKE_UNKNOWN_NID,
}));

runSdidProviderContractTests('createSdidProvider(oidc) (resilience + audit wrapped)', () => {
  const fake = new FakeSdid();
  return {
    provider: createSdidProvider({
      strategy: 'oidc',
      nidPepper: PEPPER,
      oidc: oidcOptions(fake),
      resilience: { retryBaseDelayMs: 1 },
      onAudit: async () => undefined,
    }),
    knownNid: KNOWN,
    unknownNid: FAKE_UNKNOWN_NID,
  };
});

describe('OidcEsignetStrategy: discovery', () => {
  it('fetches the discovery document once and caches it across calls', async () => {
    const { fake, strategy } = strategyOn();
    await strategy.reassert(KNOWN);
    await strategy.reassert(KNOWN);
    await strategy.getAttributes(KNOWN, ['profile']);
    expect(fake.countRequests('/.well-known/openid-configuration')).toBe(1);
  });

  it('re-fetches discovery after the cache TTL expires', async () => {
    const fake = new FakeSdid();
    let now = 1_000_000;
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, { discoveryTtlMs: 60_000, clock: () => now }),
    );
    await strategy.reassert(KNOWN);
    now += 61_000;
    await strategy.reassert(KNOWN);
    expect(fake.countRequests('/.well-known/openid-configuration')).toBe(2);
  });

  it('de-duplicates concurrent discovery fetches', async () => {
    const { fake, strategy } = strategyOn();
    await Promise.all([strategy.reassert(KNOWN), strategy.reassert(KNOWN)]);
    expect(fake.countRequests('/.well-known/openid-configuration')).toBe(1);
  });

  it('rejects a discovery document whose issuer does not match (mix-up defence)', async () => {
    const { strategy } = strategyOn({ discoveryOverride: { issuer: 'https://evil.example' } });
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidMalformedResponseError);
  });

  it('rejects a discovery document that is not valid JSON', async () => {
    const { strategy } = strategyOn({ discoveryOverride: { rawBody: 'not-json' } });
    await expect(strategy.reassert(KNOWN)).rejects.toThrow(/discovery: body is not valid JSON/);
  });

  it('surfaces a discovery HTTP failure instead of continuing without metadata', async () => {
    const { strategy } = strategyOn({ forceStatus: { urlContains: '.well-known', status: 503 } });
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('uses a configured non-standard discovery URL when SDID publishes one', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        discoveryUrl: `${FAKE_ISSUER}/esignet/.well-known/openid-configuration`,
      }),
    );
    // The fake only serves the standard path, so this must fail — proving the
    // override is honoured rather than silently ignored.
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    expect(fake.countRequests('/esignet/.well-known/openid-configuration')).toBe(1);
  });
});

describe('OidcEsignetStrategy: client authentication (Q3, detail A3)', () => {
  const tokenRequest = (fake: FakeSdid) =>
    fake.requests.find((r) => r.url.endsWith('/oauth2/token'))!;

  it('client_secret_basic sends RFC 6749 §2.3.1 Basic credentials and the requested scope', async () => {
    const { fake, strategy } = strategyOn();
    await strategy.reassert(KNOWN);
    const req = tokenRequest(fake);
    expect(req.headers.authorization).toBe(
      `Basic ${Buffer.from(`${FAKE_CLIENT_ID}:${FAKE_CLIENT_SECRET}`).toString('base64')}`,
    );
    expect(req.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(req.body).toContain('grant_type=client_credentials');
    expect(req.body).toContain('scope=sdid.identity.read');
    // The secret is never placed in the body when Basic is in use.
    expect(req.body).not.toContain('client_secret');
  });

  it('client_secret_post sends credentials in the form body instead of a header', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        clientAuth: { method: 'client_secret_post', clientSecret: FAKE_CLIENT_SECRET },
      }),
    );
    await strategy.reassert(KNOWN);
    const req = tokenRequest(fake);
    expect(req.headers.authorization).toBeUndefined();
    expect(req.body).toContain(`client_id=${FAKE_CLIENT_ID}`);
    expect(req.body).toContain('client_secret=');
  });

  it('private_key_jwt produces an RFC 7523 assertion bound to the token endpoint', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        clientAuth: {
          method: 'private_key_jwt',
          privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
          alg: 'ES256',
          kid: 'bridge-key-1',
        },
      }),
    );
    await strategy.reassert(KNOWN);

    const body = new URLSearchParams(tokenRequest(fake).body!);
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    const jwt = body.get('client_assertion')!;
    const [h, p, s] = jwt.split('.');
    const header = JSON.parse(Buffer.from(h!, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8'));
    expect(header).toMatchObject({ alg: 'ES256', typ: 'JWT', kid: 'bridge-key-1' });
    expect(payload.iss).toBe(FAKE_CLIENT_ID);
    expect(payload.sub).toBe(FAKE_CLIENT_ID);
    // Audience-bound: a captured assertion cannot be replayed elsewhere.
    expect(payload.aud).toBe(`${FAKE_ISSUER}/oauth2/token`);
    expect(payload.exp).toBeGreaterThan(payload.iat);
    expect(
      cryptoVerify(
        'sha256',
        Buffer.from(`${h}.${p}`),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(s!, 'base64url'),
      ),
    ).toBe(true);
  });

  it('caches the access token across calls and presents it as a bearer header', async () => {
    const { fake, strategy } = strategyOn();
    await strategy.reassert(KNOWN);
    await strategy.reassert(KNOWN);
    await strategy.getAttributes(KNOWN, ['profile']);
    expect(fake.countRequests('/oauth2/token')).toBe(1);
    const resourceCall = fake.requests.find((r) => r.url.includes('/identity/status'))!;
    expect(resourceCall.headers.authorization).toBe('Bearer fake-access-token-1');
  });

  it('de-duplicates concurrent token acquisitions (no token-endpoint stampede, A5)', async () => {
    const { fake, strategy } = strategyOn();
    await Promise.all([
      strategy.reassert(KNOWN),
      strategy.reassert(KNOWN),
      strategy.reassert(KNOWN),
    ]);
    expect(fake.countRequests('/oauth2/token')).toBe(1);
  });

  it('re-acquires a token after SDID rejects the cached one (A3 rotation)', async () => {
    const { fake, strategy } = strategyOn();
    await strategy.reassert(KNOWN);
    expect(fake.countRequests('/oauth2/token')).toBe(1);

    fake.rotateCredentials(); // every issued token is now rejected with 401
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    // The rejected token was dropped, so the next attempt re-authenticates.
    await strategy.reassert(KNOWN);
    expect(fake.countRequests('/oauth2/token')).toBe(2);
  });

  it('maps a token-endpoint 401 to unavailable and never echoes the error body', async () => {
    const { strategy } = strategyOn({ failTokenRequests: 1 });
    const err = await rejection(strategy.reassert(KNOWN));
    expect(err).toBeInstanceOf(SdidUnavailableError);
    expect(err.message).toMatch(/token endpoint returned HTTP 401/);
    // An OAuth error body can carry the client_id and, from a misbehaving
    // server, echoed credentials — so it is never placed in the message.
    expect(err.message).not.toContain('invalid_client');
    expect(err.message).not.toContain(FAKE_CLIENT_SECRET);
  });

  it('refuses a non-bearer token_type rather than coercing a header', async () => {
    const { strategy } = strategyOn({
      forceStatus: {
        urlContains: '/oauth2/token',
        status: 200,
        body: JSON.stringify({ access_token: 'x', token_type: 'MAC', expires_in: 60 }),
      },
    });
    await expect(strategy.reassert(KNOWN)).rejects.toThrow(/unsupported token_type/);
  });
});

describe('OidcEsignetStrategy: error mapping (errors.ts taxonomy)', () => {
  it('404 on a resource maps to SdidUnknownIdentityError', async () => {
    const { strategy } = strategyOn();
    await expect(
      strategy.getReferenceBiometric({ nid: FAKE_UNKNOWN_NID, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('401 on a resource maps to unavailable, NOT to unknown identity', async () => {
    const { strategy } = strategyOn({
      forceStatus: { urlContains: '/biometrics/reference', status: 401 },
    });
    const err = await rejection(strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }));
    expect(err).toBeInstanceOf(SdidUnavailableError);
    expect(err).not.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('500 maps to SdidUnavailableError', async () => {
    const { strategy } = strategyOn({
      forceStatus: { urlContains: '/identity/status', status: 500 },
    });
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('429 is reported as unavailable with the quota context (A5)', async () => {
    const { strategy } = strategyOn({
      forceStatus: { urlContains: '/identity/status', status: 429 },
    });
    await expect(strategy.reassert(KNOWN)).rejects.toThrow(/rate-limited/);
  });

  it('a hung socket becomes SdidTimeoutError, not a raw abort error', async () => {
    const fake = new FakeSdid({ hang: true });
    const strategy = new OidcEsignetStrategy(oidcOptions(fake, { httpTimeoutMs: 20 }));
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidTimeoutError);
  });

  it('the resilience wrapper still enforces its own contract timeout', async () => {
    const fake = new FakeSdid({ hang: true });
    const provider = new ResilientSdidProvider(
      new OidcEsignetStrategy(oidcOptions(fake, { httpTimeoutMs: 50 })),
      { timeoutMs: 20, retries: 0 },
    );
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidTimeoutError);
  });
});

describe('OidcEsignetStrategy: boundary validation (02 §4)', () => {
  it('rejects a userinfo body that is not JSON', async () => {
    const { strategy } = strategyOn({ userinfoRawBody: '<html>maintenance</html>' });
    await expect(strategy.getAttributes(KNOWN, ['profile'])).rejects.toBeInstanceOf(
      SdidMalformedResponseError,
    );
  });

  it('rejects a userinfo body that is not a claims object', async () => {
    const { strategy } = strategyOn({ userinfoRawBody: '["not","an","object"]' });
    await expect(strategy.getAttributes(KNOWN, ['profile'])).rejects.toBeInstanceOf(
      SdidMalformedResponseError,
    );
  });

  it('drops a claim of the wrong type rather than forwarding it', async () => {
    const { strategy } = strategyOn({
      userinfoRawBody: JSON.stringify({ name: 12345, birthdate: '1990-01-01' }),
    });
    const attrs = await strategy.getAttributes(KNOWN, ['profile']);
    expect(attrs.name).toBeUndefined();
    expect(attrs.dateOfBirth).toBe('1990-01-01');
  });

  it('rejects an empty reference template', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        referenceBiometric: async () => ({ data: new Uint8Array(0), format: 'iso-19794' }),
      }),
    );
    await expect(
      strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidMalformedResponseError);
  });

  it('rejects a reference template in an unrecognised format', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        referenceBiometric: async () =>
          ({ data: new Uint8Array([1, 2, 3]), format: 'who-knows' }) as never,
      }),
    );
    await expect(
      strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidMalformedResponseError);
  });

  it('a malformed-response error carries issue paths only — never the bytes', async () => {
    const secret = new Uint8Array([9, 9, 9, 9]);
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, {
        referenceBiometric: async () => ({ data: secret, format: 'nope' }) as never,
      }),
    );
    const err = await rejection(strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }));
    expect(err.message).toContain('format');
    expect(err.message).not.toContain(Buffer.from(secret).toString('base64'));
    expect(err.message).not.toContain(KNOWN);
  });

  it('rejects a reassert payload with an unknown assurance level', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, { reassert: async () => ({ valid: true, assurance: 'AL9' }) as never }),
    );
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidMalformedResponseError);
  });
});

describe('OidcEsignetStrategy: unconfigured A1/A2 gaps fail loudly', () => {
  const bare = (fake = new FakeSdid()): OidcEsignetStrategy =>
    new OidcEsignetStrategy({
      issuer: FAKE_ISSUER,
      clientId: FAKE_CLIENT_ID,
      clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
      nidPepper: PEPPER,
      transport: fake.transport,
    });

  it('reports every unfilled gap with its open-question id', () => {
    expect(bare().describeGaps()).toEqual([
      expect.objectContaining({ optionPath: 'oidc.referenceBiometric', openQuestion: 'A2' }),
      expect.objectContaining({ optionPath: 'oidc.attributes', openQuestion: 'A1' }),
      expect.objectContaining({ optionPath: 'oidc.reassert', openQuestion: 'A1' }),
      expect.objectContaining({ optionPath: 'oidc.subjectResolver', openQuestion: 'A1/A3' }),
    ]);
  });

  it('getReferenceBiometric throws a descriptive SdidConfigurationError naming A2', async () => {
    const err = await rejection<SdidConfigurationError>(
      bare().getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    );
    expect(err).toBeInstanceOf(SdidConfigurationError);
    expect(err.optionPath).toBe('oidc.referenceBiometric');
    expect(err.openQuestion).toBe('A2');
    expect(err.message).toMatch(/do not guess a default/);
  });

  it('never issues an HTTP call for an unconfigured gap', async () => {
    const fake = new FakeSdid();
    await expect(bare(fake).reassert(KNOWN)).rejects.toBeInstanceOf(SdidConfigurationError);
    expect(fake.requests).toHaveLength(0);
  });

  it('the /userinfo-by-subject path fails loudly when no subject resolver is configured', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, { subjectResolver: undefined as never }),
    );
    const err = await rejection<SdidConfigurationError>(
      strategy.getAttributes(sdidSubjectForNid(KNOWN, PEPPER), ['profile']),
    );
    expect(err).toBeInstanceOf(SdidConfigurationError);
    expect(err.optionPath).toBe('oidc.subjectResolver');
    // A raw NID still works — only the pseudonymous path is blocked.
    await expect(strategy.getAttributes(KNOWN, ['profile'])).resolves.toBeTruthy();
  });

  it('a configuration error is never retried and never trips the circuit breaker', async () => {
    const fake = new FakeSdid();
    const provider = new ResilientSdidProvider(bare(fake), {
      retries: 3,
      retryBaseDelayMs: 1,
      breakerFailureThreshold: 1,
    });
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidConfigurationError);
    expect(provider.circuitState).toBe('closed');
    expect(fake.requests).toHaveLength(0);
  });
});

describe('createSdidProvider(oidc): composition and fail-closed configuration', () => {
  it('refuses to start without the oidc configuration block', () => {
    expect(() => createSdidProvider({ strategy: 'oidc' })).toThrow(SdidConfigurationError);
    expect(() => createSdidProvider({ strategy: 'oidc' })).toThrow(
      /requires the `oidc` configuration block/,
    );
  });

  it('refuses to start when A1/A2 adapter functions are missing (fail closed)', () => {
    const fake = new FakeSdid();
    const call = (): unknown =>
      createSdidProvider({
        strategy: 'oidc',
        nidPepper: PEPPER,
        oidc: {
          issuer: FAKE_ISSUER,
          clientId: FAKE_CLIENT_ID,
          clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
          transport: fake.transport,
        },
      });
    expect(call).toThrow(SdidConfigurationError);
    expect(call).toThrow(/oidc.referenceBiometric/);
    expect(call).toThrow(/A2/);
  });

  it('requireFullyConfigured:false starts, but the unfilled method still throws', async () => {
    const fake = new FakeSdid();
    const provider = createSdidProvider({
      strategy: 'oidc',
      nidPepper: PEPPER,
      requireFullyConfigured: false,
      resilience: { retryBaseDelayMs: 1 },
      oidc: {
        issuer: FAKE_ISSUER,
        clientId: FAKE_CLIENT_ID,
        clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
        transport: fake.transport,
        reassert: fakeReassertChecker('/identity/status'),
      },
    });
    await expect(provider.reassert(KNOWN)).resolves.toMatchObject({ valid: true });
    await expect(
      provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidConfigurationError);
  });

  it('routes the real strategy through the circuit breaker (02 §4)', async () => {
    const fake = new FakeSdid({ forceStatus: { urlContains: '/identity/status', status: 500 } });
    const provider = createSdidProvider({
      strategy: 'oidc',
      nidPepper: PEPPER,
      oidc: oidcOptions(fake),
      resilience: {
        retries: 0,
        retryBaseDelayMs: 1,
        breakerFailureThreshold: 2,
        breakerResetMs: 60_000,
      },
    });
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    // Breaker is now open: SDID is not called at all.
    const before = fake.requests.length;
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidCircuitOpenError);
    expect(fake.requests.length).toBe(before);
  });

  it('audits every real-strategy call pseudonymously, with no template bytes (07 §1)', async () => {
    const events: SdidAuditHookEvent[] = [];
    const fake = new FakeSdid();
    const provider = createSdidProvider({
      strategy: 'oidc',
      nidPepper: PEPPER,
      oidc: oidcOptions(fake),
      onAudit: async (e) => {
        events.push(e);
      },
    });
    const res = await provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' });

    expect(events).toHaveLength(1);
    const event = events[0]!;
    expect(event.action).toBe('sdid.reference_fetched');
    expect(event.result).toBe('success');
    expect(event.subjectRef).toBe(sdidSubjectForNid(KNOWN, PEPPER));
    expect(event.txnRef).toBe(res.txnRef);
    expect(event.context).toMatchObject({ strategy: 'oidc', modality: 'face' });

    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(KNOWN); // raw NID never at rest (Q8, 07 §3)
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('base64'));
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('hex'));
  });

  it('uses the SDID-supplied txnRef when the response carries one', async () => {
    const { strategy } = strategyOn();
    const res = await strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' });
    expect(res.txnRef).toMatch(/^fake-txn-\d+$/);
  });

  it('falls back to a locally generated txnRef when SDID supplies none', async () => {
    const fake = new FakeSdid();
    const strategy = new OidcEsignetStrategy(
      oidcOptions(fake, { reassert: async () => ({ valid: true, assurance: 'AL2' }) }),
    );
    const res = await strategy.reassert(KNOWN);
    expect(res.txnRef).toMatch(/^oidc-[0-9a-f]{16}$/);
  });
});
