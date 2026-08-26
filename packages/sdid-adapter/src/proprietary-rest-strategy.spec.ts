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
import {
  ProprietaryRestStrategy,
  type ProprietaryRestStrategyOptions,
} from './proprietary-rest-strategy.js';
import { sdidSubjectForNid } from './pseudonym.js';
import { runSdidProviderContractTests } from './contract-tests.js';
import {
  FAKE_API_KEY,
  FAKE_CLIENT_ID,
  FAKE_CLIENT_SECRET,
  FAKE_ISSUER,
  FAKE_KNOWN_NIDS,
  FAKE_UNKNOWN_NID,
  FakeSdid,
  fakeProprietaryAttributesFetcher,
  fakeReassertChecker,
  fakeReferenceFetcher,
  fakeSubjectResolver,
  type FakeSdidOptions,
} from './fake-sdid.fixture.js';

/**
 * ProprietaryRestStrategy tests. A bespoke API has no inferable shape, so what
 * is asserted here is exactly what the strategy owns regardless of A1: client
 * authentication, the authenticated call layer, boundary validation, error
 * mapping, pseudonymous subjects (Q8), our scope policy (Q9), and loud failure
 * on unfilled gaps. The fake SDID is a stand-in, not a claim (02 §3).
 */

const PEPPER = 'proprietary-contract-test-pepper';
const BASE_URL = `${FAKE_ISSUER}/v1`;
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

function restOptions(
  fake: FakeSdid,
  overrides: Partial<ProprietaryRestStrategyOptions> = {},
): ProprietaryRestStrategyOptions {
  return {
    baseUrl: BASE_URL,
    auth: { scheme: 'api-key', headerName: 'x-api-key', apiKey: FAKE_API_KEY },
    nidPepper: PEPPER,
    transport: fake.transport,
    referenceBiometric: fakeReferenceFetcher('/identity/reference-template'),
    attributes: fakeProprietaryAttributesFetcher('/identity/attributes'),
    reassert: fakeReassertChecker('/identity/status'),
    subjectResolver: fakeSubjectResolver(PEPPER, FAKE_KNOWN_NIDS),
    ...overrides,
  };
}

const strategyOn = (
  opts: FakeSdidOptions = {},
  overrides: Partial<ProprietaryRestStrategyOptions> = {},
): { fake: FakeSdid; strategy: ProprietaryRestStrategy } => {
  const fake = new FakeSdid(opts);
  return { fake, strategy: new ProprietaryRestStrategy(restOptions(fake, overrides)) };
};

// --- 09 §3: the same contract suite, same guarantees, different wire shape.
runSdidProviderContractTests('ProprietaryRestStrategy (fake SDID transport)', () => ({
  provider: strategyOn().strategy,
  knownNid: KNOWN,
  unknownNid: FAKE_UNKNOWN_NID,
}));

runSdidProviderContractTests('createSdidProvider(proprietary) (resilience + audit wrapped)', () => {
  const fake = new FakeSdid();
  return {
    provider: createSdidProvider({
      strategy: 'proprietary',
      nidPepper: PEPPER,
      proprietary: restOptions(fake),
      resilience: { retryBaseDelayMs: 1 },
      onAudit: async () => undefined,
    }),
    knownNid: KNOWN,
    unknownNid: FAKE_UNKNOWN_NID,
  };
});

describe('ProprietaryRestStrategy: client authentication (Q3, detail A3)', () => {
  const resourceCall = (fake: FakeSdid) =>
    fake.requests.find((r) => r.url.includes('/identity/status'))!;

  it('api-key scheme sets the configured header, lower-cased', async () => {
    const { fake, strategy } = strategyOn();
    await strategy.reassert(KNOWN);
    expect(resourceCall(fake).headers['x-api-key']).toBe(FAKE_API_KEY);
    expect(resourceCall(fake).headers.authorization).toBeUndefined();
  });

  it('bearer-static scheme presents the credential as a bearer token', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, { auth: { scheme: 'bearer-static', token: 'static-bearer' } }),
    );
    await strategy.reassert(KNOWN);
    expect(resourceCall(fake).headers.authorization).toBe('Bearer static-bearer');
  });

  it('oauth2-client-credentials acquires, caches and presents a token', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        auth: {
          scheme: 'oauth2-client-credentials',
          tokenEndpoint: `${FAKE_ISSUER}/oauth2/token`,
          clientId: FAKE_CLIENT_ID,
          clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
          scopes: ['sdid.identity.read'],
        },
      }),
    );
    await strategy.reassert(KNOWN);
    await strategy.reassert(KNOWN);
    expect(fake.countRequests('/oauth2/token')).toBe(1);
    expect(resourceCall(fake).headers.authorization).toBe('Bearer fake-access-token-1');
  });

  it('re-acquires an OAuth2 token after SDID rejects the cached one (A3 rotation)', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        auth: {
          scheme: 'oauth2-client-credentials',
          tokenEndpoint: `${FAKE_ISSUER}/oauth2/token`,
          clientId: FAKE_CLIENT_ID,
          clientAuth: { method: 'client_secret_basic', clientSecret: FAKE_CLIENT_SECRET },
        },
      }),
    );
    await strategy.reassert(KNOWN);
    fake.rotateCredentials();
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await strategy.reassert(KNOWN);
    expect(fake.countRequests('/oauth2/token')).toBe(2);
  });

  it('custom scheme can sign each request (HMAC / WS-Security shapes, A1)', async () => {
    const fake = new FakeSdid();
    const signed: string[] = [];
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        auth: {
          scheme: 'custom',
          apply: (req) => {
            const signature = `sig-over-${new URL(req.url).pathname}`;
            signed.push(signature);
            return { ...req, headers: { ...(req.headers ?? {}), 'x-sdid-signature': signature } };
          },
        },
      }),
    );
    await strategy.reassert(KNOWN);
    expect(resourceCall(fake).headers['x-sdid-signature']).toBe('sig-over-/v1/identity/status');
    expect(signed).toHaveLength(1);
  });
});

describe('ProprietaryRestStrategy: error mapping (errors.ts taxonomy)', () => {
  it('404 maps to SdidUnknownIdentityError', async () => {
    const { strategy } = strategyOn();
    await expect(
      strategy.getReferenceBiometric({ nid: FAKE_UNKNOWN_NID, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('honours a bespoke not-found status when the API does not use 404', async () => {
    const { strategy } = strategyOn(
      { forceStatus: { urlContains: '/identity/attributes', status: 410 } },
      { notFoundStatuses: [410] },
    );
    await expect(strategy.getAttributes(KNOWN, ['profile'])).rejects.toBeInstanceOf(
      SdidUnknownIdentityError,
    );
  });

  it('a status NOT listed as not-found stays an availability failure', async () => {
    const { strategy } = strategyOn(
      { forceStatus: { urlContains: '/identity/attributes', status: 410 } },
      { notFoundStatuses: [404] },
    );
    const err = await rejection(strategy.getAttributes(KNOWN, ['profile']));
    expect(err).toBeInstanceOf(SdidUnavailableError);
    expect(err).not.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('401 maps to unavailable, never to unknown identity', async () => {
    const { strategy } = strategyOn({
      forceStatus: { urlContains: '/identity/status', status: 401 },
    });
    const err = await rejection(strategy.reassert(KNOWN));
    expect(err).toBeInstanceOf(SdidUnavailableError);
    expect(err).not.toBeInstanceOf(SdidUnknownIdentityError);
  });

  it('500 maps to SdidUnavailableError', async () => {
    const { strategy } = strategyOn({
      forceStatus: { urlContains: '/identity/reference-template', status: 500 },
    });
    await expect(
      strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnavailableError);
  });

  it('a hung socket becomes SdidTimeoutError', async () => {
    const fake = new FakeSdid({ hang: true });
    const strategy = new ProprietaryRestStrategy(restOptions(fake, { httpTimeoutMs: 20 }));
    await expect(strategy.reassert(KNOWN)).rejects.toBeInstanceOf(SdidTimeoutError);
  });
});

describe('ProprietaryRestStrategy: boundary validation (02 §4)', () => {
  it('rejects a non-JSON attribute payload', async () => {
    const { strategy } = strategyOn({ userinfoRawBody: 'SOAP fault, not JSON' });
    await expect(strategy.getAttributes(KNOWN, ['profile'])).rejects.toBeInstanceOf(
      SdidMalformedResponseError,
    );
  });

  it('rejects an attribute mapping that invents extra fields', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        attributes: async () => ({ name: 'A B', nationalIdPhoto: 'oops' }) as never,
      }),
    );
    await expect(strategy.getAttributes(KNOWN, ['profile'])).rejects.toBeInstanceOf(
      SdidMalformedResponseError,
    );
  });

  it('rejects an empty reference template', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        referenceBiometric: async () => ({ data: new Uint8Array(0), format: 'iso-19794' }),
      }),
    );
    await expect(
      strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidMalformedResponseError);
  });

  it('a malformed-response error names the field, never the template bytes', async () => {
    const secret = new Uint8Array([7, 7, 7, 7, 7]);
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        referenceBiometric: async () => ({ data: secret, format: 'proprietary-v3' }) as never,
      }),
    );
    const err = await rejection(strategy.getReferenceBiometric({ nid: KNOWN, modality: 'face' }));
    expect(err.message).toContain('format');
    expect(err.message).not.toContain(Buffer.from(secret).toString('base64'));
    expect(err.message).not.toContain(KNOWN);
  });

  it('applies our scope policy even when the adapter over-fetches (Q9)', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, {
        attributes: async () => ({
          name: 'Aline Uwimana',
          dateOfBirth: '1990-01-01',
          address: 'KG 11 Ave, Kigali',
          faceReferenceAvailable: true,
        }),
      }),
    );
    const attrs = await strategy.getAttributes(KNOWN, ['profile']);
    expect(attrs.name).toBe('Aline Uwimana');
    // The adapter returned an address; our scope filter, not the adapter,
    // decides what the broker sees.
    expect(attrs.address).toBeUndefined();
  });
});

describe('ProprietaryRestStrategy: unconfigured A1/A2 gaps fail loudly', () => {
  const bare = (fake = new FakeSdid()): ProprietaryRestStrategy =>
    new ProprietaryRestStrategy({
      baseUrl: BASE_URL,
      auth: { scheme: 'api-key', headerName: 'x-api-key', apiKey: FAKE_API_KEY },
      nidPepper: PEPPER,
      transport: fake.transport,
    });

  it('reports every unfilled gap with its open-question id', () => {
    expect(bare().describeGaps()).toEqual([
      expect.objectContaining({
        optionPath: 'proprietary.referenceBiometric',
        openQuestion: 'A2',
      }),
      expect.objectContaining({ optionPath: 'proprietary.attributes', openQuestion: 'A1' }),
      expect.objectContaining({ optionPath: 'proprietary.reassert', openQuestion: 'A1' }),
      expect.objectContaining({
        optionPath: 'proprietary.subjectResolver',
        openQuestion: 'A1/A3',
      }),
    ]);
  });

  it('getReferenceBiometric throws a descriptive SdidConfigurationError naming A2', async () => {
    const fake = new FakeSdid();
    const err = await rejection<SdidConfigurationError>(
      bare(fake).getReferenceBiometric({ nid: KNOWN, modality: 'face' }),
    );
    expect(err).toBeInstanceOf(SdidConfigurationError);
    expect(err.optionPath).toBe('proprietary.referenceBiometric');
    expect(err.openQuestion).toBe('A2');
    expect(err.message).toMatch(/do not guess a default/);
    expect(fake.requests).toHaveLength(0); // no wasted SDID call (A5)
  });

  it('constructor refuses an empty base URL (A4)', () => {
    expect(
      () =>
        new ProprietaryRestStrategy({
          baseUrl: '',
          auth: { scheme: 'api-key', headerName: 'x-api-key', apiKey: FAKE_API_KEY },
          nidPepper: PEPPER,
        }),
    ).toThrow(/baseUrl is required/);
  });

  it('the by-subject path fails loudly without a resolver, raw NID still works', async () => {
    const fake = new FakeSdid();
    const strategy = new ProprietaryRestStrategy(
      restOptions(fake, { subjectResolver: undefined as never }),
    );
    const err = await rejection<SdidConfigurationError>(
      strategy.getAttributes(sdidSubjectForNid(KNOWN, PEPPER), ['profile']),
    );
    expect(err).toBeInstanceOf(SdidConfigurationError);
    expect(err.optionPath).toBe('proprietary.subjectResolver');
    await expect(strategy.getAttributes(KNOWN, ['profile'])).resolves.toBeTruthy();
  });
});

describe('createSdidProvider(proprietary): composition and fail-closed configuration', () => {
  it('refuses to start without the proprietary configuration block', () => {
    expect(() => createSdidProvider({ strategy: 'proprietary' })).toThrow(
      /requires the `proprietary` configuration block/,
    );
  });

  it('refuses to start when A1/A2 adapter functions are missing (fail closed)', () => {
    const fake = new FakeSdid();
    const call = (): unknown =>
      createSdidProvider({
        strategy: 'proprietary',
        nidPepper: PEPPER,
        proprietary: {
          baseUrl: BASE_URL,
          auth: { scheme: 'api-key', headerName: 'x-api-key', apiKey: FAKE_API_KEY },
          transport: fake.transport,
        },
      });
    expect(call).toThrow(SdidConfigurationError);
    expect(call).toThrow(/proprietary.referenceBiometric/);
  });

  it('routes the real strategy through the circuit breaker (02 §4)', async () => {
    const fake = new FakeSdid({ forceStatus: { urlContains: '/identity/status', status: 503 } });
    const provider = createSdidProvider({
      strategy: 'proprietary',
      nidPepper: PEPPER,
      proprietary: restOptions(fake),
      resilience: {
        retries: 0,
        retryBaseDelayMs: 1,
        breakerFailureThreshold: 2,
        breakerResetMs: 60_000,
      },
    });
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidUnavailableError);
    const before = fake.requests.length;
    await expect(provider.reassert(KNOWN)).rejects.toBeInstanceOf(SdidCircuitOpenError);
    expect(fake.requests.length).toBe(before);
  });

  it('retries a transient failure through the resilience wrapper', async () => {
    let calls = 0;
    const fake = new FakeSdid();
    const provider = createSdidProvider({
      strategy: 'proprietary',
      nidPepper: PEPPER,
      resilience: { retryBaseDelayMs: 1, retries: 2 },
      proprietary: restOptions(fake, {
        reassert: async (input, ctx) => {
          calls += 1;
          if (calls < 3) throw new SdidUnavailableError('transient');
          return await fakeReassertChecker('/identity/status')(input, ctx);
        },
      }),
    });
    await expect(provider.reassert(KNOWN)).resolves.toMatchObject({ valid: true });
    expect(calls).toBe(3);
  });

  it('audits every real-strategy call pseudonymously, with no template bytes (07 §1)', async () => {
    const events: SdidAuditHookEvent[] = [];
    const fake = new FakeSdid();
    const provider = createSdidProvider({
      strategy: 'proprietary',
      nidPepper: PEPPER,
      proprietary: restOptions(fake),
      onAudit: async (e) => {
        events.push(e);
      },
    });
    const res = await provider.getReferenceBiometric({ nid: KNOWN, modality: 'fingerprint' });
    const event = events[0]!;
    expect(event.subjectRef).toBe(sdidSubjectForNid(KNOWN, PEPPER));
    expect(event.context).toMatchObject({ strategy: 'proprietary', modality: 'fingerprint' });
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain(KNOWN);
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('base64'));
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('hex'));
  });

  it('audits a failure without leaking the identifier that failed', async () => {
    const events: SdidAuditHookEvent[] = [];
    const fake = new FakeSdid();
    const provider = createSdidProvider({
      strategy: 'proprietary',
      nidPepper: PEPPER,
      proprietary: restOptions(fake),
      onAudit: async (e) => {
        events.push(e);
      },
    });
    await expect(
      provider.getReferenceBiometric({ nid: FAKE_UNKNOWN_NID, modality: 'face' }),
    ).rejects.toBeInstanceOf(SdidUnknownIdentityError);
    const event = events[0]!;
    expect(event.result).toBe('failure');
    expect(event.context?.error).toBe('SdidUnknownIdentityError');
    expect(JSON.stringify(event)).not.toContain(FAKE_UNKNOWN_NID);
  });
});
