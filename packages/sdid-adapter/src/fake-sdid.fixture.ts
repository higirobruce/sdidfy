import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  parseJsonBody,
  type SdidHttpRequest,
  type SdidHttpResponse,
  type SdidHttpTransport,
} from './http-transport.js';
import type { OidcAttributesConfig } from './oidc-esignet-strategy.js';
import { sdidSubjectForNid } from './pseudonym.js';
import type {
  AttributesFetcher,
  ReassertChecker,
  ReferenceBiometricFetcher,
  SubjectResolver,
} from './upstream.js';

/**
 * TEST FIXTURE ONLY — never built into dist (excluded in tsconfig.json).
 *
 * An in-memory fake SDID reachable through the SdidHttpTransport seam. It is
 * NOT a claim about what SDID looks like: A1/A2 are unanswered (02 §3). It is a
 * stand-in with *some* plausible shape, whose only job is to let the shared
 * contract suite (09 §3) drive OidcEsignetStrategy and ProprietaryRestStrategy
 * end-to-end with no network — proving the strategies compose, validate, map
 * errors, and honour the SdidProvider contract identically to the mock.
 *
 * When A1/A2 are answered, this fixture is rewritten to the real shape and the
 * strategies' own code should not need to change — only the deployment-supplied
 * adapter functions, which live in the spec files beside it.
 */

export const FAKE_ISSUER = 'https://sdid.fake.gov.rw';

/** Seeded identities the fake knows. Fixture data — not real NIDs. */
export const FAKE_KNOWN_NIDS = [
  '1199012345678901',
  '1199012345678902',
  '1198567890123401',
] as const;

export const FAKE_UNKNOWN_NID = '1190000000000000';

export const FAKE_CLIENT_ID = 'rw-auth-bridge';
export const FAKE_CLIENT_SECRET = 'fixture-client-secret';
export const FAKE_API_KEY = 'fixture-api-key';

/** Deterministic fixture bytes; face and fingerprint differ for the same NID. */
export function fakeReferenceBytes(nid: string, modality: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(`fake-sdid:${modality}:${nid}`).digest());
}

const FIRST = ['Aline', 'Eric', 'Diane', 'Clarisse'] as const;
const LAST = ['Uwimana', 'Mugisha', 'Ingabire', 'Habimana'] as const;

/** Deterministic fixture attributes — plausible shapes, never real people. */
export function fakeAttributes(nid: string): {
  name: string;
  birthdate: string;
  address: string;
} {
  const h = createHash('sha256').update(`fake-attrs:${nid}`).digest();
  const y = 1960 + (h[0]! % 40);
  const m = 1 + (h[1]! % 12);
  const d = 1 + (h[2]! % 28);
  const pad = (n: number): string => String(n).padStart(2, '0');
  return {
    name: `${FIRST[h[3]! % FIRST.length]!} ${LAST[h[4]! % LAST.length]!}`,
    birthdate: `${y}-${pad(m)}-${pad(d)}`,
    address: `KG ${1 + (h[5]! % 500)} St, Kigali, Rwanda`,
  };
}

export interface FakeSdidOptions {
  knownNids?: readonly string[];
  issuer?: string;
  /** Force this status on every request whose URL contains the given substring. */
  forceStatus?: { urlContains: string; status: number; body?: string };
  /** Break the discovery document (issuer mix-up / malformed JSON scenarios). */
  discoveryOverride?: { issuer?: string; rawBody?: string };
  /** Return this body verbatim from userinfo (malformed-payload scenarios). */
  userinfoRawBody?: string;
  /** Reject the first N token requests with 401 (credential-rotation scenario). */
  failTokenRequests?: number;
  /** Never resolve — used to prove the resilience timeout fires (02 §4). */
  hang?: boolean;
}

export interface FakeRequestLogEntry {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

/**
 * Records every request so tests can assert on discovery caching, token reuse
 * and header construction without reaching into strategy internals.
 */
export class FakeSdid {
  readonly requests: FakeRequestLogEntry[] = [];
  readonly issuer: string;
  private readonly known: Set<string>;
  private txnCounter = 0;
  private tokenCounter = 0;
  private tokenFailuresLeft: number;
  /** Access tokens the fake has issued and still accepts. */
  private readonly liveTokens = new Set<string>();

  constructor(private readonly opts: FakeSdidOptions = {}) {
    this.issuer = opts.issuer ?? FAKE_ISSUER;
    this.known = new Set(opts.knownNids ?? FAKE_KNOWN_NIDS);
    this.tokenFailuresLeft = opts.failTokenRequests ?? 0;
  }

  /** Count of requests whose URL contains `fragment`. */
  countRequests(fragment: string): number {
    return this.requests.filter((r) => r.url.includes(fragment)).length;
  }

  /** Revoke every issued token — models a credential rotation mid-flight (A3). */
  rotateCredentials(): void {
    this.liveTokens.clear();
  }

  get transport(): SdidHttpTransport {
    return {
      send: (req, signal) => this.handle(req, signal),
    };
  }

  private json(status: number, value: unknown): SdidHttpResponse {
    return {
      status,
      headers: { 'content-type': 'application/json' },
      body: new Uint8Array(Buffer.from(JSON.stringify(value), 'utf8')),
    };
  }

  private raw(status: number, body: string): SdidHttpResponse {
    return {
      status,
      headers: { 'content-type': 'application/json' },
      body: new Uint8Array(Buffer.from(body, 'utf8')),
    };
  }

  private nextTxn(): string {
    this.txnCounter += 1;
    return `fake-txn-${this.txnCounter}`;
  }

  private async handle(req: SdidHttpRequest, signal: AbortSignal): Promise<SdidHttpResponse> {
    this.requests.push({
      method: req.method,
      url: req.url,
      headers: { ...(req.headers ?? {}) },
      ...(typeof req.body === 'string' ? { body: req.body } : {}),
    });

    if (this.opts.hang) {
      // Resolve never; reject on abort, exactly as a real socket would.
      return await new Promise<SdidHttpResponse>((_, reject) => {
        signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    }

    const forced = this.opts.forceStatus;
    if (forced && req.url.includes(forced.urlContains)) {
      return this.raw(forced.status, forced.body ?? '{"error":"forced"}');
    }

    const url = new URL(req.url);
    const path = url.pathname;
    const nid = url.searchParams.get('nid') ?? url.searchParams.get('id') ?? '';

    if (path === '/.well-known/openid-configuration') {
      if (this.opts.discoveryOverride?.rawBody !== undefined) {
        return this.raw(200, this.opts.discoveryOverride.rawBody);
      }
      return this.json(200, {
        issuer: this.opts.discoveryOverride?.issuer ?? this.issuer,
        authorization_endpoint: `${this.issuer}/oauth2/authorize`,
        token_endpoint: `${this.issuer}/oauth2/token`,
        userinfo_endpoint: `${this.issuer}/oidc/userinfo`,
        jwks_uri: `${this.issuer}/oauth2/jwks`,
      });
    }

    if (path === '/oauth2/token') {
      if (this.tokenFailuresLeft > 0) {
        this.tokenFailuresLeft -= 1;
        return this.json(401, { error: 'invalid_client' });
      }
      // Any of the supported client-auth methods is accepted; the specs assert
      // on the exact header/body the strategy produced via `requests`.
      const authenticated =
        (req.headers?.authorization ?? '').startsWith('Basic ') ||
        String(req.body ?? '').includes('client_secret=') ||
        String(req.body ?? '').includes('client_assertion=');
      if (!authenticated) return this.json(401, { error: 'invalid_client' });
      this.tokenCounter += 1;
      const token = `fake-access-token-${this.tokenCounter}`;
      this.liveTokens.add(token);
      return this.json(200, { access_token: token, token_type: 'Bearer', expires_in: 300 });
    }

    // Everything below is a resource call and needs client authentication.
    const bearer = (req.headers?.authorization ?? '').replace(/^Bearer /, '');
    const apiKey = req.headers?.['x-api-key'];
    const signed = req.headers?.['x-sdid-signature'];
    const authorized =
      (bearer && this.liveTokens.has(bearer)) ||
      bearer === 'static-bearer' ||
      apiKey === FAKE_API_KEY ||
      signed !== undefined;
    if (!authorized) return this.json(401, { error: 'unauthorized' });

    const isKnown = this.known.has(nid);

    // --- OIDC-shaped resources ------------------------------------------
    if (path === '/oidc/userinfo' || path === '/v1/identity/attributes') {
      if (this.opts.userinfoRawBody !== undefined) return this.raw(200, this.opts.userinfoRawBody);
      if (!isKnown) return this.json(404, { error: 'identity_not_found' });
      const a = fakeAttributes(nid);
      return this.json(200, {
        sub: `fake-sdid-sub-${createHash('sha256').update(nid).digest('hex').slice(0, 12)}`,
        name: a.name,
        birthdate: a.birthdate,
        address: { formatted: a.address },
        face_reference_available: true,
      });
    }

    if (path === '/biometrics/reference' || path === '/v1/identity/reference-template') {
      if (!isKnown) return this.json(404, { error: 'identity_not_found' });
      const modality = url.searchParams.get('modality') ?? 'face';
      return this.json(200, {
        // Base64 in a JSON envelope is ONE plausible A2 answer among several.
        template: Buffer.from(fakeReferenceBytes(nid, modality)).toString('base64'),
        format: 'iso-19794',
        txn_ref: this.nextTxn(),
      });
    }

    if (path === '/identity/status' || path === '/v1/identity/status') {
      if (!isKnown) return this.json(404, { error: 'identity_not_found' });
      return this.json(200, { status: 'active', assurance: 'AL2', txn_ref: this.nextTxn() });
    }

    return this.json(404, { error: 'no_such_endpoint' });
  }
}

// ---------------------------------------------------------------------------
// Worked examples of the deployment-supplied adapter functions.
//
// These are what a Phase-3 deployment writes once A1/A2 are answered — the
// STRATEGY code does not change, only these. They live here so the contract
// suite (09 §3) can run both real strategies, and so the README has a concrete
// reference. Every one of them validates its response with zod before handing
// anything back (02 §4), and none of them logs a byte of template data (07 §1).
// ---------------------------------------------------------------------------

const fakeReferenceSchema = z.object({
  template: z.string().min(1),
  format: z.enum(['iso-19794', 'jpeg2000']),
  txn_ref: z.string().min(1),
});

const fakeStatusSchema = z.object({
  status: z.enum(['active', 'suspended', 'deceased']),
  assurance: z.enum(['AL1', 'AL2', 'AL3']),
  txn_ref: z.string().min(1),
});

const qs = (params: Record<string, string>): string =>
  new URLSearchParams(params).toString();

/** OPEN A2 stand-in: base64 template inside a JSON envelope. */
export function fakeReferenceFetcher(path: string): ReferenceBiometricFetcher {
  return async ({ nid, modality }, ctx) => {
    const res = await ctx.call(
      {
        method: 'GET',
        url: `${ctx.url(path)}?${qs({ nid, modality })}`,
        headers: { accept: 'application/json' },
      },
      { context: 'reference-template' },
    );
    const body = parseJsonBody(res, fakeReferenceSchema, 'reference-template');
    return {
      // Decoded straight into the in-memory reference; never logged (07 §1).
      data: new Uint8Array(Buffer.from(body.template, 'base64')),
      format: body.format,
      txnRef: body.txn_ref,
    };
  };
}

/** OPEN A1 stand-in for the OIDC shape: identity named by query parameter. */
export function fakeOidcAttributesConfig(fallbackPath: string): OidcAttributesConfig {
  return {
    buildRequest: ({ identifier }, ctx) => ({
      method: 'GET',
      url: `${ctx.userinfoEndpoint ?? ctx.url(fallbackPath)}?${qs({ nid: identifier })}`,
      headers: { accept: 'application/json' },
    }),
    claimNames: {
      name: 'name',
      dateOfBirth: 'birthdate',
      address: 'address.formatted',
      faceReferenceAvailable: 'face_reference_available',
    },
  };
}

/** OPEN A1 stand-in for the proprietary shape: bespoke JSON envelope. */
export function fakeProprietaryAttributesFetcher(path: string): AttributesFetcher {
  const schema = z.object({
    name: z.string().min(1),
    birthdate: z.string().min(1),
    address: z.object({ formatted: z.string().min(1) }),
    face_reference_available: z.boolean(),
  });
  return async ({ identifier }, ctx) => {
    const res = await ctx.call(
      {
        method: 'GET',
        url: `${ctx.url(path)}?${qs({ nid: identifier })}`,
        headers: { accept: 'application/json' },
      },
      { context: 'attributes' },
    );
    const body = parseJsonBody(res, schema, 'attributes');
    return {
      name: body.name,
      dateOfBirth: body.birthdate,
      address: body.address.formatted,
      faceReferenceAvailable: body.face_reference_available,
    };
  };
}

/** OPEN A1/Q12 stand-in: lifecycle status maps onto valid/assurance. */
export function fakeReassertChecker(path: string): ReassertChecker {
  return async ({ identifier }, ctx) => {
    const res = await ctx.call(
      {
        method: 'GET',
        url: `${ctx.url(path)}?${qs({ nid: identifier })}`,
        headers: { accept: 'application/json' },
      },
      { context: 'reassert' },
    );
    const body = parseJsonBody(res, fakeStatusSchema, 'reassert');
    return {
      // Q12: anything other than an active record is our revoked/deceased signal.
      valid: body.status === 'active',
      assurance: body.assurance,
      txnRef: body.txn_ref,
    };
  };
}

/**
 * OPEN A1/A3 stand-in. Backed by a raw-NID table, which is acceptable ONLY
 * because these are fixture NIDs — 07 §3 forbids storing raw NIDs, so a
 * production resolver must map our pseudonym to an SDID-side identifier
 * instead. See README "Blocked on A1".
 */
export function fakeSubjectResolver(pepper: string, nids: readonly string[]): SubjectResolver {
  const table = new Map(nids.map((n) => [sdidSubjectForNid(n, pepper), n]));
  return (subject) => {
    const nid = table.get(subject);
    if (!nid) return subject; // unresolvable -> upstream answers "not found"
    return nid;
  };
}
