import { z } from 'zod';
import type {
  AttributeSet,
  BiometricModality,
  ReassertResult,
  ReferenceBiometricResult,
  SdidProvider,
} from '@sdid/shared';
import { SdidMalformedResponseError, SdidUnknownIdentityError } from './errors.js';
import {
  createFetchTransport,
  parseJsonBody,
  sendWithDeadline,
  type SdidHttpRequest,
  type SdidHttpResponse,
  type SdidHttpTransport,
} from './http-transport.js';
import {
  ClientCredentialsTokenSource,
  type OidcClientAuth,
} from './oidc-client-auth.js';
import { sdidSubjectForNid } from './pseudonym.js';
import {
  filterAttributesByScope,
  makeCallContext,
  requireAdapter,
  resolveUpstreamIdentifier,
  type ReassertChecker,
  type ReferenceBiometricFetcher,
  type SubjectResolver,
  type UpstreamCallContext,
  type UpstreamGapReport,
} from './upstream.js';

/**
 * OidcEsignetStrategy (spec 02 §1) — the strategy for the case where SDID
 * turns out to expose a standard OIDC / eSignet interface.
 *
 * ⚠️ A1 IS UNANSWERED. What is implemented here is only what the OIDC shape
 * itself guarantees: discovery, client authentication, client-credentials
 * token acquisition with caching, an authenticated call layer, zod validation
 * of every response, and error mapping onto the adapter taxonomy. Everything
 * that depends on SDID's actual endpoints, claim names, or the
 * reference-template mechanics (A2) is an explicit, typed, injectable hole
 * that fails loudly when unfilled — never a default that quietly returns the
 * wrong data about a citizen.
 *
 * Resilience and audit are NOT this class's job and must never be reimplemented
 * here: createSdidProvider composes this exactly like the mock —
 * strategy -> ResilientSdidProvider -> withAuditHook (02 §4).
 */
export interface OidcEsignetStrategyOptions {
  /** SDID issuer URL (A4). Discovery is fetched relative to this and the document's `issuer` must match it. */
  issuer: string;
  /** OAuth2 client id (A3). */
  clientId: string;
  /** Client authentication method + credential (Q3, detail A3). */
  clientAuth: OidcClientAuth;
  /** Scopes requested at the token endpoint (A3 — SDID's scope names, not ours). */
  tokenScopes?: readonly string[];
  /** NID pepper for the pseudonymous subject (Q8). Threaded from createSdidProvider. */
  nidPepper: string;

  /** Injected in tests (fake SDID); defaults to Node's fetch. */
  transport?: SdidHttpTransport;
  /** Socket-level deadline per HTTP request. The contract-level timeout is the resilience wrapper's. */
  httpTimeoutMs?: number;
  /** Discovery-document cache TTL. */
  discoveryTtlMs?: number;
  /** Override the discovery URL when SDID publishes it off the standard path. */
  discoveryUrl?: string;
  /** Injectable clock for tests. */
  clock?: () => number;

  /** OPEN A2 (critical) — see ReferenceBiometricFetcher. */
  referenceBiometric?: ReferenceBiometricFetcher;
  /** OPEN A1 — how an identity is named to userinfo, and the claim names it returns. */
  attributes?: OidcAttributesConfig;
  /** OPEN A1 + Q12 — what "still valid" looks like on the wire. */
  reassert?: ReassertChecker;
  /** OPEN A1/A3 — mapping a stored sdidSubject to an upstream identifier. */
  subjectResolver?: SubjectResolver;
}

/**
 * OPEN A1. In a standard OIDC flow the identity is bound to the access token,
 * not passed as a parameter — but we authenticate as a service
 * (client-credentials, Q3) and must name the citizen explicitly. How SDID
 * accepts that (path segment, query parameter, request object, a
 * per-transaction token) is exactly what A1 has to tell us, so it is a
 * function, not a URL template.
 */
export interface OidcAttributesConfig {
  buildRequest: (
    input: { identifier: string; scopes: readonly string[] },
    ctx: OidcAttributesContext,
  ) => SdidHttpRequest;
  /** OPEN A1 — the claim names SDID actually returns. */
  claimNames: OidcAttributeClaimNames;
  /**
   * Optional: supply when the response is not a plain JSON claims object —
   * a signed/encrypted userinfo JWT is permitted by OIDC Core §5.3.2 and is
   * plausible for a national ID service. Must return the decoded claims.
   */
  decodeBody?: (res: SdidHttpResponse) => unknown;
}

export interface OidcAttributesContext extends UpstreamCallContext {
  /** From the discovery document; undefined when SDID does not advertise one. */
  userinfoEndpoint: string | undefined;
  discovery: OidcDiscoveryDocument;
}

/** Claim names, dotted paths allowed (e.g. `address.formatted`). */
export interface OidcAttributeClaimNames {
  name: string;
  dateOfBirth: string;
  address: string;
  /** Optional presence indicator for the face reference (Q9). */
  faceReferenceAvailable?: string;
}

/**
 * The OIDC Core §5.1 standard claim names — offered as an OPT-IN convenience,
 * NOT a default. SDID may use any names it likes, and silently reading the
 * wrong claim would put the wrong data in a citizen's token. Pass this only
 * after A1 confirms SDID uses standard claims.
 */
export const STANDARD_OIDC_CLAIM_NAMES: OidcAttributeClaimNames = {
  name: 'name',
  dateOfBirth: 'birthdate',
  address: 'address.formatted',
};

/** OIDC Discovery / RFC 8414 metadata, validated at the boundary (02 §4). */
const discoverySchema = z
  .object({
    issuer: z.string().min(1),
    token_endpoint: z.string().min(1),
    userinfo_endpoint: z.string().min(1).optional(),
    authorization_endpoint: z.string().min(1).optional(),
    jwks_uri: z.string().min(1).optional(),
  })
  .passthrough();

export type OidcDiscoveryDocument = z.infer<typeof discoverySchema>;

/** A userinfo-shaped response: an object of claims. Values checked on read. */
const claimsSchema = z.record(z.string(), z.unknown());

/** Adapter-supplied reference template, validated before it reaches the broker. */
const upstreamReferenceSchema = z.object({
  data: z
    .instanceof(Uint8Array)
    .refine((d) => d.byteLength > 0, { message: 'empty biometric reference' }),
  format: z.enum(['iso-19794', 'jpeg2000']),
  txnRef: z.string().min(1).optional(),
});

const upstreamReassertSchema = z.object({
  valid: z.boolean(),
  assurance: z.enum(['AL1', 'AL2', 'AL3']),
  txnRef: z.string().min(1).optional(),
});

/** Dotted-path claim read. Returns undefined for anything that is not a string. */
function readStringClaim(claims: Record<string, unknown>, path: string): string | undefined {
  let cursor: unknown = claims;
  for (const segment of path.split('.')) {
    if (typeof cursor !== 'object' || cursor === null) return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return typeof cursor === 'string' && cursor.length > 0 ? cursor : undefined;
}

export const OIDC_GAPS: Record<
  'referenceBiometric' | 'attributes' | 'reassert' | 'subjectResolver',
  UpstreamGapReport
> = {
  referenceBiometric: {
    optionPath: 'oidc.referenceBiometric',
    openQuestion: 'A2',
    detail:
      'fetching the enrolled reference template for a claimed NID (endpoint, request shape and ' +
      'response encoding are unknown, and whether fingerprint is served at all is unconfirmed)',
  },
  attributes: {
    optionPath: 'oidc.attributes',
    openQuestion: 'A1',
    detail:
      'naming an identity to the userinfo/attribute endpoint and the claim names it returns',
  },
  reassert: {
    optionPath: 'oidc.reassert',
    openQuestion: 'A1',
    detail: 're-verification call shape and how SDID signals a revoked/deceased identity (Q12)',
  },
  subjectResolver: {
    optionPath: 'oidc.subjectResolver',
    openQuestion: 'A1/A3',
    detail: 'mapping a stored pseudonymous sdidSubject back to an identifier SDID accepts',
  },
};

export class OidcEsignetStrategy implements SdidProvider {
  private readonly transport: SdidHttpTransport;
  private readonly httpTimeoutMs: number;
  private readonly discoveryTtlMs: number;
  private readonly clock: () => number;
  private readonly tokens: ClientCredentialsTokenSource;
  private discoveryCache: { doc: OidcDiscoveryDocument; fetchedAtMs: number } | undefined;
  private discoveryInFlight: Promise<OidcDiscoveryDocument> | undefined;

  constructor(private readonly opts: OidcEsignetStrategyOptions) {
    if (!opts.issuer) throw new Error('OidcEsignetStrategy: issuer is required (02 §3 A4)');
    if (!opts.clientId) throw new Error('OidcEsignetStrategy: clientId is required (02 §3 A3)');
    this.transport = opts.transport ?? createFetchTransport();
    this.httpTimeoutMs = opts.httpTimeoutMs ?? 5000;
    this.discoveryTtlMs = opts.discoveryTtlMs ?? 3_600_000;
    this.clock = opts.clock ?? Date.now;
    this.tokens = new ClientCredentialsTokenSource({
      clientId: opts.clientId,
      clientAuth: opts.clientAuth,
      ...(opts.tokenScopes ? { scopes: opts.tokenScopes } : {}),
      transport: this.transport,
      httpTimeoutMs: this.httpTimeoutMs,
      clock: this.clock,
    });
  }

  /** Unconfigured A1/A2 holes — reported at boot by createSdidProvider (fail closed). */
  describeGaps(): UpstreamGapReport[] {
    const gaps: UpstreamGapReport[] = [];
    if (!this.opts.referenceBiometric) gaps.push(OIDC_GAPS.referenceBiometric);
    if (!this.opts.attributes) gaps.push(OIDC_GAPS.attributes);
    if (!this.opts.reassert) gaps.push(OIDC_GAPS.reassert);
    if (!this.opts.subjectResolver) gaps.push(OIDC_GAPS.subjectResolver);
    return gaps;
  }

  // --- Discovery -----------------------------------------------------------

  private discoveryEndpoint(): string {
    if (this.opts.discoveryUrl) return this.opts.discoveryUrl;
    return `${this.opts.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
  }

  /**
   * Fetch-and-cache the discovery document. Cached for `discoveryTtlMs`, with
   * concurrent fetches de-duplicated — an SDID call quota (A5) should not be
   * spent re-reading static metadata.
   */
  async discovery(): Promise<OidcDiscoveryDocument> {
    const cached = this.discoveryCache;
    if (cached && this.clock() - cached.fetchedAtMs < this.discoveryTtlMs) return cached.doc;
    if (this.discoveryInFlight) return await this.discoveryInFlight;
    const inFlight = this.fetchDiscovery().finally(() => {
      this.discoveryInFlight = undefined;
    });
    this.discoveryInFlight = inFlight;
    return await inFlight;
  }

  private async fetchDiscovery(): Promise<OidcDiscoveryDocument> {
    const res = await sendWithDeadline(
      this.transport,
      { method: 'GET', url: this.discoveryEndpoint(), headers: { accept: 'application/json' } },
      this.httpTimeoutMs,
    );
    if (res.status < 200 || res.status >= 300) {
      throw new SdidMalformedResponseError(`discovery: HTTP ${res.status}`);
    }
    const doc = parseJsonBody(res, discoverySchema, 'discovery');
    // Issuer identification (OIDC Discovery §4.3): a document that names a
    // different issuer is a mix-up attempt or a misrouted host — fail closed
    // rather than take its token endpoint.
    if (doc.issuer.replace(/\/+$/, '') !== this.opts.issuer.replace(/\/+$/, '')) {
      throw new SdidMalformedResponseError('discovery: issuer does not match configured issuer');
    }
    this.discoveryCache = { doc, fetchedAtMs: this.clock() };
    return doc;
  }

  // --- Authenticated call layer -------------------------------------------

  private async context(): Promise<UpstreamCallContext & { discovery: OidcDiscoveryDocument }> {
    const doc = await this.discovery();
    const ctx = makeCallContext({
      baseUrl: this.opts.issuer,
      transport: this.transport,
      httpTimeoutMs: this.httpTimeoutMs,
      authorize: async (req) => {
        const token = await this.tokens.getToken(doc.token_endpoint);
        return { ...req, headers: { ...(req.headers ?? {}), authorization: `Bearer ${token}` } };
      },
      // A 401/403 usually means our credential rotated out from under us
      // (A3 grace period unknown) — drop the cached token so the resilience
      // layer's next retry re-authenticates instead of replaying a dead one.
      onAuthRejected: () => this.tokens.invalidate(),
      txnPrefix: 'oidc',
    });
    return Object.assign(ctx, { discovery: doc });
  }

  // --- SdidProvider --------------------------------------------------------

  async getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult> {
    const fetcher = requireAdapter(this.opts.referenceBiometric, OIDC_GAPS.referenceBiometric);
    const ctx = await this.context();
    const upstream = await fetcher({ nid: input.nid, modality: input.modality }, ctx);
    // Boundary validation (02 §4). zod reports issue paths/codes only, so a
    // rejected payload never puts template bytes into an error message.
    const parsed = upstreamReferenceSchema.safeParse(upstream);
    if (!parsed.success) {
      throw new SdidMalformedResponseError(
        `reference biometric: ${parsed.error.issues
          .map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`)
          .join('; ')}`,
      );
    }
    return {
      // CARDINAL RULE (07 §1): these bytes are handed straight to the caller's
      // in-memory match and discarded. Not logged, not cached, not audited.
      reference: {
        modality: input.modality,
        data: parsed.data.data,
        format: parsed.data.format,
      },
      // Subject identifier is OUR keyed pseudonym (Q8), not whatever SDID
      // calls this person — so nothing SDID-side leaks into our storage.
      sdidSubject: sdidSubjectForNid(input.nid, this.opts.nidPepper),
      txnRef: parsed.data.txnRef ?? ctx.newTxnRef(),
    };
  }

  async getAttributes(idOrSubject: string, scopes: string[]): Promise<AttributeSet> {
    const cfg = requireAdapter(this.opts.attributes, OIDC_GAPS.attributes);
    const identifier = await resolveUpstreamIdentifier(
      idOrSubject,
      this.opts.subjectResolver,
      OIDC_GAPS.subjectResolver.optionPath,
    );
    const base = await this.context();
    const ctx: OidcAttributesContext = Object.assign(base, {
      userinfoEndpoint: base.discovery.userinfo_endpoint,
    });
    const res = await ctx.call(cfg.buildRequest({ identifier, scopes }, ctx), {
      context: 'userinfo',
    });
    const decoded = cfg.decodeBody
      ? cfg.decodeBody(res)
      : parseJsonBody(res, claimsSchema, 'userinfo');
    const claims = claimsSchema.safeParse(decoded);
    if (!claims.success) throw new SdidMalformedResponseError('userinfo: not a claims object');

    // Read only the claims we are authorised to receive (Q9). An absent claim
    // stays absent — we never substitute a placeholder for citizen data.
    const full: AttributeSet = {};
    const name = readStringClaim(claims.data, cfg.claimNames.name);
    const dob = readStringClaim(claims.data, cfg.claimNames.dateOfBirth);
    const address = readStringClaim(claims.data, cfg.claimNames.address);
    if (name !== undefined) full.name = name;
    if (dob !== undefined) full.dateOfBirth = dob;
    if (address !== undefined) full.address = address;
    if (cfg.claimNames.faceReferenceAvailable) {
      const raw = claims.data[cfg.claimNames.faceReferenceAvailable];
      if (typeof raw === 'boolean') full.faceReferenceAvailable = raw;
    }
    return filterAttributesByScope(full, scopes);
  }

  async reassert(idOrSubject: string): Promise<ReassertResult> {
    const checker = requireAdapter(this.opts.reassert, OIDC_GAPS.reassert);
    const identifier = await resolveUpstreamIdentifier(
      idOrSubject,
      this.opts.subjectResolver,
      OIDC_GAPS.subjectResolver.optionPath,
    );
    const ctx = await this.context();
    let upstream;
    try {
      upstream = await checker({ identifier }, ctx);
    } catch (err) {
      // Q12: re-verification is our revoked/deceased signal. An identity SDID
      // no longer knows is reported as not valid, not as an error — the
      // caller's job is to suspend the citizen record, not to retry.
      if (err instanceof SdidUnknownIdentityError) {
        return { valid: false, assurance: 'AL1', txnRef: ctx.newTxnRef() };
      }
      throw err;
    }
    const parsed = upstreamReassertSchema.safeParse(upstream);
    if (!parsed.success) {
      throw new SdidMalformedResponseError(
        `reassert: ${parsed.error.issues
          .map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`)
          .join('; ')}`,
      );
    }
    return {
      valid: parsed.data.valid,
      assurance: parsed.data.assurance,
      txnRef: parsed.data.txnRef ?? ctx.newTxnRef(),
    };
  }
}
