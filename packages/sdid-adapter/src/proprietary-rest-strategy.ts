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
  type SdidHttpRequest,
  type SdidHttpTransport,
} from './http-transport.js';
import { ClientCredentialsTokenSource, type OidcClientAuth } from './oidc-client-auth.js';
import { sdidSubjectForNid } from './pseudonym.js';
import {
  filterAttributesByScope,
  makeCallContext,
  requireAdapter,
  resolveUpstreamIdentifier,
  type AttributesFetcher,
  type ReassertChecker,
  type ReferenceBiometricFetcher,
  type SubjectResolver,
  type UpstreamCallContext,
  type UpstreamGapReport,
} from './upstream.js';

/**
 * ProprietaryRestStrategy (spec 02 §1) — the strategy for the case where SDID
 * turns out to be a bespoke REST (or SOAP-over-HTTP) API.
 *
 * ⚠️ A1 IS UNANSWERED, and by definition a bespoke API has no shape we can
 * infer. So what this class owns is exactly the part that does not depend on
 * the answer: base URL and client authentication (Q3/A3), the authenticated
 * call layer, boundary validation of everything that comes back, mapping onto
 * the adapter error taxonomy, pseudonymous subjects (Q8), and our scope policy
 * (Q9). Payload shaping is three injectable adapter functions — the same
 * function types the OIDC strategy uses, so an answer to A1/A2 is written once.
 *
 * The transport is byte-oriented, so a SOAP envelope is as serviceable as JSON;
 * an adapter that builds/parses XML needs no change here.
 *
 * Resilience and audit are applied by createSdidProvider, never here (02 §4).
 */
export type ProprietaryAuth =
  /** Static API key in a header, e.g. `x-api-key` (Q3). Rotation policy is A3. */
  | { scheme: 'api-key'; headerName: string; apiKey: string }
  /** Long-lived bearer credential issued out of band (Q3). */
  | { scheme: 'bearer-static'; token: string }
  /** OAuth2 client credentials against a fixed token endpoint (Q3, detail A3). */
  | {
      scheme: 'oauth2-client-credentials';
      tokenEndpoint: string;
      clientId: string;
      clientAuth: OidcClientAuth;
      scopes?: readonly string[];
    }
  /**
   * Anything else A1 turns out to require — per-request HMAC signing,
   * WS-Security headers, a nonce/timestamp scheme. Receives the outbound
   * request and returns it authenticated.
   *
   * NOTE: mTLS is NOT configured here — it is a transport concern (C1/C2);
   * supply a transport whose agent carries the client certificate.
   */
  | { scheme: 'custom'; apply: (req: SdidHttpRequest) => SdidHttpRequest | Promise<SdidHttpRequest> };

export interface ProprietaryRestStrategyOptions {
  /** SDID API base URL (A4). All configured paths resolve against this. */
  baseUrl: string;
  /** Client authentication (Q3, detail A3). */
  auth: ProprietaryAuth;
  /** NID pepper for the pseudonymous subject (Q8). Threaded from createSdidProvider. */
  nidPepper: string;

  /** Injected in tests (fake SDID); defaults to Node's fetch. */
  transport?: SdidHttpTransport;
  /** Socket-level deadline per HTTP request; the contract-level timeout is the resilience wrapper's. */
  httpTimeoutMs?: number;
  /** Injectable clock for tests. */
  clock?: () => number;
  /**
   * Statuses this API uses for "no such identity". Default `[404]`; some
   * bespoke APIs answer 200 with an error body instead, in which case the
   * adapter function should throw SdidUnknownIdentityError itself.
   */
  notFoundStatuses?: readonly number[];

  /** OPEN A2 (critical) — see ReferenceBiometricFetcher. */
  referenceBiometric?: ReferenceBiometricFetcher;
  /** OPEN A1 — attribute request/response shaping. */
  attributes?: AttributesFetcher;
  /** OPEN A1 + Q12 — re-verification request/response shaping. */
  reassert?: ReassertChecker;
  /** OPEN A1/A3 — mapping a stored sdidSubject to an upstream identifier. */
  subjectResolver?: SubjectResolver;
}

const upstreamReferenceSchema = z.object({
  data: z
    .instanceof(Uint8Array)
    .refine((d) => d.byteLength > 0, { message: 'empty biometric reference' }),
  format: z.enum(['iso-19794', 'jpeg2000']),
  txnRef: z.string().min(1).optional(),
});

/** Strict: an adapter returning unexpected keys is a mapping bug, not extra data to forward. */
const upstreamAttributesSchema = z
  .object({
    name: z.string().min(1).optional(),
    dateOfBirth: z.string().min(1).optional(),
    address: z.string().min(1).optional(),
    faceReferenceAvailable: z.boolean().optional(),
  })
  .strict();

const upstreamReassertSchema = z.object({
  valid: z.boolean(),
  assurance: z.enum(['AL1', 'AL2', 'AL3']),
  txnRef: z.string().min(1).optional(),
});

export const PROPRIETARY_GAPS: Record<
  'referenceBiometric' | 'attributes' | 'reassert' | 'subjectResolver',
  UpstreamGapReport
> = {
  referenceBiometric: {
    optionPath: 'proprietary.referenceBiometric',
    openQuestion: 'A2',
    detail:
      'fetching the enrolled reference template for a claimed NID (endpoint, request shape and ' +
      'response encoding are unknown, and whether fingerprint is served at all is unconfirmed)',
  },
  attributes: {
    optionPath: 'proprietary.attributes',
    openQuestion: 'A1',
    detail: 'the attribute endpoint, its request payload and its response field names',
  },
  reassert: {
    optionPath: 'proprietary.reassert',
    openQuestion: 'A1',
    detail: 're-verification call shape and how SDID signals a revoked/deceased identity (Q12)',
  },
  subjectResolver: {
    optionPath: 'proprietary.subjectResolver',
    openQuestion: 'A1/A3',
    detail: 'mapping a stored pseudonymous sdidSubject back to an identifier SDID accepts',
  },
};

function issueDetail(error: z.ZodError): string {
  return error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`).join('; ');
}

export class ProprietaryRestStrategy implements SdidProvider {
  private readonly transport: SdidHttpTransport;
  private readonly httpTimeoutMs: number;
  private readonly tokens: ClientCredentialsTokenSource | undefined;

  constructor(private readonly opts: ProprietaryRestStrategyOptions) {
    if (!opts.baseUrl) {
      throw new Error('ProprietaryRestStrategy: baseUrl is required (02 §3 A4)');
    }
    this.transport = opts.transport ?? createFetchTransport();
    this.httpTimeoutMs = opts.httpTimeoutMs ?? 5000;
    this.tokens =
      opts.auth.scheme === 'oauth2-client-credentials'
        ? new ClientCredentialsTokenSource({
            clientId: opts.auth.clientId,
            clientAuth: opts.auth.clientAuth,
            ...(opts.auth.scopes ? { scopes: opts.auth.scopes } : {}),
            transport: this.transport,
            httpTimeoutMs: this.httpTimeoutMs,
            ...(opts.clock ? { clock: opts.clock } : {}),
          })
        : undefined;
  }

  /** Unconfigured A1/A2 holes — reported at boot by createSdidProvider (fail closed). */
  describeGaps(): UpstreamGapReport[] {
    const gaps: UpstreamGapReport[] = [];
    if (!this.opts.referenceBiometric) gaps.push(PROPRIETARY_GAPS.referenceBiometric);
    if (!this.opts.attributes) gaps.push(PROPRIETARY_GAPS.attributes);
    if (!this.opts.reassert) gaps.push(PROPRIETARY_GAPS.reassert);
    if (!this.opts.subjectResolver) gaps.push(PROPRIETARY_GAPS.subjectResolver);
    return gaps;
  }

  /** Applies the configured client-authentication scheme to an outbound request. */
  private async authorize(req: SdidHttpRequest): Promise<SdidHttpRequest> {
    const auth = this.opts.auth;
    switch (auth.scheme) {
      case 'api-key':
        return {
          ...req,
          headers: { ...(req.headers ?? {}), [auth.headerName.toLowerCase()]: auth.apiKey },
        };
      case 'bearer-static':
        return {
          ...req,
          headers: { ...(req.headers ?? {}), authorization: `Bearer ${auth.token}` },
        };
      case 'oauth2-client-credentials': {
        const token = await this.tokens!.getToken(auth.tokenEndpoint);
        return {
          ...req,
          headers: { ...(req.headers ?? {}), authorization: `Bearer ${token}` },
        };
      }
      case 'custom':
        return await auth.apply(req);
    }
  }

  private context(): UpstreamCallContext {
    return makeCallContext({
      baseUrl: this.opts.baseUrl,
      transport: this.transport,
      httpTimeoutMs: this.httpTimeoutMs,
      authorize: (req) => this.authorize(req),
      // Drop any cached token so the resilience layer's next retry
      // re-authenticates rather than replaying a rotated-out credential (A3).
      onAuthRejected: () => this.tokens?.invalidate(),
      txnPrefix: 'sdid',
    });
  }

  /** Wrap ctx.call so the deployment's notFoundStatuses apply by default. */
  private callContext(): UpstreamCallContext {
    const base = this.context();
    const notFoundStatuses = this.opts.notFoundStatuses ?? [404];
    return {
      ...base,
      call: (req, opts = {}) => base.call(req, { notFoundStatuses, ...opts }),
    };
  }

  async getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult> {
    const fetcher = requireAdapter(
      this.opts.referenceBiometric,
      PROPRIETARY_GAPS.referenceBiometric,
    );
    const ctx = this.callContext();
    const upstream = await fetcher({ nid: input.nid, modality: input.modality }, ctx);
    const parsed = upstreamReferenceSchema.safeParse(upstream);
    if (!parsed.success) {
      // Issue paths/codes only — a rejected payload never puts template bytes
      // into an error message (07 §1).
      throw new SdidMalformedResponseError(`reference biometric: ${issueDetail(parsed.error)}`);
    }
    return {
      // CARDINAL RULE (07 §1): in-memory only, matched and discarded in the
      // same request. Never logged, cached, persisted, or audited.
      reference: { modality: input.modality, data: parsed.data.data, format: parsed.data.format },
      sdidSubject: sdidSubjectForNid(input.nid, this.opts.nidPepper), // Q8
      txnRef: parsed.data.txnRef ?? ctx.newTxnRef(),
    };
  }

  async getAttributes(idOrSubject: string, scopes: string[]): Promise<AttributeSet> {
    const fetcher = requireAdapter(this.opts.attributes, PROPRIETARY_GAPS.attributes);
    const identifier = await resolveUpstreamIdentifier(
      idOrSubject,
      this.opts.subjectResolver,
      PROPRIETARY_GAPS.subjectResolver.optionPath,
    );
    const ctx = this.callContext();
    const upstream = await fetcher({ identifier, scopes }, ctx);
    const parsed = upstreamAttributesSchema.safeParse(upstream);
    if (!parsed.success) {
      throw new SdidMalformedResponseError(`attributes: ${issueDetail(parsed.error)}`);
    }
    // Our scope policy (Q9) is applied here, not by the adapter function — so
    // a mapping mistake cannot widen what the broker receives.
    return filterAttributesByScope(parsed.data, scopes);
  }

  async reassert(idOrSubject: string): Promise<ReassertResult> {
    const checker = requireAdapter(this.opts.reassert, PROPRIETARY_GAPS.reassert);
    const identifier = await resolveUpstreamIdentifier(
      idOrSubject,
      this.opts.subjectResolver,
      PROPRIETARY_GAPS.subjectResolver.optionPath,
    );
    const ctx = this.callContext();
    let upstream;
    try {
      upstream = await checker({ identifier }, ctx);
    } catch (err) {
      // Q12: an identity SDID no longer knows is reported as not valid.
      if (err instanceof SdidUnknownIdentityError) {
        return { valid: false, assurance: 'AL1', txnRef: ctx.newTxnRef() };
      }
      throw err;
    }
    const parsed = upstreamReassertSchema.safeParse(upstream);
    if (!parsed.success) {
      throw new SdidMalformedResponseError(`reassert: ${issueDetail(parsed.error)}`);
    }
    return {
      valid: parsed.data.valid,
      assurance: parsed.data.assurance,
      txnRef: parsed.data.txnRef ?? ctx.newTxnRef(),
    };
  }
}
