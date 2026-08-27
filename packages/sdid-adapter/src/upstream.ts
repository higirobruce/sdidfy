import { randomBytes } from 'node:crypto';
import type { AttributeSet, BiometricModality, BiometricReference } from '@sdid/shared';
import { SdidConfigurationError } from './errors.js';
import { isSdidSubject } from './pseudonym.js';
import {
  isOk,
  joinUrl,
  sendWithDeadline,
  throwForStatus,
  type SdidHttpRequest,
  type SdidHttpResponse,
  type SdidHttpTransport,
} from './http-transport.js';

/**
 * Shared machinery for the two real strategies (02 §1: OidcEsignetStrategy and
 * ProprietaryRestStrategy). Everything in this file is either (a) genuinely
 * knowable today, or (b) an explicitly typed hole with a named open question,
 * so a Phase-3 cutover is "fill these in", not "redesign this".
 *
 * The holes are function-shaped rather than data-shaped on purpose: A1/A2 could
 * answer with a JSON envelope, a multipart body, base64url in a claim, or raw
 * ISO-19794 bytes with a header, and a function absorbs all of those. A
 * data-shaped guess (a hard-coded path, a presumed field name) would compile
 * and then silently return the wrong citizen's data.
 */

/** Context handed to every deployment-supplied adapter function. */
export interface UpstreamCallContext {
  /**
   * Absolute base for relative paths — the discovery-derived issuer for OIDC,
   * the configured base URL for the proprietary REST shape.
   */
  readonly baseUrl: string;
  /** Resolve a configured relative path against `baseUrl`. */
  url(path: string): string;
  /**
   * Perform an authenticated request. Client authentication (bearer token,
   * API key, signature) is applied here, so adapter functions never see or
   * handle credentials. Non-2xx responses are mapped onto the error taxonomy
   * unless the status is listed in `allowStatuses`.
   */
  call(req: SdidHttpRequest, opts?: UpstreamCallOptions): Promise<SdidHttpResponse>;
  /** Correlator to use when SDID does not supply its own txnRef. */
  newTxnRef(): string;
}

export interface UpstreamCallOptions {
  /** Statuses that mean "no such identity" for this endpoint. Default `[404]`. */
  notFoundStatuses?: readonly number[];
  /** Non-2xx statuses to return to the caller instead of throwing. */
  allowStatuses?: readonly number[];
  /** Short label used in error messages. Never include identity data. */
  context?: string;
}

/**
 * OPEN A2 (critical, 02 §3). The reference-template fetch: endpoint, request
 * shape, response encoding, and whether fingerprint is served at all are all
 * unknown. A deployment supplies this once A2 is answered.
 *
 * CARDINAL RULE (07 §1 / 10 non-negotiables): the bytes returned here go
 * straight into an in-memory BiometricReference and are matched and discarded
 * inside the same request. They are never logged, cached, written to disk, or
 * placed in an error or audit record — including by this function.
 */
export type ReferenceBiometricFetcher = (
  input: { nid: string; modality: BiometricModality },
  ctx: UpstreamCallContext,
) => Promise<UpstreamReferenceBiometric>;

export interface UpstreamReferenceBiometric {
  /** Raw template/image bytes. In-memory only. */
  data: Uint8Array;
  /** Declared format (A2). 'mock' is not accepted from a real strategy. */
  format: Exclude<BiometricReference['format'], 'mock'>;
  /** SDID-side transaction reference, if the response carries one. */
  txnRef?: string;
}

/**
 * OPEN A1 (02 §3). Attribute retrieval for the proprietary shape: path, verb,
 * request body and response field names are all bespoke. Returns the FULL
 * attribute set it can retrieve; the strategy applies our scope filter (Q9).
 */
export type AttributesFetcher = (
  input: { identifier: string; scopes: readonly string[] },
  ctx: UpstreamCallContext,
) => Promise<AttributeSet>;

/**
 * OPEN A1 + Q12 (02 §3, 03 §6). Re-verification is our only revoked/deceased
 * signal, so what "still valid" means on the wire — a status field, an HTTP
 * code, a lifecycle enum — must come from SDID, not from us.
 *
 * A checker that throws SdidUnknownIdentityError is interpreted by both
 * strategies as `{ valid: false }`: an identity SDID no longer knows is, for
 * our purposes, revoked. That mapping is ours and is spec-backed (Q12).
 */
export type ReassertChecker = (
  input: { identifier: string },
  ctx: UpstreamCallContext,
) => Promise<UpstreamReassert>;

export interface UpstreamReassert {
  valid: boolean;
  /** Assurance SDID asserts for the identity. Mapped to our AL scale (03 §3). */
  assurance: 'AL1' | 'AL2' | 'AL3';
  txnRef?: string;
}

/**
 * OPEN A1/A3 (02 §3). The v1 /userinfo path calls getAttributes with the
 * STORED sdidSubject, because a raw NID is deliberately not persisted
 * (07 §3). A real strategy therefore needs some way to name that identity
 * upstream, and we do not yet know what SDID accepts:
 *   - if SDID accepts its own stable subject identifier, this resolver maps
 *     our pseudonym to that identifier (the expected answer);
 *   - if SDID only accepts a raw NID, this path is not implementable without
 *     storing raw NIDs, which 07 §3 forbids — that is an escalation, not a
 *     configuration choice.
 *
 * A resolver backed by a raw-NID store is a data-protection regression. It is
 * acceptable ONLY in tests, where the "NIDs" are seeded fixtures.
 */
export type SubjectResolver = (sdidSubject: string) => string | Promise<string>;

/** Adapter functions a real strategy needs before it can serve each method. */
export interface UpstreamGaps {
  referenceBiometric?: ReferenceBiometricFetcher;
  attributes?: AttributesFetcher;
  reassert?: ReassertChecker;
  subjectResolver?: SubjectResolver;
}

/** One unconfigured gap, for boot-time reporting. */
export interface UpstreamGapReport {
  optionPath: string;
  openQuestion: string;
  detail: string;
}

/**
 * Throw loudly rather than guess. Called at first use of a gap; the factory
 * also calls `describeGaps` at construction so a misconfigured deployment
 * fails at boot instead of mid-enrolment (fail closed).
 */
export function requireAdapter<T>(
  fn: T | undefined,
  gap: UpstreamGapReport,
): T {
  if (!fn) throw new SdidConfigurationError(gap.optionPath, gap.openQuestion, gap.detail);
  return fn;
}

/**
 * Resolve whatever identifier a caller passed into the identifier the upstream
 * expects. A raw NID passes through (enrolment path, 03 §2). A pseudonymous
 * sdidSubject needs the resolver above.
 */
export async function resolveUpstreamIdentifier(
  idOrSubject: string,
  resolver: SubjectResolver | undefined,
  optionPath: string,
): Promise<string> {
  if (!isSdidSubject(idOrSubject)) return idOrSubject;
  const resolve = requireAdapter(resolver, {
    optionPath,
    openQuestion: 'A1/A3',
    detail:
      'this call named the identity by its stored pseudonymous sdidSubject (the /userinfo path), ' +
      'and how to name that identity to SDID is unresolved',
  });
  return await resolve(idOrSubject);
}

/**
 * Apply our scope policy (Q9) to a full upstream attribute set. Identical to
 * the mock's filter so the contract suite is a genuine equivalence check:
 * `profile` -> name + dateOfBirth, `address` -> address.
 * Anything not requested is simply not returned — the broker never sees more
 * citizen data than the RP's scopes justify.
 */
export function filterAttributesByScope(
  full: AttributeSet,
  scopes: readonly string[],
): AttributeSet {
  const out: AttributeSet = {};
  if (full.faceReferenceAvailable !== undefined) {
    out.faceReferenceAvailable = full.faceReferenceAvailable;
  }
  if (scopes.includes('profile')) {
    if (full.name !== undefined) out.name = full.name;
    if (full.dateOfBirth !== undefined) out.dateOfBirth = full.dateOfBirth;
  }
  if (scopes.includes('address') && full.address !== undefined) out.address = full.address;
  return out;
}

/** Locally generated transaction correlator, used when SDID supplies none. */
export function newLocalTxnRef(prefix: string): string {
  return `${prefix}-${randomBytes(8).toString('hex')}`;
}

/** Build the call context handed to deployment adapters. */
export function makeCallContext(args: {
  baseUrl: string;
  transport: SdidHttpTransport;
  httpTimeoutMs: number;
  /** Applies client authentication to an outbound request. */
  authorize: (req: SdidHttpRequest) => Promise<SdidHttpRequest>;
  /** Called when SDID rejects our credentials, so the next attempt re-auths. */
  onAuthRejected: () => void;
  txnPrefix: string;
}): UpstreamCallContext {
  const { baseUrl, transport, httpTimeoutMs, authorize, onAuthRejected, txnPrefix } = args;
  return {
    baseUrl,
    url: (path) => joinUrl(baseUrl, path),
    newTxnRef: () => newLocalTxnRef(txnPrefix),
    async call(req, opts = {}) {
      const authorized = await authorize(req);
      const res = await sendWithDeadline(transport, authorized, httpTimeoutMs);
      if (isOk(res.status)) return res;
      if (opts.allowStatuses?.includes(res.status)) return res;
      if (res.status === 401 || res.status === 403) onAuthRejected();
      throwForStatus(res.status, opts.context ?? req.method, opts.notFoundStatuses ?? [404]);
    },
  };
}
