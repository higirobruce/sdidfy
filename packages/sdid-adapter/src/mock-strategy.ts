import { createHash, randomBytes } from 'node:crypto';
import {
  MOCK_TEST_NIDS,
  mockBiometricBytes,
  type AttributeSet,
  type BiometricModality,
  type ReassertResult,
  type ReferenceBiometricResult,
  type SdidProvider,
} from '@sdid/shared';
import { SdidUnavailableError, SdidUnknownIdentityError } from './errors.js';
import { sdidSubjectForNid } from './pseudonym.js';

/**
 * MockSdidStrategy (spec 02 §2) — the Phase 0–2 build enabler. There is no
 * SDID sandbox (Q4), so this is the only strategy until A1/A2 are answered.
 * Knows exactly MOCK_TEST_NIDS; everything it returns is deterministic per
 * NID so enrolment/match/userinfo tests are repeatable.
 */
export interface MockSdidStrategyOptions {
  /** Simulated per-call latency. Env SDID_MOCK_LATENCY_MS overrides. */
  latencyMs?: number;
  /** Probability 0..1 that a call fails with SdidUnavailableError. Env SDID_MOCK_FAILURE_RATE overrides. */
  failureRate?: number;
  /** Deterministic failure injection: the next N calls fail, then recover. */
  failNextCalls?: number;
}

// Seeded fake attributes only — plausible Rwandan names, never real people.
const FIRST_NAMES = [
  'Aline',
  'Eric',
  'Diane',
  'Jean Bosco',
  'Clarisse',
  'Patrick',
  'Solange',
  'Emmanuel',
] as const;
const SURNAMES = [
  'Uwimana',
  'Mugisha',
  'Niyonzima',
  'Mukamana',
  'Habimana',
  'Ingabire',
  'Nsengiyumva',
  'Uwase',
] as const;
const KIGALI_DISTRICTS = ['Gasabo', 'Kicukiro', 'Nyarugenge'] as const;

function mockTxnRef(): string {
  return `mock-${randomBytes(6).toString('hex')}`;
}

const pad2 = (n: number): string => String(n).padStart(2, '0');

export class MockSdidStrategy implements SdidProvider {
  private readonly latencyMs: number;
  private readonly failureRate: number;
  private failNextCalls: number;
  /** sdidSubject -> NID, so getAttributes/reassert accept either form. */
  private readonly subjectToNid = new Map<string, string>();

  constructor(opts: MockSdidStrategyOptions = {}) {
    const envLatency = Number.parseInt(process.env.SDID_MOCK_LATENCY_MS ?? '', 10);
    const envFailureRate = Number.parseFloat(process.env.SDID_MOCK_FAILURE_RATE ?? '');
    this.latencyMs = Number.isFinite(envLatency) ? envLatency : (opts.latencyMs ?? 0);
    this.failureRate = Number.isFinite(envFailureRate) ? envFailureRate : (opts.failureRate ?? 0);
    this.failNextCalls = opts.failNextCalls ?? 0;
    for (const nid of MOCK_TEST_NIDS) this.subjectToNid.set(sdidSubjectForNid(nid), nid);
  }

  /** Latency + failure injection for resilience testing (09 §3). */
  private async simulateTransport(): Promise<void> {
    if (this.latencyMs > 0) await new Promise((r) => setTimeout(r, this.latencyMs));
    if (this.failNextCalls > 0) {
      this.failNextCalls -= 1;
      throw new SdidUnavailableError('mock SDID: injected failure');
    }
    if (this.failureRate > 0 && Math.random() < this.failureRate) {
      throw new SdidUnavailableError('mock SDID: injected failure');
    }
  }

  /** Accepts a raw test NID or its sdidSubject; undefined when unknown. */
  private resolveNid(idOrSubject: string): string | undefined {
    if ((MOCK_TEST_NIDS as readonly string[]).includes(idOrSubject)) return idOrSubject;
    return this.subjectToNid.get(idOrSubject);
  }

  async getReferenceBiometric(input: {
    nid: string;
    modality: BiometricModality;
  }): Promise<ReferenceBiometricResult> {
    await this.simulateTransport();
    const nid = this.resolveNid(input.nid);
    if (!nid) throw new SdidUnknownIdentityError();
    return {
      // Reference bytes are in-memory only (07 §1) — never logged or audited.
      reference: {
        modality: input.modality,
        data: mockBiometricBytes(nid, input.modality),
        format: 'mock',
      },
      sdidSubject: sdidSubjectForNid(nid),
      txnRef: mockTxnRef(),
    };
  }

  /**
   * Accepts EITHER a raw NID (enrolment path) or an sdidSubject — the v1
   * /userinfo endpoint only stores the sdidSubject and passes that here.
   */
  async getAttributes(idOrSubject: string, scopes: string[]): Promise<AttributeSet> {
    await this.simulateTransport();
    const nid = this.resolveNid(idOrSubject);
    if (!nid) throw new SdidUnknownIdentityError();
    const full = this.seededAttributes(nid);
    // Scope filtering (Q9): 'profile' -> name + dateOfBirth; 'address' -> address.
    const out: AttributeSet = { faceReferenceAvailable: full.faceReferenceAvailable };
    if (scopes.includes('profile')) {
      out.name = full.name;
      out.dateOfBirth = full.dateOfBirth;
    }
    if (scopes.includes('address')) out.address = full.address;
    return out;
  }

  async reassert(idOrSubject: string): Promise<ReassertResult> {
    await this.simulateTransport();
    const known = this.resolveNid(idOrSubject) !== undefined;
    return known
      ? { valid: true, assurance: 'AL2', txnRef: mockTxnRef() }
      : { valid: false, assurance: 'AL1', txnRef: mockTxnRef() };
  }

  /** Deterministic per-NID fake attributes, seeded by hash — never real data. */
  private seededAttributes(nid: string): Required<AttributeSet> {
    const h = createHash('sha256').update(`mock-attributes:${nid}`).digest();
    const first = FIRST_NAMES[h[0]! % FIRST_NAMES.length]!;
    const last = SURNAMES[h[1]! % SURNAMES.length]!;
    const year = 1960 + (h[2]! % 41);
    const month = 1 + (h[3]! % 12);
    const day = 1 + (h[4]! % 28);
    const district = KIGALI_DISTRICTS[h[5]! % KIGALI_DISTRICTS.length]!;
    const street = `KG ${1 + (h[6]! % 600)} St`;
    return {
      name: `${first} ${last}`,
      dateOfBirth: `${year}-${pad2(month)}-${pad2(day)}`,
      address: `${street}, ${district}, Kigali, Rwanda`,
      faceReferenceAvailable: true,
    };
  }
}
