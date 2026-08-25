import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS } from '@sdid/shared';
import {
  createSdidProvider,
  MockSdidStrategy,
  ResilientSdidProvider,
  type SdidAuditHookEvent,
} from './index.js';
// Imported directly (not via the package entry): the contract suite pulls in
// vitest, which must never load through the adapter's runtime entry point.
import { runSdidProviderContractTests } from './contract-tests.js';

const KNOWN = MOCK_TEST_NIDS[1];
const UNKNOWN = '1190000000000000';

const expectedSubjectRef = (id: string): string =>
  `sdid-${createHash('sha256').update(id).digest('hex').slice(0, 16)}`;

// Contract suite (spec 09 §3) against the bare mock strategy...
runSdidProviderContractTests('MockSdidStrategy (bare)', () => ({
  provider: new MockSdidStrategy(),
  knownNid: MOCK_TEST_NIDS[0],
  unknownNid: UNKNOWN,
}));

// ...and against the full factory output, proving the wrappers preserve the contract.
runSdidProviderContractTests('createSdidProvider(mock) (resilience + audit wrapped)', () => ({
  provider: createSdidProvider({ strategy: 'mock', onAudit: async () => undefined }),
  knownNid: MOCK_TEST_NIDS[0],
  unknownNid: UNKNOWN,
}));

describe('createSdidProvider', () => {
  it('real strategies are gated on integration answers A1/A2', () => {
    for (const strategy of ['oidc', 'proprietary'] as const) {
      expect(() => createSdidProvider({ strategy })).toThrow(
        'SDID strategy pending integration answers A1/A2 (docs/SPEC.md 02 §3)',
      );
    }
  });

  it('mock strategy is resilience-wrapped (retries transient injected failures)', async () => {
    const provider = createSdidProvider({
      strategy: 'mock',
      mock: { failNextCalls: 2 },
      resilience: { retryBaseDelayMs: 1 },
    });
    await expect(provider.reassert(KNOWN)).resolves.toEqual(
      expect.objectContaining({ valid: true }),
    );
  });
});

describe('audit hook', () => {
  const collect = (): { events: SdidAuditHookEvent[]; onAudit: (e: SdidAuditHookEvent) => Promise<void> } => {
    const events: SdidAuditHookEvent[] = [];
    return {
      events,
      onAudit: async (e) => {
        events.push(e);
      },
    };
  };

  it('getReferenceBiometric emits sdid.reference_fetched with a pseudonymous subjectRef', async () => {
    const { events, onAudit } = collect();
    const provider = createSdidProvider({ strategy: 'mock', onAudit });
    const res = await provider.getReferenceBiometric({ nid: KNOWN, modality: 'face' });

    expect(events).toHaveLength(1);
    const e = events[0]!;
    expect(e.action).toBe('sdid.reference_fetched');
    expect(e.result).toBe('success');
    expect(e.subjectRef).toBe(expectedSubjectRef(KNOWN));
    expect(e.txnRef).toBe(res.txnRef);
    expect(e.context).toMatchObject({ modality: 'face', strategy: 'mock' });
    expect(typeof e.context?.durationMs).toBe('number');

    // Biometric discipline (07 §1): no raw NID, no reference bytes anywhere in the event.
    const serialized = JSON.stringify(e);
    expect(serialized).not.toContain(KNOWN);
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('base64'));
    expect(serialized).not.toContain(Buffer.from(res.reference.data).toString('hex'));
  });

  it('failure paths still emit an audit event, pseudonymous, without the raw NID', async () => {
    const { events, onAudit } = collect();
    const provider = createSdidProvider({ strategy: 'mock', onAudit });
    await expect(
      provider.getReferenceBiometric({ nid: UNKNOWN, modality: 'fingerprint' }),
    ).rejects.toThrow();

    expect(events).toHaveLength(1);
    const e = events[0]!;
    expect(e.action).toBe('sdid.reference_fetched');
    expect(e.result).toBe('failure');
    expect(e.subjectRef).toBe(expectedSubjectRef(UNKNOWN));
    expect(e.context?.error).toBe('SdidUnknownIdentityError');
    expect(JSON.stringify(e)).not.toContain(UNKNOWN);
  });

  it('getAttributes audits with the action sdid.reference_fetched and no attribute values', async () => {
    const { events, onAudit } = collect();
    const provider = createSdidProvider({ strategy: 'mock', onAudit });
    const attrs = await provider.getAttributes(KNOWN, ['profile', 'address']);

    const e = events[0]!;
    expect(e.action).toBe('sdid.reference_fetched');
    expect(e.subjectRef).toBe(expectedSubjectRef(KNOWN));
    expect(e.context).toMatchObject({ scopes: ['profile', 'address'], strategy: 'mock' });
    const serialized = JSON.stringify(e);
    expect(serialized).not.toContain(attrs.name!);
    expect(serialized).not.toContain(attrs.dateOfBirth!);
    expect(serialized).not.toContain(attrs.address!);
    expect(serialized).not.toContain(KNOWN);
  });

  it('getAttributes called with the stored sdidSubject keeps that ref in audit (no double hash)', async () => {
    const { events, onAudit } = collect();
    const provider = createSdidProvider({ strategy: 'mock', onAudit });
    const subject = expectedSubjectRef(KNOWN); // mock sdidSubject is the same derivation
    await provider.getAttributes(subject, ['profile']);
    expect(events[0]!.subjectRef).toBe(subject);
  });

  it('reassert emits sdid.reassert with txnRef', async () => {
    const { events, onAudit } = collect();
    const provider = createSdidProvider({ strategy: 'mock', onAudit });
    const res = await provider.reassert(KNOWN);
    const e = events[0]!;
    expect(e.action).toBe('sdid.reassert');
    expect(e.result).toBe('success');
    expect(e.txnRef).toBe(res.txnRef);
    expect(e.subjectRef).toBe(expectedSubjectRef(KNOWN));
  });

  it('an onAudit failure never alters the call outcome', async () => {
    const provider = createSdidProvider({
      strategy: 'mock',
      onAudit: async () => {
        throw new Error('audit sink down');
      },
    });
    await expect(provider.reassert(KNOWN)).resolves.toEqual(
      expect.objectContaining({ valid: true }),
    );
  });
});

describe('ResilientSdidProvider export surface', () => {
  it('exposes circuit state for tests/health', () => {
    const provider = new ResilientSdidProvider(new MockSdidStrategy());
    expect(provider.circuitState).toBe('closed');
  });
});
