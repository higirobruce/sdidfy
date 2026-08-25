import { describe, expect, it } from 'vitest';
import { ASSURANCE_LEVELS, type SdidProvider } from '@sdid/shared';
import { SdidUnknownIdentityError } from './errors.js';

/**
 * Shared SdidProvider contract suite (spec 09 §3): mock and real strategies
 * must pass the same tests, so the Phase-3 cutover is low-risk. Imported by
 * .spec files only — never at runtime outside vitest.
 */
export interface SdidProviderContractContext {
  provider: SdidProvider;
  /** An identity the provider is guaranteed to know. */
  knownNid: string;
  /** An identity guaranteed unknown to the provider. */
  unknownNid: string;
}

export function runSdidProviderContractTests(
  name: string,
  factory: () => SdidProviderContractContext | Promise<SdidProviderContractContext>,
): void {
  describe(`SdidProvider contract: ${name}`, () => {
    it('getReferenceBiometric returns a well-formed, pseudonymous result', async () => {
      const { provider, knownNid } = await factory();
      const res = await provider.getReferenceBiometric({ nid: knownNid, modality: 'face' });
      expect(res.reference.data).toBeInstanceOf(Uint8Array);
      expect(res.reference.data.byteLength).toBeGreaterThan(0);
      expect(res.reference.modality).toBe('face');
      expect(res.sdidSubject.length).toBeGreaterThan(0);
      expect(res.txnRef.length).toBeGreaterThan(0);
      // The subject is pseudonymous — it never embeds the raw NID.
      expect(res.sdidSubject).not.toContain(knownNid);
    });

    it('sdidSubject is stable per identity; txnRef is per-transaction', async () => {
      const { provider, knownNid } = await factory();
      const a = await provider.getReferenceBiometric({ nid: knownNid, modality: 'face' });
      const b = await provider.getReferenceBiometric({ nid: knownNid, modality: 'fingerprint' });
      expect(a.sdidSubject).toBe(b.sdidSubject);
      expect(a.txnRef).not.toBe(b.txnRef);
    });

    it('face and fingerprint references differ for the same identity', async () => {
      const { provider, knownNid } = await factory();
      const face = await provider.getReferenceBiometric({ nid: knownNid, modality: 'face' });
      const finger = await provider.getReferenceBiometric({
        nid: knownNid,
        modality: 'fingerprint',
      });
      expect(Buffer.from(face.reference.data).equals(Buffer.from(finger.reference.data))).toBe(
        false,
      );
    });

    it('getReferenceBiometric rejects an unknown NID with SdidUnknownIdentityError', async () => {
      const { provider, unknownNid } = await factory();
      await expect(
        provider.getReferenceBiometric({ nid: unknownNid, modality: 'face' }),
      ).rejects.toBeInstanceOf(SdidUnknownIdentityError);
    });

    it('getAttributes filters by scope: profile -> name + dateOfBirth', async () => {
      const { provider, knownNid } = await factory();
      const attrs = await provider.getAttributes(knownNid, ['profile']);
      expect(attrs.name).toBeTruthy();
      expect(attrs.dateOfBirth).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(attrs.address).toBeUndefined();
    });

    it('getAttributes filters by scope: address -> address only', async () => {
      const { provider, knownNid } = await factory();
      const attrs = await provider.getAttributes(knownNid, ['address']);
      expect(attrs.address).toBeTruthy();
      expect(attrs.name).toBeUndefined();
      expect(attrs.dateOfBirth).toBeUndefined();
    });

    it('getAttributes is deterministic per identity', async () => {
      const { provider, knownNid } = await factory();
      const a = await provider.getAttributes(knownNid, ['profile', 'address']);
      const b = await provider.getAttributes(knownNid, ['profile', 'address']);
      expect(a).toEqual(b);
    });

    it('getAttributes accepts the sdidSubject in place of the NID (v1 /userinfo path)', async () => {
      const { provider, knownNid } = await factory();
      const ref = await provider.getReferenceBiometric({ nid: knownNid, modality: 'face' });
      const byNid = await provider.getAttributes(knownNid, ['profile']);
      const bySubject = await provider.getAttributes(ref.sdidSubject, ['profile']);
      expect(bySubject).toEqual(byNid);
    });

    it('getAttributes rejects an unknown id with SdidUnknownIdentityError', async () => {
      const { provider, unknownNid } = await factory();
      await expect(provider.getAttributes(unknownNid, ['profile'])).rejects.toBeInstanceOf(
        SdidUnknownIdentityError,
      );
    });

    it('reassert returns valid + assurance + txnRef for a known identity', async () => {
      const { provider, knownNid } = await factory();
      const res = await provider.reassert(knownNid);
      expect(res.valid).toBe(true);
      expect(ASSURANCE_LEVELS).toContain(res.assurance);
      expect(res.txnRef.length).toBeGreaterThan(0);
    });

    it('reassert reports an unknown identity as not valid', async () => {
      const { provider, unknownNid } = await factory();
      const res = await provider.reassert(unknownNid);
      expect(res.valid).toBe(false);
      expect(res.txnRef.length).toBeGreaterThan(0);
    });
  });
}
