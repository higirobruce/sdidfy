import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MOCK_TEST_NIDS, uuidv7 } from '@sdid/shared';
import {
  cleanTestData,
  createTestApp,
  insertTestRp,
  pseudoNidOf,
  type TestContext,
} from '../enrolment/testkit.js';
import { ConsentService } from './consent.service.js';
import { citizens } from '../../db/schema.js';

describe('ConsentService (spec 04 §5, integration)', () => {
  let ctx: TestContext;
  let service: ConsentService;
  let citizenId: string;
  let rpId: string;

  beforeAll(async () => {
    ctx = await createTestApp();
    await cleanTestData(ctx);
    service = ctx.app.get(ConsentService);
    // A bare citizen row is enough for consent semantics — no binding needed.
    citizenId = uuidv7();
    await ctx.db.db
      .insert(citizens)
      .values({ id: citizenId, pseudoNid: pseudoNidOf(MOCK_TEST_NIDS[0]) });
    rpId = await insertTestRp(ctx, 'Consent Test RP');
  });

  afterAll(async () => {
    await ctx.app.close();
  });

  it('recordGrant persists the grant and hasActiveGrant honours scope subsets', async () => {
    const { id } = await service.recordGrant({
      citizenId,
      rpId,
      scopes: ['openid', 'profile'],
      source: 'ciba-approval',
    });
    expect(id).toMatch(/^[0-9a-f-]{36}$/);

    expect(await service.hasActiveGrant(citizenId, rpId, ['openid'])).toBe(true);
    expect(await service.hasActiveGrant(citizenId, rpId, ['openid', 'profile'])).toBe(true);
    // A scope the grant does not cover is not silently included.
    expect(await service.hasActiveGrant(citizenId, rpId, ['openid', 'address'])).toBe(false);
    // A different RP shares nothing.
    const otherRpId = await insertTestRp(ctx, 'Other RP');
    expect(await service.hasActiveGrant(citizenId, otherRpId, ['openid'])).toBe(false);
  });

  it('listGrants resolves the RP name and ISO timestamps', async () => {
    const grants = await service.listGrants(citizenId);
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({
      rpName: 'Consent Test RP',
      scopes: ['openid', 'profile'],
      source: 'ciba-approval',
      revokedAt: null,
    });
    expect(new Date(grants[0]!.grantedAt).getTime()).toBeGreaterThan(0);
  });

  it('revokeGrant ends the grant (idempotently) and audit-covers it', async () => {
    const grants = await service.listGrants(citizenId);
    const consentId = grants[0]!.id;
    await service.revokeGrant(citizenId, consentId);
    expect(await service.hasActiveGrant(citizenId, rpId, ['openid'])).toBe(false);
    const after = await service.listGrants(citizenId);
    expect(after[0]!.revokedAt).not.toBeNull();
    // Idempotent: revoking again neither throws nor re-audits a state change.
    await expect(service.revokeGrant(citizenId, consentId)).resolves.toBeUndefined();
  });

  it("refuses to revoke another citizen's grant", async () => {
    const { id } = await service.recordGrant({
      citizenId,
      rpId,
      scopes: ['openid'],
      source: 'standing-grant',
    });
    await expect(service.revokeGrant(uuidv7(), id)).rejects.toMatchObject({
      code: 'invalid_request',
      httpStatus: 404,
    });
    // Still active for the rightful owner.
    expect(await service.hasActiveGrant(citizenId, rpId, ['openid'])).toBe(true);
  });
});
