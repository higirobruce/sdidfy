import { buildChallengePayload, type PendingTransaction } from '@sdid/shared';
import { describe, expect, it } from 'vitest';
import {
  collapsePending,
  hasMultipleDistinctRequests,
  isDecidable,
  isExpired,
  secondsRemaining,
} from './pending.js';

const T0 = Date.parse('2026-08-26T10:00:00.000Z');

function txn(overrides: {
  authReqId: string;
  rpName?: string;
  bindingMessage?: string | null;
  scopes?: string[];
  createdOffset?: number;
  expiresOffset?: number;
  challengeExpiresOffset?: number;
}): PendingTransaction {
  const challengeId = `chal-${overrides.authReqId}`;
  const nonce = `nonce-${overrides.authReqId}`;
  return {
    authReqId: overrides.authReqId,
    rpName: overrides.rpName ?? 'Irembo',
    rpLogoUri: null,
    scopes: overrides.scopes ?? ['openid'],
    scopeDescriptions: ['Confirm your identity'],
    bindingMessage: overrides.bindingMessage === undefined ? 'code 7Q42' : overrides.bindingMessage,
    requestedAssurance: 'AL2',
    createdAt: new Date(T0 + (overrides.createdOffset ?? 0)).toISOString(),
    expiresAt: new Date(T0 + (overrides.expiresOffset ?? 180_000)).toISOString(),
    challenge: {
      challengeId,
      nonce,
      approvePayload: buildChallengePayload(
        { kind: 'ciba-approve', authReqId: overrides.authReqId },
        challengeId,
        nonce,
      ),
      denyPayload: buildChallengePayload(
        { kind: 'ciba-deny', authReqId: overrides.authReqId },
        challengeId,
        nonce,
      ),
      expiresAt: new Date(T0 + (overrides.challengeExpiresOffset ?? 120_000)).toISOString(),
    },
  };
}

describe('time-boxing (04 §3, T7)', () => {
  it('counts down and expires', () => {
    const t = txn({ authReqId: 'a', expiresOffset: 180_000 });
    expect(secondsRemaining(t, T0)).toBe(180);
    expect(secondsRemaining(t, T0 + 179_500)).toBe(0);
    expect(isExpired(t, T0 + 180_000)).toBe(true);
    expect(secondsRemaining(t, T0 + 999_999)).toBe(0);
  });

  it('stops being decidable when the CHALLENGE expires, before the request does', () => {
    // Challenge TTL is 120 s, CIBA request TTL 180 s (runbook §2): a screen
    // left open goes stale first and must be re-pulled, not signed.
    const t = txn({ authReqId: 'a' });
    expect(isDecidable(t, T0 + 119_000)).toBe(true);
    expect(isDecidable(t, T0 + 121_000)).toBe(false);
    expect(isExpired(t, T0 + 121_000)).toBe(false);
  });
});

describe('duplicate collapse (05 §9, T7)', () => {
  it('collapses identical asks from the same RP inside the window, keeping the oldest', () => {
    const groups = collapsePending(
      [
        txn({ authReqId: 'b', createdOffset: 20_000 }),
        txn({ authReqId: 'a', createdOffset: 0 }),
        txn({ authReqId: 'c', createdOffset: 40_000 }),
      ],
      T0 + 45_000,
    );
    expect(groups).toHaveLength(1);
    expect(groups[0]!.primary.authReqId).toBe('a');
    expect(groups[0]!.count).toBe(3);
    expect(groups[0]!.duplicates.map((d) => d.authReqId)).toEqual(['b', 'c']);
  });

  it('does NOT collapse a different binding message — that is a different ask', () => {
    const groups = collapsePending(
      [
        txn({ authReqId: 'a', bindingMessage: 'code 7Q42' }),
        txn({ authReqId: 'b', bindingMessage: 'code 9X11', createdOffset: 1000 }),
      ],
      T0 + 2000,
    );
    expect(groups).toHaveLength(2);
  });

  it('does NOT collapse a different RP or a different scope set', () => {
    expect(
      collapsePending(
        [txn({ authReqId: 'a' }), txn({ authReqId: 'b', rpName: 'IFMIS', createdOffset: 1000 })],
        T0 + 2000,
      ),
    ).toHaveLength(2);
    expect(
      collapsePending(
        [
          txn({ authReqId: 'a', scopes: ['openid'] }),
          txn({ authReqId: 'b', scopes: ['openid', 'address'], createdOffset: 1000 }),
        ],
        T0 + 2000,
      ),
    ).toHaveLength(2);
  });

  it('treats identical asks far apart in time as separate decisions', () => {
    const groups = collapsePending(
      [
        txn({ authReqId: 'a', createdOffset: 0, expiresOffset: 400_000 }),
        txn({ authReqId: 'b', createdOffset: 90_000, expiresOffset: 400_000 }),
      ],
      T0 + 95_000,
    );
    expect(groups).toHaveLength(2);
  });

  it('drops expired requests entirely', () => {
    const groups = collapsePending(
      [txn({ authReqId: 'a', expiresOffset: 10_000 }), txn({ authReqId: 'b', rpName: 'IFMIS' })],
      T0 + 20_000,
    );
    expect(groups.map((g) => g.primary.authReqId)).toEqual(['b']);
  });

  it('flags the "multiple requests pending" state only for DISTINCT asks', () => {
    const duplicates = collapsePending(
      [txn({ authReqId: 'a' }), txn({ authReqId: 'b', createdOffset: 1000 })],
      T0 + 2000,
    );
    expect(hasMultipleDistinctRequests(duplicates)).toBe(false);

    const distinct = collapsePending(
      [txn({ authReqId: 'a' }), txn({ authReqId: 'b', rpName: 'IFMIS', createdOffset: 1000 })],
      T0 + 2000,
    );
    expect(hasMultipleDistinctRequests(distinct)).toBe(true);
  });

  it('never merges two requests into one decision — duplicates keep their own ids', () => {
    const groups = collapsePending(
      [txn({ authReqId: 'a' }), txn({ authReqId: 'b', createdOffset: 5000 })],
      T0 + 6000,
    );
    const all = [groups[0]!.primary, ...groups[0]!.duplicates].map((t) => t.authReqId);
    expect(new Set(all).size).toBe(2);
  });
});
