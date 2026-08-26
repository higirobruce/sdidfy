import { describe, expect, it } from 'vitest';
import { JsonLogger, type LogRecord } from './json-logger.js';
import { runWithRequestContext, sanitizeRequestId } from './correlation.js';
import { REDACTED, REDACTED_NID, isDeniedField, redact, scrubString } from './redact.js';

/**
 * These tests are the enforcement of a non-negotiable (spec 10): a biometric
 * byte, a raw NID, a token or a nonce must be IMPOSSIBLE to log. They assert
 * on the two independent passes — deny-listed field names and NID-shaped
 * value scrubbing — and then on the logger end-to-end, because a redactor
 * nothing routes through would protect nothing.
 */

/** A NID-shaped value used throughout; never a real one. */
const NID = '1199880012345678';

describe('redaction — deny-listed field names', () => {
  it('normalises case and separators when matching a field name', () => {
    expect(isDeniedField('pushToken')).toBe(true);
    expect(isDeniedField('push_token')).toBe(true);
    expect(isDeniedField('PUSH-TOKEN')).toBe(true);
    expect(isDeniedField('deviceLabel')).toBe(false);
  });

  it('removes the WHOLE subtree, not just leaf strings', () => {
    const out = redact({
      sample: { modality: 'face', data: 'QUJDRA==', liveness: { score: 0.97 } },
      deviceLabel: 'Primary phone',
    }) as Record<string, unknown>;
    expect(out['sample']).toBe(REDACTED);
    expect(JSON.stringify(out)).not.toContain('QUJDRA==');
    // Non-sensitive siblings survive: redaction must not make logs useless.
    expect(out['deviceLabel']).toBe('Primary phone');
  });

  it('redacts credentials, tokens, nonces and challenge material at any depth', () => {
    const out = redact({
      a: {
        b: {
          nid: NID,
          accessToken: 'ey.header.payload',
          nonce: 'Zm9vYmFy',
          signature: 'MEUCIQ',
          clientSecret: 's3cret',
          privateKey: '-----BEGIN EC PRIVATE KEY-----',
        },
      },
    });
    const text = JSON.stringify(out);
    for (const leaked of ['ey.header.payload', 'Zm9vYmFy', 'MEUCIQ', 's3cret', 'BEGIN EC PRIVATE KEY']) {
      expect(text).not.toContain(leaked);
    }
    expect(text).not.toContain(NID);
  });

  it('never renders binary — the shape a biometric sample arrives in', () => {
    const out = redact({ blob: Buffer.from([1, 2, 3, 4]) }) as Record<string, unknown>;
    expect(out['blob']).toBe('[binary 4 bytes]');
  });
});

describe('redaction — NID-shaped value scrubbing', () => {
  it('scrubs a 16-digit run inside free text (the case a deny-list cannot catch)', () => {
    expect(scrubString(`no match for ${NID}`)).toBe(`no match for ${REDACTED_NID}`);
  });

  it('scrubs runs longer than 16 digits too', () => {
    expect(scrubString('11998800123456789012')).toBe(REDACTED_NID);
  });

  it('leaves shorter digit runs alone (timestamps, ports, counters)', () => {
    const line = 'ts=1756180000000 port=3100 count=42';
    expect(scrubString(line)).toBe(line);
  });

  it('scrubs a NID hidden under an innocuous field name', () => {
    const out = redact({ reasonDetail: `probe of ${NID}` }) as Record<string, unknown>;
    expect(out['reasonDetail']).toBe(`probe of ${REDACTED_NID}`);
  });

  it('scrubs a NID-shaped NUMBER, but leaves ordinary numbers as numbers', () => {
    const out = redact({ big: 1199880012345678, small: 42 }) as Record<string, unknown>;
    expect(out['big']).toBe(REDACTED_NID);
    expect(out['small']).toBe(42);
  });

  it('scrubs NIDs out of error messages and stacks', () => {
    const out = redact(new Error(`SDID rejected ${NID}`)) as Record<string, unknown>;
    expect(out['message']).toBe(`SDID rejected ${REDACTED_NID}`);
    expect(String(out['stack'] ?? '')).not.toContain(NID);
  });

  it('truncates blob-length strings so a base64 sample cannot ride in a message', () => {
    const scrubbed = scrubString('A'.repeat(5000));
    expect(scrubbed.length).toBeLessThan(600);
    expect(scrubbed.endsWith('[truncated]')).toBe(true);
  });
});

describe('redaction — hostile and pathological inputs never break the logger', () => {
  it('handles cycles', () => {
    const cyclic: Record<string, unknown> = { name: 'x' };
    cyclic['self'] = cyclic;
    expect(() => JSON.stringify(redact(cyclic))).not.toThrow();
    expect(JSON.stringify(redact(cyclic))).toContain('[circular]');
  });

  it('caps depth, array length and key count', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 20; i += 1) deep = { next: deep };
    expect(JSON.stringify(redact(deep))).toContain('[depth-limit]');
    expect(JSON.stringify(redact(Array.from({ length: 100 }, (_, i) => i)))).toContain('more]');
  });

  it('replaces values JSON.stringify cannot serialise', () => {
    const out = redact({ fn: () => 1, sym: Symbol('s'), big: 10n }) as Record<string, unknown>;
    expect(out['fn']).toBe(REDACTED);
    expect(out['sym']).toBe(REDACTED);
    expect(out['big']).toBe('10');
  });
});

describe('JsonLogger — every line is redacted and correlated', () => {
  function capture(): { logger: JsonLogger; lines: LogRecord[] } {
    const lines: LogRecord[] = [];
    const logger = new JsonLogger('debug', (line) => {
      lines.push(JSON.parse(line) as LogRecord);
    });
    return { logger, lines };
  }

  it('emits one JSON object per line with ts/level/msg', () => {
    const { logger, lines } = capture();
    logger.write('info', 'http_request', { handler: 'OidcController.token', status: 200 });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({ level: 'info', msg: 'http_request', status: 200 });
    expect(typeof lines[0]?.ts).toBe('string');
  });

  it('redacts fields AND scrubs the message itself', () => {
    const { logger, lines } = capture();
    logger.write('warn', `enrolment failed for ${NID}`, { nid: NID, sessionToken: 'ey.a.b' });
    const text = JSON.stringify(lines[0]);
    expect(text).not.toContain(NID);
    expect(text).not.toContain('ey.a.b');
    expect(lines[0]?.msg).toContain(REDACTED_NID);
  });

  it('carries the request correlation id when one is in scope', () => {
    const { logger, lines } = capture();
    logger.write('info', 'outside');
    runWithRequestContext({ requestId: 'req-abc-123' }, () => {
      logger.write('info', 'inside');
    });
    expect(lines[0]?.requestId).toBeUndefined();
    expect(lines[1]?.requestId).toBe('req-abc-123');
  });

  it('refuses caller-supplied fields that would forge reserved keys', () => {
    const { logger, lines } = capture();
    runWithRequestContext({ requestId: 'real-id-000000' }, () => {
      logger.write('info', 'msg', { level: 'debug', ts: 'forged', requestId: 'spoofed-id-1' });
    });
    expect(lines[0]?.level).toBe('info');
    expect(lines[0]?.ts).not.toBe('forged');
    expect(lines[0]?.requestId).toBe('real-id-000000');
  });

  it('honours the level threshold, and `silent` emits nothing at all', () => {
    const warnOnly = capture();
    const warnLogger = new JsonLogger('warn', (l) => warnOnly.lines.push(JSON.parse(l) as LogRecord));
    warnLogger.write('info', 'dropped');
    warnLogger.write('error', 'kept');
    expect(warnOnly.lines.map((l) => l.msg)).toEqual(['kept']);

    const silent: LogRecord[] = [];
    const silentLogger = new JsonLogger('silent', (l) => silent.push(JSON.parse(l) as LogRecord));
    silentLogger.write('error', 'nothing');
    expect(silent).toHaveLength(0);
  });

  it('routes Nest-style logger calls through the same redaction', () => {
    const { logger, lines } = capture();
    logger.error(new Error(`boom ${NID}`), 'AttestationService');
    expect(JSON.stringify(lines[0])).not.toContain(NID);
    expect(lines[0]?.context).toBe('AttestationService');
  });
});

describe('correlation ids — inbound values are untrusted', () => {
  it('accepts a well-shaped caller id', () => {
    expect(sanitizeRequestId('trace-0af7651916cd43dd')).toBe('trace-0af7651916cd43dd');
  });

  it('replaces log-injection, oversized and wrong-shaped ids with a fresh uuid', () => {
    for (const hostile of ['short', 'has spaces here', `bad\nline`, 'x'.repeat(200), 42, undefined]) {
      const id = sanitizeRequestId(hostile);
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
    }
  });
});
