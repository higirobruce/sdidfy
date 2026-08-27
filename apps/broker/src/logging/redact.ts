/**
 * Log redaction (07 §1, 06 §7, non-negotiables in 10).
 *
 * The cardinal rule is that a biometric byte, a raw NID, a token or a nonce
 * must be IMPOSSIBLE to log — not "must not be logged by careful authors".
 * Careful authors are not a control: the logger is called from exception
 * paths, from third-party middleware, and from code written a year from now by
 * someone who has not read `07`. So redaction is applied unconditionally to
 * every value the logger touches, and it works two ways at once because
 * either one alone has a hole:
 *
 *  1. **Deny-listed field names** — kills a whole subtree by the name it is
 *     filed under (`sample`, `token`, `signature`, …), catching values whose
 *     shape is unremarkable. A raw NID captured under `nid` is just digits.
 *  2. **Value-shape scrubbing** — kills a 16-digit run wherever it appears,
 *     including inside a free-text message, a stack trace, an error from a
 *     library, or a field name nobody thought to deny-list. This is the one
 *     that catches `new Error("no match for 1199880012345678")`.
 *
 * Neither pass "sanitises for safe logging" in the sense of preserving value:
 * redacted content is replaced outright with a marker. A log line that is
 * slightly less useful is always the right trade against a national identity
 * number in a log aggregator.
 */

export const REDACTED = '[redacted]';
export const REDACTED_NID = '[redacted-nid]';
export const TRUNCATED = '…[truncated]';

/**
 * Field names whose VALUE never belongs in a log, at any nesting depth.
 * Matching is case-insensitive and ignores `_`/`-`, so `push_token`,
 * `pushToken` and `PUSH-TOKEN` are one entry. When a key matches, the entire
 * value is replaced — objects and arrays included, because the interesting
 * bytes are usually one level further down (`sample.data`).
 *
 * Grouped by why each is here; add to the list rather than reasoning about
 * whether a particular call site is safe.
 */
export const DENIED_FIELD_NAMES: readonly string[] = [
  // Biometrics — never persisted, never logged, never cached (07 §1, T17).
  'sample',
  'samples',
  'biometric',
  'biometricsample',
  'reference',
  'referencebiometric',
  'referencetemplate',
  'template',
  'liveness',
  'faceimage',
  'fingerprint',
  // Raw national identity number (Q8: only the peppered pseudo-NID at rest).
  'nid',
  'rawnid',
  'nationalid',
  'nationalidnumber',
  'idnumber',
  // Credentials, tokens and anything a holder could replay (T4, T13).
  'token',
  'tokens',
  'accesstoken',
  'idtoken',
  'refreshtoken',
  'sessiontoken',
  'authorization',
  'proxyauthorization',
  'cookie',
  'setcookie',
  'bearer',
  'jwt',
  'assertion',
  'clientsecret',
  'secret',
  'password',
  'passphrase',
  'apikey',
  'credentials',
  'credentialsjson',
  'privatekey',
  'privatejwk',
  'p8',
  'pepper',
  'salt',
  'pairwisesalt',
  // Challenge material: logging a live nonce or challenge hands an attacker
  // the exact bytes a device is about to sign (T4).
  'nonce',
  'challenge',
  'challengepayload',
  'payload',
  'signature',
  'code',
  // NOTE `code`: this is the OAuth authorization code, a bearer credential
  // (04 §3). It costs us the ability to log a field literally named `code`,
  // so error/rejection codes are logged as `error_code` / `rejection_code`.
  'codeverifier',
  'authreqid',
  'pushtoken',
  'devicetoken',
  'registrationtoken',
  // Attestation blobs contain device identifiers and are large besides.
  'attestationtoken',
  'keyattestation',
  'integritytoken',
];

const DENIED = new Set(DENIED_FIELD_NAMES.map(normalizeKey));

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[_\-\s]/g, '');
}

export function isDeniedField(key: string): boolean {
  return DENIED.has(normalizeKey(key));
}

/**
 * A Rwandan NID is 16 digits. Scrub any run of 16 OR MORE digits: a longer run
 * contains a NID-shaped substring, and nothing the broker legitimately logs is
 * a 16-digit number (timestamps are 13, ports and counts are short).
 */
const NID_SHAPED = /\d{16,}/g;
/** Same shape, non-global: `.test()` on a /g regex is stateful via lastIndex. */
const NID_SHAPED_TEST = /\d{16,}/;

/** Above this, a string is a blob (token, base64 sample) rather than a message. */
const MAX_STRING_LENGTH = 512;

/** Depth/size ceilings: a log call must never become the expensive operation. */
const MAX_DEPTH = 6;
const MAX_ARRAY_ITEMS = 32;
const MAX_OBJECT_KEYS = 64;

/** Scrub NID-shaped runs and cap length. Applied to EVERY string that is logged. */
export function scrubString(value: string): string {
  const scrubbed = value.replace(NID_SHAPED, REDACTED_NID);
  return scrubbed.length > MAX_STRING_LENGTH
    ? `${scrubbed.slice(0, MAX_STRING_LENGTH)}${TRUNCATED}`
    : scrubbed;
}

/**
 * Recursively redact an arbitrary value for logging. Cycles, class instances,
 * Errors, Buffers and Maps all arrive here in practice, so each is handled
 * rather than left to `JSON.stringify` to mangle or throw on.
 */
export function redact(value: unknown): unknown {
  return redactInner(value, 0, new WeakSet<object>());
}

function redactInner(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return scrubString(value);
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    // A bare number can still be NID-shaped — a 16-digit NID parsed with
    // JSON.parse arrives here as a float64. Numbers stay numbers unless the
    // digits look like an identity, so ordinary counters read normally.
    const rendered = String(value);
    return NID_SHAPED_TEST.test(rendered) ? REDACTED_NID : value;
  }
  if (typeof value === 'bigint') return scrubString(value.toString());
  if (typeof value === 'function' || typeof value === 'symbol') return REDACTED;

  // Binary is the shape a biometric sample arrives in. Never render bytes.
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    return `[binary ${value.byteLength} bytes]`;
  }
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) {
    return {
      name: value.name,
      message: scrubString(value.message),
      // Stack traces routinely embed argument values via framework frames.
      stack: value.stack ? scrubString(value.stack) : undefined,
    };
  }

  if (typeof value === 'object') {
    if (seen.has(value)) return '[circular]';
    if (depth >= MAX_DEPTH) return '[depth-limit]';
    seen.add(value);

    if (Array.isArray(value)) {
      const items = value.slice(0, MAX_ARRAY_ITEMS).map((v) => redactInner(v, depth + 1, seen));
      if (value.length > MAX_ARRAY_ITEMS) items.push(`[+${value.length - MAX_ARRAY_ITEMS} more]`);
      return items;
    }
    if (value instanceof Map) {
      return redactInner(Object.fromEntries(value.entries()), depth, seen);
    }
    if (value instanceof Set) {
      return redactInner([...value.values()], depth, seen);
    }

    const out: Record<string, unknown> = {};
    let keys = 0;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (keys >= MAX_OBJECT_KEYS) {
        out['…'] = '[key-limit]';
        break;
      }
      keys += 1;
      out[k] = isDeniedField(k) ? REDACTED : redactInner(v, depth + 1, seen);
    }
    return out;
  }
  return REDACTED;
}
