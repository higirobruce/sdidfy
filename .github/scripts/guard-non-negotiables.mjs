#!/usr/bin/env node
/**
 * guard-non-negotiables.mjs — a CI backstop for the project's hard rules.
 *
 * Protects three of the non-negotiables in docs/SPEC.md (10 — Decisions Log,
 * "Non-negotiables"; detail in 07 §1, §3 and §4):
 *
 *   1. Biometric samples and reference templates are processed in memory only
 *      and are NEVER persisted (07 §1) and never logged.
 *   2. The raw 16-digit NID is never at rest and never in the audit trail —
 *      only the peppered pseudo-NID is (Q8, 07 §2/§3).
 *   3. `audit_events` is append-only (07 §4): no UPDATE, no DELETE, no
 *      TRUNCATE, and the DB triggers that enforce that are not removed.
 *
 * ---------------------------------------------------------------------------
 * THIS IS A BACKSTOP, NOT A GUARANTEE.
 * ---------------------------------------------------------------------------
 * It is a lexical scanner with no understanding of types, data flow or intent.
 * It catches the obvious, mechanical version of each mistake — the shape a
 * rushed patch actually takes — and nothing subtler. See "WHAT THIS DOES NOT
 * CATCH" at the bottom of this file, and repeat it to anyone who reads a green
 * check here as evidence that a change is safe. Human review against
 * docs/CONTRIBUTING.md ("Non-negotiables a reviewer must check") is the
 * control; this is the tripwire in front of it.
 *
 * Node 22, zero dependencies, no network, no git. Run it with:
 *     pnpm ci:guard
 *
 * Exit codes: 0 = no findings, 1 = findings, 2 = the guard itself failed.
 *
 * Waivers: a finding can be suppressed by putting
 *     spec-guard:allow <rule-id> — <reason>
 * in a comment on the offending line or the line directly above it. A reason
 * is mandatory; a waiver without one is itself a finding. Waivers are printed
 * in the run output so they stay visible in review rather than disappearing.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Directories we never descend into. */
const SKIP_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.git',
  '.turbo',
  '.github', // this guard, and the CI scripts that legitimately name the rules
  'docs', // prose about the rules is not a violation of them
]);

/** Source trees that are subject to the rules. */
const SCAN_ROOTS = ['apps', 'packages', 'e2e'];

/**
 * Test files are exempt from the *logging* rules only. Fixtures and failing
 * assertions legitimately handle and print mock NIDs and synthetic samples
 * (packages/shared/src/mock-biometrics.ts seeds them), and no test file ships
 * to production. They are NOT exempt from the SQL / audit-mutation rules.
 */
const isTestFile = (rel) =>
  /\.(spec|test)\.ts$/.test(rel) || /(^|[/\\])testkit\.ts$/.test(rel);

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/**
 * Column names that suggest a biometric artefact is being put at rest.
 * `attestation` and `device_pubkey_jwk` are proofs, not biometrics, and are
 * deliberately absent. Word-ish substring match against the column name only.
 */
const BIOMETRIC_COLUMN = /(biometric|template|minutia|iris|face|finger|selfie|photo|image|sample|probe|specimen|capture)/i;

/**
 * Columns that are fine despite matching the pattern above, with the reason.
 * Keep this list short and justified — every entry is a hole in the rule.
 */
const BIOMETRIC_COLUMN_ALLOW = new Map([
  // 07 §4 requires the match OUTCOME (pass/fail + score band) in the audit
  // trail. It carries no biometric bytes; the engine zeroizes those.
  ['match_result', 'audit of the match outcome is required by 07 §4 (never the bytes)'],
]);

/**
 * A raw national ID at rest. Matched against the whole column name: anything
 * ENDING in `nid` (`nid`, `raw_nid`, `citizen_nid`) or a spelled-out national
 * identifier. Names beginning `pseudo…` are excluded — `pseudo_nid` is the
 * peppered value the schema is supposed to hold (Q8).
 */
const RAW_NID_COLUMN = /^(?!pseudo)(?:.*_)?(nid|national_id|nid_number|national_id_number|id_number|nin)$/i;

/** Any 16-digit run — the shape of a Rwandan NID — hard-coded in a migration. */
const NID_LITERAL_IN_SQL = /(^|[^0-9])[0-9]{16}([^0-9]|$)/;

/** A column definition line: `name type ...` or `ADD COLUMN name type ...`. */
const SQL_TYPES =
  '(uuid|text|bytea|jsonb|json|bigint|bigserial|serial|int|int4|int8|integer|smallint|boolean|bool|timestamptz|timestamp|date|time|numeric|decimal|real|double|varchar|character|char|inet|cidr|macaddr|xml|tsvector)';
const SQL_COLUMN_DEF = new RegExp(`^\\s*"?([a-z_][a-z0-9_]*)"?\\s+${SQL_TYPES}\\b`, 'i');
const SQL_ADD_COLUMN = new RegExp(`\\bADD\\s+COLUMN\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?"?([a-z_][a-z0-9_]*)"?`, 'i');
const SQL_RENAME_COLUMN = /\bRENAME\s+(?:COLUMN\s+)?"?[a-z_][a-z0-9_]*"?\s+TO\s+"?([a-z_][a-z0-9_]*)"?/i;

/** Statements that would break audit append-only. Applied to .sql and .ts. */
const AUDIT_MUTATIONS = [
  [/\bUPDATE\s+(?:only\s+)?"?audit_events"?\b/i, 'UPDATE of audit_events'],
  [/\bDELETE\s+FROM\s+(?:only\s+)?"?audit_events"?\b/i, 'DELETE FROM audit_events'],
  [/\bTRUNCATE\s+(?:TABLE\s+)?(?:only\s+)?"?audit_events"?\b/i, 'TRUNCATE of audit_events'],
  [/\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?audit_events"?\b/i, 'DROP TABLE audit_events'],
  [/\bDROP\s+TRIGGER\b[^;]{0,120}\bON\s+(?:only\s+)?"?audit_events"?\b/i, 'DROP TRIGGER on audit_events'],
  [/\bALTER\s+TABLE\s+(?:only\s+)?"?audit_events"?\b[^;]{0,120}\bDISABLE\s+TRIGGER\b/i, 'DISABLE TRIGGER on audit_events'],
  // Drizzle query-builder equivalents (apps/broker/src/db/schema.ts exports
  // the table as `auditEvents`).
  [/\.\s*update\s*\(\s*auditEvents\b/, 'drizzle .update(auditEvents)'],
  [/\.\s*delete\s*\(\s*auditEvents\b/, 'drizzle .delete(auditEvents)'],
];

/**
 * Identifiers that, when they reach a log sink as a VALUE, mean a biometric or
 * a raw NID could be written to stdout / a log aggregator. Matched only
 * against the non-string-literal part of a logging call (see stripLiterals),
 * so `console.warn('unknown NID')` is not a finding but
 * `console.warn(\`nid=\${nid}\`)` is.
 */
const SENSITIVE_VALUES = [
  [/\bsample[A-Za-z0-9_]*\b/i, 'a biometric sample'],
  [/\bbiometric[A-Za-z0-9_]*\b/i, 'biometric data'],
  [/\btemplate[A-Za-z0-9_]*\b/i, 'a biometric reference template'],
  [/\b(face|fingerprint|iris|minutiae|selfie|probe)[A-Za-z0-9_]*\b/i, 'a biometric capture'],
  [/(^|[^A-Za-z0-9_])(nid|rawNid|raw_nid|nationalId|national_id)([^A-Za-z0-9_]|$)/, 'a raw NID'],
];

/** Log sinks we scan the arguments of. */
const LOG_CALL_START = /(^|[^\w.$])((?:this\.)?(?:console|logger|log)\s*\.\s*(?:log|info|warn|error|debug|trace|verbose|fatal))\s*\(/g;

// ---------------------------------------------------------------------------
// Machinery
// ---------------------------------------------------------------------------

const findings = [];
const waivers = [];
let filesScanned = 0;

function report(ruleId, file, line, message, evidence) {
  findings.push({ ruleId, file, line, message, evidence });
}

/** Files walked under `dir`, filtered by extension. */
function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

/**
 * A waiver applies to a finding if `spec-guard:allow` appears on the offending
 * line or the line above it. Returns 'none' | 'waived' | 'no-reason'.
 */
function waiverFor(lines, lineNo, ruleId) {
  const candidates = [lines[lineNo - 1] ?? '', lines[lineNo - 2] ?? ''];
  for (const text of candidates) {
    const m = /spec-guard:allow\s*([A-Za-z0-9-]*)\s*(.*)$/.exec(text);
    if (!m) continue;
    const scoped = m[1];
    if (scoped && scoped.toLowerCase() !== ruleId.toLowerCase()) continue;
    const reason = m[2].replace(/^[\s—:-]+/, '').replace(/\*\/\s*$/, '').trim();
    if (reason.length < 8) return { kind: 'no-reason' };
    return { kind: 'waived', reason };
  }
  return { kind: 'none' };
}

/** Record a finding unless it carries a justified inline waiver. */
function flag(ruleId, rel, lines, lineNo, message, evidence) {
  const w = waiverFor(lines, lineNo, ruleId);
  if (w.kind === 'waived') {
    waivers.push({ ruleId, file: rel, line: lineNo, reason: w.reason });
    return;
  }
  if (w.kind === 'no-reason') {
    report(
      'GUARD-WAIVER',
      rel,
      lineNo,
      `spec-guard:allow with no reason (a waiver must say why, in >= 8 characters)`,
      lines[lineNo - 1]?.trim() ?? '',
    );
    return;
  }
  report(ruleId, rel, lineNo, message, evidence);
}

/**
 * Blank out string-literal CONTENT so the log rules see identifiers and
 * template interpolations only. Single/double-quoted contents are removed
 * entirely; inside a template literal the literal text is removed but every
 * `${...}` expression is kept. Not a real parser — good enough for the one
 * question asked of it ("is a value, not a word, being logged?").
 */
function stripLiterals(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "'" || ch === '"') {
      const quote = ch;
      i += 1;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
      continue;
    }
    if (ch === '`') {
      i += 1;
      let depth = 0;
      while (i < src.length) {
        if (depth === 0 && src[i] === '\\') {
          i += 2;
          continue;
        }
        if (depth === 0 && src[i] === '`') {
          i += 1;
          break;
        }
        if (depth === 0 && src[i] === '$' && src[i + 1] === '{') {
          depth = 1;
          i += 2;
          out += ' ';
          continue;
        }
        if (depth > 0) {
          if (src[i] === '{') depth += 1;
          else if (src[i] === '}') {
            depth -= 1;
            if (depth === 0) {
              i += 1;
              out += ' ';
              continue;
            }
          }
          out += src[i];
          i += 1;
          continue;
        }
        i += 1; // literal text inside the template — dropped
      }
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** Extract the argument text of a call whose `(` sits at `openIdx`. */
function callArgs(src, openIdx) {
  let depth = 0;
  let i = openIdx;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      i += 1;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i += 1;
        i += 1;
      }
      i += 1;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
    i += 1;
  }
  return src.slice(openIdx + 1); // unbalanced — scan what we have
}

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/** SQL migrations: what the schema is allowed to put at rest. */
function checkSql(rel, src) {
  const lines = src.split('\n');
  lines.forEach((raw, idx) => {
    const lineNo = idx + 1;
    const line = raw.replace(/--.*$/, ''); // ignore SQL line comments
    if (!line.trim()) return;

    const names = [];
    const def = SQL_COLUMN_DEF.exec(line);
    if (def) names.push(def[1]);
    const added = SQL_ADD_COLUMN.exec(line);
    if (added) names.push(added[1]);
    const renamed = SQL_RENAME_COLUMN.exec(line);
    if (renamed) names.push(renamed[1]);

    for (const name of names) {
      // BIO-COL: a persisted column whose name suggests biometric storage.
      if (BIOMETRIC_COLUMN.test(name) && !BIOMETRIC_COLUMN_ALLOW.has(name.toLowerCase())) {
        flag(
          'BIO-COL',
          rel,
          lines,
          lineNo,
          `column "${name}" reads as biometric storage — biometric samples and reference templates are processed in memory only and never persisted (SPEC 07 §1)`,
          raw.trim(),
        );
      }
      // NID-COL: a persisted column that looks like a raw national ID.
      if (RAW_NID_COLUMN.test(name)) {
        flag(
          'NID-COL',
          rel,
          lines,
          lineNo,
          `column "${name}" reads as a raw NID at rest — only the peppered pseudo-NID is stored (SPEC 07 §2/§3, Q8)`,
          raw.trim(),
        );
      }
    }

    // NID-LITERAL: a 16-digit constant baked into a migration (seed data).
    if (NID_LITERAL_IN_SQL.test(line)) {
      flag(
        'NID-LITERAL',
        rel,
        lines,
        lineNo,
        'a 16-digit literal in a migration has the shape of a real NID — migrations must not carry citizen identifiers',
        raw.trim(),
      );
    }
  });
}

/** Audit append-only, in both SQL and TypeScript. */
function checkAuditMutation(rel, src) {
  const lines = src.split('\n');
  for (const [pattern, label] of AUDIT_MUTATIONS) {
    const rx = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    let m;
    while ((m = rx.exec(src)) !== null) {
      const lineNo = lineOf(src, m.index);
      flag(
        'AUDIT-APPEND-ONLY',
        rel,
        lines,
        lineNo,
        `${label} — audit_events is append-only and its guard triggers must stay in place (SPEC 07 §4)`,
        lines[lineNo - 1]?.trim() ?? m[0],
      );
      if (m.index === rx.lastIndex) rx.lastIndex += 1;
    }
  }
}

/** Logging of a biometric or a raw NID value. */
function checkLogging(rel, src) {
  const lines = src.split('\n');
  LOG_CALL_START.lastIndex = 0;
  let m;
  while ((m = LOG_CALL_START.exec(src)) !== null) {
    const openIdx = src.indexOf('(', m.index + m[1].length);
    if (openIdx === -1) continue;
    const args = stripLiterals(callArgs(src, openIdx));
    const lineNo = lineOf(src, openIdx);
    for (const [pattern, what] of SENSITIVE_VALUES) {
      if (pattern.test(args)) {
        flag(
          'LOG-PII',
          rel,
          lines,
          lineNo,
          `${m[2]}(...) appears to log ${what} — biometric bytes are never logged (SPEC 07 §1) and the raw NID never reaches a log or the audit trail (07 §3, Q8)`,
          lines[lineNo - 1]?.trim() ?? '',
        );
        break; // one finding per call is enough
      }
    }
  }
}

/**
 * The append-only triggers must exist somewhere in the migration set. This
 * catches "migration 0001 was edited" rather than "a new migration drops it".
 */
function checkTriggersStillDeclared(sqlFiles) {
  const all = sqlFiles.map(([, src]) => src).join('\n');
  const hasRowGuard =
    /CREATE\s+TRIGGER[\s\S]{0,200}?BEFORE\s+UPDATE\s+OR\s+DELETE\s+ON\s+(?:only\s+)?"?audit_events"?/i.test(all);
  const hasTruncateGuard =
    /CREATE\s+TRIGGER[\s\S]{0,200}?BEFORE\s+TRUNCATE\s+ON\s+(?:only\s+)?"?audit_events"?/i.test(all);
  if (!hasRowGuard) {
    report(
      'AUDIT-TRIGGER-MISSING',
      'apps/broker/migrations',
      0,
      'no migration declares a BEFORE UPDATE OR DELETE trigger on audit_events — the append-only guarantee (SPEC 07 §4) is unenforced',
      '',
    );
  }
  if (!hasTruncateGuard) {
    report(
      'AUDIT-TRIGGER-MISSING',
      'apps/broker/migrations',
      0,
      'no migration declares a BEFORE TRUNCATE trigger on audit_events (SPEC 07 §4)',
      '',
    );
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

function main() {
  const files = [];
  for (const root of SCAN_ROOTS) {
    const abs = join(REPO_ROOT, root);
    try {
      if (!statSync(abs).isDirectory()) continue;
    } catch {
      continue;
    }
    walk(abs, files);
  }

  const sqlFiles = [];
  for (const abs of files) {
    const rel = relative(REPO_ROOT, abs).split(sep).join('/');
    const isSql = rel.endsWith('.sql');
    const isTs = /\.(ts|tsx|mts|cts)$/.test(rel) && !rel.endsWith('.d.ts');
    if (!isSql && !isTs) continue;

    let src;
    try {
      src = readFileSync(abs, 'utf8');
    } catch (err) {
      report('GUARD-IO', rel, 0, `could not read file: ${err.message}`, '');
      continue;
    }
    filesScanned += 1;

    if (isSql) {
      sqlFiles.push([rel, src]);
      checkSql(rel, src);
    }
    // Audit append-only applies everywhere, tests included: a test that
    // deletes audit rows is a test that would pass against a broken schema.
    checkAuditMutation(rel, src);
    if (isTs && !isTestFile(rel)) checkLogging(rel, src);
  }

  checkTriggersStillDeclared(sqlFiles);

  // ---- output ----
  console.log(`spec-guard: scanned ${filesScanned} file(s) under ${SCAN_ROOTS.join(', ')}`);
  if (waivers.length > 0) {
    console.log(`\nWaived (${waivers.length}) — these are visible on purpose; review them:`);
    for (const w of waivers) {
      console.log(`  ~ ${w.file}:${w.line} [${w.ruleId}] ${w.reason}`);
    }
  }
  if (findings.length === 0) {
    console.log('\nspec-guard: no findings.');
    console.log('Reminder: this is a lexical backstop, not proof of compliance —');
    console.log('see docs/CONTRIBUTING.md for what a reviewer still has to check.');
    return 0;
  }

  console.log(`\nspec-guard: ${findings.length} finding(s):\n`);
  for (const f of findings) {
    // GitHub Actions renders this as an inline annotation on the PR diff.
    if (process.env.GITHUB_ACTIONS === 'true') {
      const msg = `[${f.ruleId}] ${f.message}`.replace(/\r?\n/g, ' ');
      console.log(`::error file=${f.file},line=${Math.max(f.line, 1)}::${msg}`);
    }
    console.log(`  ${f.file}:${f.line}  [${f.ruleId}]`);
    console.log(`    ${f.message}`);
    if (f.evidence) console.log(`    > ${f.evidence}`);
    console.log('');
  }
  console.log('If a finding is a false positive, waive it on the line (or the line above):');
  console.log('    // spec-guard:allow <RULE-ID> — why this is safe');
  console.log('A waiver needs a reason and shows up in every subsequent run.');
  return 1;
}

try {
  process.exit(main());
} catch (err) {
  console.error('spec-guard failed to run:', err);
  process.exit(2);
}

/* ---------------------------------------------------------------------------
 * WHAT THIS DOES NOT CATCH — read this before trusting a green run.
 * ---------------------------------------------------------------------------
 * - Persistence that is not a migration: writing a sample to disk, S3, a
 *   temp file, Redis, an ORM model without a matching migration, or a
 *   crash dump. Only `**/migrations/*.sql` column names are inspected.
 * - A biometric column with an innocent name (`payload`, `blob`, `data`,
 *   `ref`, `b64`). The rule reads names, not contents.
 * - Biometrics or NIDs leaving the process by any route other than a
 *   console/logger call: an HTTP response body, an exception message that
 *   bubbles into a log, a metric label, a Sentry breadcrumb, a `process.
 *   stdout.write`, or a third-party logger not named `console`/`logger`/`log`.
 * - A raw NID assigned to an innocuously named variable and then logged
 *   (`console.log(claimed)`), or one embedded in an object that is logged
 *   whole (`console.log(req.body)` — flagged only if `body`… is not, in fact,
 *   flagged at all).
 * - Audit rows mutated through raw SQL built at runtime from fragments, a
 *   psql/CLI path, a superuser session, or a role that bypasses triggers.
 * - Whether the match engine actually zeroizes, whether the trigger is
 *   actually installed in the running database (CI job `db-integrity` tests
 *   that against a real Postgres), or whether retention is honoured.
 * - Anything in `docs/`, `.github/`, or a non-TypeScript service.
 *
 * In short: it catches the careless version of each mistake. It cannot catch
 * the determined one, and it is not evidence for the DPIA (SPEC 08).
 * ------------------------------------------------------------------------ */
