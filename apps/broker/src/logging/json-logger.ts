import type { LoggerService, LogLevel } from '@nestjs/common';
import { currentRequestId } from './correlation.js';
import { redact, scrubString } from './redact.js';

/** Emittable levels. `silent` is a THRESHOLD only — nothing is logged at it. */
export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type BrokerLogLevel = (typeof LOG_LEVELS)[number];
export type BrokerLogThreshold = BrokerLogLevel | 'silent';

const LEVEL_RANK: Record<BrokerLogThreshold, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: Number.POSITIVE_INFINITY,
};

/** Nest emits five levels; map them onto ours (verbose collapses into debug). */
const NEST_LEVEL_MAP: Record<LogLevel, BrokerLogLevel> = {
  verbose: 'debug',
  debug: 'debug',
  log: 'info',
  warn: 'warn',
  error: 'error',
  fatal: 'error',
};

export interface LogRecord {
  ts: string;
  level: BrokerLogLevel;
  msg: string;
  context?: string;
  requestId?: string;
  [key: string]: unknown;
}

/**
 * Minimal JSON logger (06 §7 — operational logs are a separate stream from the
 * audit trail, and must be machine-parseable for the Phase 3/4 alerting we are
 * building against).
 *
 * Hand-rolled rather than pulling in pino/winston: this is ~80 lines, the
 * broker sits on the citizen-authentication path where every dependency is
 * supply-chain surface (06 §8), and — decisively — a third-party logger would
 * format values BEFORE we could redact them. Owning the write path is what
 * makes the redaction guarantee in `redact.ts` actually total: there is
 * exactly one place a value can become a log line, and it goes through
 * `redact()` on the way.
 *
 * Every line carries the request correlation id when one exists, so an
 * operator handed one id can reconstruct a whole request across services.
 */
export class JsonLogger implements LoggerService {
  private readonly threshold: number;

  constructor(
    level: BrokerLogThreshold = 'info',
    private readonly sink: (line: string) => void = (line) => process.stdout.write(line),
  ) {
    this.threshold = LEVEL_RANK[level];
  }

  /** Structured entry point. Extra fields are redacted like everything else. */
  write(level: BrokerLogLevel, msg: string, fields?: Record<string, unknown>): void {
    if (LEVEL_RANK[level] < this.threshold) return;
    const record: LogRecord = {
      ts: new Date().toISOString(),
      level,
      msg: scrubString(msg),
    };
    const requestId = currentRequestId();
    if (requestId) record['requestId'] = requestId;
    if (fields) {
      const safe = redact(fields) as Record<string, unknown>;
      for (const [k, v] of Object.entries(safe)) {
        // Reserved keys are never overwritten by caller-supplied fields:
        // a forged `level` or `ts` would corrupt downstream log queries.
        if (k === 'ts' || k === 'level' || k === 'msg' || k === 'requestId') continue;
        record[k] = v;
      }
    }
    // JSON.stringify cannot throw here: redact() has already replaced every
    // non-serialisable value (functions, symbols, bigints, cycles).
    this.sink(`${JSON.stringify(record)}\n`);
  }

  // --- Nest LoggerService surface ----------------------------------------
  // Nest calls these with (message, ...optionalParams), where the LAST param
  // is conventionally the context string. Messages arriving here can be any
  // shape, so they go through redact() rather than String().

  private emitNest(level: LogLevel, message: unknown, params: unknown[]): void {
    const context = typeof params.at(-1) === 'string' ? (params.at(-1) as string) : undefined;
    const rest = context !== undefined ? params.slice(0, -1) : params;
    const fields: Record<string, unknown> = {};
    if (context !== undefined) fields['context'] = context;
    if (rest.length > 0) fields['detail'] = rest.length === 1 ? rest[0] : rest;
    const text =
      typeof message === 'string'
        ? message
        : message instanceof Error
          ? message.message
          : JSON.stringify(redact(message));
    if (message instanceof Error && message.stack) fields['stack'] = message.stack;
    this.write(NEST_LEVEL_MAP[level], text ?? '', fields);
  }

  log(message: unknown, ...params: unknown[]): void {
    this.emitNest('log', message, params);
  }

  error(message: unknown, ...params: unknown[]): void {
    this.emitNest('error', message, params);
  }

  warn(message: unknown, ...params: unknown[]): void {
    this.emitNest('warn', message, params);
  }

  debug(message: unknown, ...params: unknown[]): void {
    this.emitNest('debug', message, params);
  }

  verbose(message: unknown, ...params: unknown[]): void {
    this.emitNest('verbose', message, params);
  }

  fatal(message: unknown, ...params: unknown[]): void {
    this.emitNest('fatal', message, params);
  }
}
