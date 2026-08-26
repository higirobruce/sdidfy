import { Global, Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { loadConfig } from '../config.js';
import { JsonLogger } from './json-logger.js';
import { LoggingInterceptor } from './logging.interceptor.js';
import { BROKER_LOGGER } from './logging.tokens.js';

/** Build the process logger from config. Also used by main.ts before Nest boots. */
export function createBrokerLogger(): JsonLogger {
  return new JsonLogger(loadConfig().LOG_LEVEL);
}

/**
 * Structured logging (06 §7). Global: the logger and the request-logging
 * interceptor apply to the whole surface, and an operational log line that
 * exists only on some routes is worse than none — an incident reconstruction
 * would silently miss the routes nobody remembered to annotate.
 *
 * APP_INTERCEPTOR registers `LoggingInterceptor` app-wide, so the one line
 * per request and the HTTP metrics cover every controller automatically,
 * including ones added later.
 */
@Global()
@Module({
  providers: [
    { provide: BROKER_LOGGER, useFactory: createBrokerLogger },
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor },
  ],
  exports: [BROKER_LOGGER],
})
export class LoggingModule {}
