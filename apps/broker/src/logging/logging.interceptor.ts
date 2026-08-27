import { CallHandler, ExecutionContext, Inject, Injectable, NestInterceptor } from '@nestjs/common';
import type { Request, Response } from 'express';
import { Observable, tap } from 'rxjs';
import { MetricsService } from '../observability/metrics.service.js';
import type { JsonLogger } from './json-logger.js';
import { BROKER_LOGGER } from './logging.tokens.js';


/**
 * One structured line per HTTP request, plus the HTTP metric families.
 *
 * What is deliberately NOT logged:
 *  - **request and response bodies** — an enrolment body carries a biometric
 *    sample and a raw NID (07 §1). Redaction would catch them, but the only
 *    airtight answer is never to hand them to the logger.
 *  - **query strings** — `/oidc/authorize?login_hint=…` carries a pairwise
 *    subject and the redirect back carries an authorization code (04 §3).
 *    Only `req.path` is logged.
 *  - **headers** — `authorization` is a bearer token on most routes.
 *
 * The route label is the CONTROLLER HANDLER name, not the URL: it is bounded
 * (metric cardinality) and it cannot contain an identifier, whereas
 * `/admin/rps/<uuid>/pairwise` contains one by construction.
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(
    @Inject(BROKER_LOGGER) private readonly logger: JsonLogger,
    private readonly metrics: MetricsService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== 'http') return next.handle();
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();
    const handler = `${context.getClass().name}.${context.getHandler().name}`;
    const startedAt = process.hrtime.bigint();

    const finish = (outcome: 'ok' | 'error'): void => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      // On the error path the exception filter has not run yet, so
      // res.statusCode still holds the pre-error value and would be
      // misleading; 0 means "status not yet decided" and the metric records
      // it as the `error` status class.
      const statusCode = outcome === 'ok' ? res.statusCode : 0;
      this.metrics.recordHttpRequest({ handler, statusCode, durationMs });
      this.logger.write(outcome === 'ok' ? 'info' : 'warn', 'http_request', {
        handler,
        method: req.method,
        // Path only — never the query string (login_hint / code / state).
        path: req.path,
        status: statusCode,
        outcome,
        durationMs: Math.round(durationMs * 100) / 100,
      });
    };

    return next.handle().pipe(
      tap({
        next: () => finish('ok'),
        error: () => finish('error'),
      }),
    );
  }
}
