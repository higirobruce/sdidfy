import { ArgumentsHost, Catch, ExceptionFilter, HttpException, Logger } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import type { Response } from 'express';
import { ZodError } from 'zod';

/**
 * Maps BridgeError codes to OAuth2-style JSON error bodies. User-facing
 * messages stay generic; specifics live in the audit trail (03 §7).
 */
@Catch()
export class BridgeErrorFilter implements ExceptionFilter {
  private readonly logger = new Logger('BridgeErrorFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    if (exception instanceof BridgeError) {
      res.status(exception.httpStatus).json({ error: exception.code, error_description: exception.message });
      return;
    }
    if (exception instanceof ZodError) {
      res.status(400).json({ error: 'invalid_request', error_description: 'Request validation failed' });
      return;
    }
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      res.status(exception.getStatus()).json(typeof body === 'string' ? { error: body } : body);
      return;
    }
    this.logger.error(exception instanceof Error ? exception.stack : String(exception));
    res.status(500).json({ error: 'internal_error', error_description: 'Internal error' });
  }
}
