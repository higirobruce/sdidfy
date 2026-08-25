import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { RpModule } from '../rp/rp.module.js';
import { OidcController } from './oidc.controller.js';
import { TokenService } from './token.service.js';

/**
 * OAuth2 endpoints must accept application/x-www-form-urlencoded (RFC 6749).
 * Nest's express adapter parses urlencoded bodies by default; this fallback
 * covers configurations where that parser is disabled, without touching
 * main.ts. It only runs when nothing has parsed the body yet.
 */
function urlencodedFallback(req: Request, _res: Response, next: NextFunction): void {
  const contentType = req.headers['content-type'] ?? '';
  if (req.body !== undefined || !contentType.includes('application/x-www-form-urlencoded')) {
    next();
    return;
  }
  let raw = '';
  req.setEncoding('utf8');
  req.on('data', (chunk: string) => {
    raw += chunk;
  });
  req.on('end', () => {
    try {
      req.body = Object.fromEntries(new URLSearchParams(raw));
    } catch {
      req.body = {};
    }
    next();
  });
}

/** RP-facing OIDC protocol surface (spec 04): discovery, token, userinfo, lifecycle. */
@Module({
  imports: [RpModule],
  controllers: [OidcController],
  providers: [TokenService],
  exports: [TokenService],
})
export class OidcModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(urlencodedFallback).forRoutes('{*splat}');
  }
}
