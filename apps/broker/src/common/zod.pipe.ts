import { Injectable, PipeTransform } from '@nestjs/common';
import { BridgeError } from '@sdid/shared';
import type { ZodType } from 'zod';

/** Body/query validation pipe: usage `@Body(new ZodPipe(schema))`. */
@Injectable()
export class ZodPipe<T> implements PipeTransform<unknown, T> {
  constructor(private readonly schema: ZodType<T>) {}

  transform(value: unknown): T {
    const parsed = this.schema.safeParse(value);
    if (!parsed.success) {
      throw new BridgeError('invalid_request', 'Request validation failed', 400);
    }
    return parsed.data;
  }
}
