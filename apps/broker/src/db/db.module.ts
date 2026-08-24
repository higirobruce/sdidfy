import { Global, Injectable, Module, OnModuleDestroy } from '@nestjs/common';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { loadConfig } from '../config.js';
import * as schema from './schema.js';

export type Db = NodePgDatabase<typeof schema>;

@Injectable()
export class DbService implements OnModuleDestroy {
  readonly pool: Pool;
  readonly db: Db;

  constructor() {
    this.pool = new Pool({ connectionString: loadConfig().DATABASE_URL, max: 10 });
    this.db = drizzle(this.pool, { schema });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}

@Global()
@Module({
  providers: [DbService],
  exports: [DbService],
})
export class DbModule {}
