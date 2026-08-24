import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { BridgeErrorFilter } from './common/bridge-error.filter.js';
import { loadConfig } from './config.js';
import { runMigrations } from './db/migrate.js';

async function bootstrap(): Promise<void> {
  const config = loadConfig();
  await runMigrations();
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new BridgeErrorFilter());
  await app.listen(config.BROKER_PORT);
  console.log(`SDID Auth Bridge broker listening on :${config.BROKER_PORT} (issuer ${config.BROKER_ISSUER})`);
}

bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
