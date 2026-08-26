import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import { BridgeErrorFilter } from './common/bridge-error.filter.js';
import { loadConfig } from './config.js';
import { runMigrations } from './db/migrate.js';
import { correlationMiddleware } from './logging/correlation.js';
import { createBrokerLogger } from './logging/logging.module.js';

async function bootstrap(): Promise<void> {
  const config = loadConfig();
  // The JSON logger is built before Nest so boot-time output (migrations,
  // module init, a failed key load) is structured and redacted too — the lines
  // an operator most needs during an incident are the earliest ones.
  const logger = createBrokerLogger();
  await runMigrations();
  const app = await NestFactory.create(AppModule, { logger });
  // Registered before the router so EVERY line logged while handling a
  // request — including from the global exception filter — carries the same
  // correlation id, and the id is echoed back in the response header.
  app.use(correlationMiddleware);
  app.useGlobalFilters(new BridgeErrorFilter());
  await app.listen(config.BROKER_PORT);
  logger.write('info', 'broker_listening', {
    port: config.BROKER_PORT,
    issuer: config.BROKER_ISSUER,
    sdidStrategy: config.SDID_STRATEGY,
    attestationMode: config.ATTESTATION_MODE,
    metricsEnabled: config.METRICS_ENABLED,
    anomalyDetection: config.ANOMALY_ENABLED,
  });
}

bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
