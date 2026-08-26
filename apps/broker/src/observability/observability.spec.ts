import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BridgeErrorFilter } from '../common/bridge-error.filter.js';
import { DbModule } from '../db/db.module.js';
import { KeysModule, KeysService } from '../keys/keys.service.js';
import { RedisModule } from '../redis/redis.module.js';
import { cleanTestData, createTestApp, type TestContext } from '../modules/enrolment/testkit.js';
import { ObservabilityModule } from './observability.module.js';

const ADMIN_TOKEN = 'dev-admin-token';

describe('/metrics endpoint (09 §2 Phase 3)', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestApp();
    await cleanTestData(ctx);
  });

  afterAll(async () => {
    await ctx.app.close();
  });

  it('refuses an unauthenticated scrape', async () => {
    await ctx.http().get('/metrics').expect(401);
  });

  it('refuses a wrong token', async () => {
    await ctx.http().get('/metrics').set('Authorization', 'Bearer nope').expect(401);
  });

  it('serves the Prometheus text format to an authorised scraper', async () => {
    const res = await ctx.http()
      .get('/metrics')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.headers['content-type']).toContain('version=0.0.4');
    expect(res.text).toContain('# HELP sdid_broker_build_info');
    expect(res.text).toContain('# TYPE sdid_broker_build_info gauge');
    expect(res.text).toContain('sdid_broker_enrolment_attempts_total');
    expect(res.text).toContain('sdid_broker_audit_append_failures_total');
  });

  it('exposes the families the runbook alerts on', async () => {
    const res = await ctx.http()
      .get('/metrics')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    for (const family of [
      'sdid_broker_enrolment_attempts_total',
      'sdid_broker_attestation_verdicts_total',
      'sdid_broker_biometric_match_total',
      'sdid_broker_ciba_requests_total',
      'sdid_broker_ciba_decisions_total',
      'sdid_broker_ciba_expiries_total',
      'sdid_broker_tokens_issued_total',
      'sdid_broker_signature_verification_failures_total',
      'sdid_broker_rate_limit_hits_total',
      'sdid_broker_lockout_hits_total',
      'sdid_broker_anomaly_detections_total',
      'sdid_broker_sdid_call_duration_seconds',
      'sdid_broker_sdid_circuit_open',
      'sdid_broker_audit_appends_total',
      'sdid_broker_push_deliveries_total',
      'sdid_broker_readiness',
    ]) {
      expect(res.text).toContain(`# TYPE ${family}`);
    }
  });

  it('records HTTP traffic under a bounded handler label, never a URL', async () => {
    await ctx.http().get('/healthz').expect(200);
    const res = await ctx.http()
      .get('/metrics')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    expect(res.text).toMatch(/sdid_broker_http_requests_total\{handler="HealthController\.liveness"/);
    expect(res.text).not.toContain('/healthz');
  });

  it('never renders an identifying value, even after real traffic', async () => {
    const res = await ctx.http()
      .get('/metrics')
      .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .expect(200);
    // No 16-digit NID run, and no uuid — the two shapes that would mean a
    // citizen/binding identifier had reached the monitoring estate.
    expect(res.text).not.toMatch(/\d{16}/);
    expect(res.text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
  });
});

describe('/healthz and /readyz (09 §2 Phase 3)', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestApp();
  });

  afterAll(async () => {
    await ctx.app.close();
  });

  it('/healthz answers 200 without touching a dependency', async () => {
    const res = await ctx.http().get('/healthz').expect(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('/healthz needs no credential (an orchestrator cannot hold one)', async () => {
    await ctx.http().get('/healthz').expect(200);
  });

  it('/readyz reports ready when Postgres, Redis and the signing key all work', async () => {
    const res = await ctx.http().get('/readyz').expect(200);
    expect(res.body).toEqual({
      status: 'ready',
      checks: { postgres: 'ok', redis: 'ok', signing_key: 'ok' },
    });
  });

  it('/readyz leaks no detail beyond ok/fail per component', async () => {
    const res = await ctx.http().get('/readyz').expect(200);
    const text = JSON.stringify(res.body);
    expect(text).not.toMatch(/postgres:\/\/|redis:\/\/|password|localhost/i);
  });
});

describe('/readyz reflects a genuinely broken dependency', () => {
  let app: INestApplication;

  beforeAll(async () => {
    // The signing key is the check that cannot be simulated by stopping a
    // container in a test, so it is driven through the seam: a KeysService
    // whose probe throws is exactly what an expired KMS credential looks like
    // once custody moves off the dev store (decision #5).
    const moduleRef = await Test.createTestingModule({
      imports: [ObservabilityModule, DbModule, RedisModule, KeysModule],
    })
      .overrideProvider(KeysService)
      .useValue({
        async probeSigning(): Promise<void> {
          throw new Error('KMS credential expired');
        },
      })
      .compile();
    app = moduleRef.createNestApplication();
    app.useGlobalFilters(new BridgeErrorFilter());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('answers 503 with the failing component marked, and no error detail', async () => {
    const res = await request(app.getHttpServer()).get('/readyz').expect(503);
    expect(res.body.status).toBe('not_ready');
    expect(res.body.checks.signing_key).toBe('fail');
    // Postgres and Redis are genuinely up in this suite.
    expect(res.body.checks.postgres).toBe('ok');
    expect(res.body.checks.redis).toBe('ok');
    expect(JSON.stringify(res.body)).not.toContain('KMS credential expired');
  });

  it('still answers /healthz 200 — a dependency outage must not kill the process', async () => {
    await request(app.getHttpServer()).get('/healthz').expect(200);
  });
});
