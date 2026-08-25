// @sdid/e2e — "ghost login" e2e (09 §6): test RP completes a full CIBA login
// of a simulated device against mock SDID, end to end.
// - ghost-login.spec.ts  vitest suite over the real broker process
// - ghost-login-demo.ts  narrated demo (pnpm demo:ghost-login)
export {
  ADMIN_TOKEN,
  BROKER_PORT,
  BROKER_URL,
  BrokerHarness,
  DATABASE_URL,
  NID_PEPPER,
  REPO_ROOT,
  clearEnrolmentThrottles,
  ensureBrokerBuilt,
  revokeAllBindingsViaSql,
  sleep,
} from './harness.js';
