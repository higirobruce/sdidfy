/**
 * Injection token for the process-wide JsonLogger. Kept in its own file so the
 * interceptor and the module can both reference it without a circular import.
 */
export const BROKER_LOGGER = Symbol('BROKER_LOGGER');
