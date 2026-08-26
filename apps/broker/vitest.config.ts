import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// NestJS DI needs emitDecoratorMetadata, which esbuild (vitest default) does
// not produce — so tests compile through SWC.
export default defineConfig({
  test: {
    include: ['src/**/*.spec.ts', 'src/**/*.test.ts', 'test/**/*.spec.ts', 'test/**/*.test.ts'],
    environment: 'node',
    hookTimeout: 30000,
    testTimeout: 30000,
    fileParallelism: false,
    env: {
      // Silence the JSON request logger during tests: the suite asserts on
      // behaviour, and one structured line per HTTP call would bury failures.
      // Redaction and logger behaviour are tested directly in
      // src/logging/redact.spec.ts against an explicit sink.
      LOG_LEVEL: 'silent',
    },
  },
  plugins: [
    swc.vite({
      // ESM output: vitest 3 cannot load CJS-transformed test files (its CJS
      // entry is a guard that throws). Decorator metadata is still emitted.
      module: { type: 'es6' },
      jsc: {
        parser: { syntax: 'typescript', decorators: true },
        transform: { legacyDecorator: true, decoratorMetadata: true },
        target: 'es2022',
      },
    }),
  ],
});
