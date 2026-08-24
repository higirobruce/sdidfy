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
  },
  plugins: [
    swc.vite({
      module: { type: 'commonjs' },
      jsc: {
        parser: { syntax: 'typescript', decorators: true },
        transform: { legacyDecorator: true, decoratorMetadata: true },
        target: 'es2022',
      },
    }),
  ],
});
