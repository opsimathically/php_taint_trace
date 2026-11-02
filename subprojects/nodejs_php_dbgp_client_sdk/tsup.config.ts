import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      cli: 'src/cli.ts'
    },
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'node22',
    outExtension({ format }) {
      return {
        js: format === 'cjs' ? '.cjs' : '.mjs'
      };
    }
  }
]);
