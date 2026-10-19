import { defineConfig } from 'vitest/config';

// Own config so Vitest doesn't walk up to the frontend's vitest.config.ts, which
// imports packages the backend (and its CI job) doesn't install.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
