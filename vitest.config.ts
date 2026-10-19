import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Backend tests run from backend/ with their own config
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
