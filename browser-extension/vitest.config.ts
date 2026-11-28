import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Tests run in jsdom with an in-memory stand-in for the WebExtension APIs (test/fake-browser.ts)
// in place of webextension-polyfill.
export default defineConfig({
  resolve: {
    alias: {
      'webextension-polyfill': fileURLToPath(new URL('./test/fake-browser.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
    restoreMocks: true,
  },
});
