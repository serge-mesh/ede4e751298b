// The real-browser tests (browser-extension.md §5): the built extension in Playwright's Chromium
// and Firefox against a fake edge (test/browser/harness). `npm run test:browser` builds first.

import { defineConfig } from '@playwright/test';

import { scaled } from './test/browser/harness/time';

export default defineConfig({
  testDir: 'test/browser',
  testMatch: '**/*.spec.ts',
  outputDir: 'test-results',
  // Scaled for slower machines (test/browser/harness/time.ts).
  timeout: scaled(90_000),
  expect: { timeout: scaled(15_000) },
  // Each test launches its own browser; two at a time keep this machine responsive.
  workers: process.env['CI'] === undefined ? 2 : 1,
  retries: 0,
  forbidOnly: process.env['CI'] !== undefined,
  reporter: [['list']],
  // Tests tagged @slow run only with `npm run test:browser:slow`.
  ...(process.env['PICKET_BROWSER_SLOW'] === '1' ? {} : { grepInvert: /@slow/ }),
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
  ],
});
