// The CI job's Playwright image follows the pinned @playwright/test (its browsers are that
// version's): a version bump without the image tag fails here, before CI does.

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), 'utf8');

describe('CI', () => {
  it("runs the browser tests in the Playwright image of the pinned @playwright/test", () => {
    const pkg = JSON.parse(read('../package.json')) as { devDependencies: Record<string, string> };
    const version = pkg.devDependencies['@playwright/test'];
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    const images = [...read('../../.github/workflows/ci.yml').matchAll(/mcr\.microsoft\.com\/playwright:v([0-9.]+)-\w+@sha256:[0-9a-f]{64}/g)].map((m) => m[1]);
    expect(images).toEqual([version]);
  });
});
