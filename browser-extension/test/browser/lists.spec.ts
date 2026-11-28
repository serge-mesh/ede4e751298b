// Browser-list URLs (bundles.md §8 "Subscribe"): the options page builds the subscription URL of a
// profile's pruned or full list, or a bundle's, on core's address (from the core UI URL saved at
// setup, or typed), and copies it.

import { expect, setUp, test } from './harness/fixtures';

test('the options page builds browser-list URLs on core’s address', async ({ ext, edge }) => {
  await setUp(ext, edge, { coreUrl: 'https://core.test:8443/ui' });
  const page = (await ext.openExtensionTab('options.html')).surface();
  // Filled from the saved core UI URL.
  await expect.poll(() => page.run(() => document.querySelector<HTMLInputElement>('#list-base')!.value, null)).toBe('https://core.test:8443');
  const url = (): Promise<string> => page.run(() => document.querySelector<HTMLInputElement>('#list-url')!.value, null);

  await page.fill('#list-id', 'kids');
  await expect.poll(url).toBe('https://core.test:8443/lists/profiles/kids.txt');
  await page.select('#list-kind', 'full');
  await expect.poll(url).toBe('https://core.test:8443/lists/profiles/kids-full.txt');
  await page.select('#list-kind', 'bundle');
  expect(await page.text('#list-id-label')).toBe('Bundle ID');
  await page.fill('#list-id', 'block-common');
  await page.fill('#list-base', 'http://core.test:8080');
  await expect.poll(url).toBe('http://core.test:8080/lists/block-common.txt');

  // A profile ID never ends in -full.
  await page.select('#list-kind', 'pruned');
  await page.fill('#list-id', 'kids-full');
  await expect.poll(() => page.text('#list-status')).toBe('A profile ID never ends in "-full": choose the full list above instead.');
  expect(await url()).toBe('');

  await page.fill('#list-id', 'kids');
  await page.click('#copy-url');
  // Copied, or (no clipboard access in this browser) the URL selected for Ctrl+C.
  await expect.poll(() => page.text('#list-status')).toMatch(/^(Copied\.|Press Ctrl\+C \(⌘C\) to copy the selected URL\.)$/);
  expect(await page.run(() => {
    const el = document.querySelector<HTMLInputElement>('#list-url')!;
    return el.value.slice(el.selectionStart ?? 0, el.selectionEnd ?? 0);
  }, null)).toBe('http://core.test:8080/lists/profiles/kids.txt');
});
