// @vitest-environment node
import { describe, expect, it } from 'vitest';

import { badScript, scriptSrc } from '../scripts/remote-code.mjs';

const page = (script: string): string => `<!doctype html><html><head>${script}</head><body></body></html>`;

/** One script tag per non-blank line. */
const tags = (block: string): string[] =>
  block
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');

/** Local scripts, whatever their quoting. */
const LOCAL = tags(`
  <script type="module" crossorigin src="./assets/popup.js"></script>
  <script src='main.js'></script>
  <script src=main.js></script>
  <script src=assets/main.js type=module></script>
  <SCRIPT SRC="main.js"></SCRIPT>
`);

/** Remote, protocol-relative and inline scripts, in every quoting form. */
const REMOTE_OR_INLINE = tags(`
  <script src='https://example.com/x.js'></script>
  <script src="https://example.com/x.js"></script>
  <script src=https://example.com/x.js></script>
  <script src='//example.com/x.js'></script>
  <script src=//example.com/x.js></script>
  <script src='data:text/javascript,alert(1)'></script>
  <script>alert(1)</script>
  <script src='main.js'>alert(1)</script>
  <script type="module"></script>
  <script src></script>
`);

/**
 * A remote src behind text that only looks like a local one: in another attribute's name or value,
 * a second src, a name that U+00A0 (not HTML whitespace) extends, and a src a browser reads as
 * remote though its text isn't (a leading space, an entity, a backslash).
 */
const DISGUISED = [
  ...tags(`
    <script data-src="main.js" src="https://example.com/x.js"></script>
    <script title=" src=main.js" src='//example.com/x.js'></script>
    <script src="https://example.com/x.js" src="main.js"></script>
    <script src=" https://example.com/x.js"></script>
    <script src="https&#58;//example.com/x.js"></script>
    <script src="/\\example.com/x.js"></script>
  `),
  '<script src ="main.js" src="https://example.com/x.js"></script>',
  '<script x src="main.js" src="https://example.com/x.js"></script>',
  // Browsers drop tabs and newlines anywhere in a URL.
  '<script src="ht\ttps://example.com/x.js"></script>',
  "<script src='ht\ntps://example.com/x.js'></script>",
];

describe('the build check on pages', () => {
  it('reads src in every HTML quoting form', () => {
    expect(scriptSrc(' type="module" src="./assets/main.js"')).toBe('./assets/main.js');
    expect(scriptSrc(" src='main.js'")).toBe('main.js');
    expect(scriptSrc(' src=main.js defer')).toBe('main.js');
    expect(scriptSrc(' SRC = "main.js"')).toBe('main.js');
    expect(scriptSrc('\fsrc\f=\f"main.js"')).toBe('main.js');
    expect(scriptSrc(' type="module"')).toBeUndefined();
    expect(scriptSrc(' src ="main.js"')).toBeUndefined();
  });

  it('accepts local scripts whatever their quoting', () => {
    expect(LOCAL).toHaveLength(5);
    for (const tag of LOCAL) {
      expect(badScript(page(tag)), tag).toBeUndefined();
    }
  });

  it('rejects remote, protocol-relative and inline scripts in every quoting form, and disguised ones', () => {
    expect(REMOTE_OR_INLINE).toHaveLength(10);
    expect(DISGUISED).toHaveLength(10);
    for (const tag of [...REMOTE_OR_INLINE, ...DISGUISED]) {
      expect(badScript(page(tag)), tag).toBe(tag);
    }
  });
});
