// @vitest-environment node
import { describe, expect, it } from 'vitest';

import { badScript, scriptSrc } from '../scripts/remote-code.mjs';

const page = (script: string): string => `<!doctype html><html><head>${script}</head><body></body></html>`;

describe('the build check on pages', () => {
  it('reads src in every HTML quoting form', () => {
    expect(scriptSrc(' type="module" src="./assets/main.js"')).toBe('./assets/main.js');
    expect(scriptSrc(" src='main.js'")).toBe('main.js');
    expect(scriptSrc(' src=main.js defer')).toBe('main.js');
    expect(scriptSrc(' SRC = "main.js"')).toBe('main.js');
    expect(scriptSrc(' type="module"')).toBeUndefined();
    expect(scriptSrc(' src\u00a0="main.js"')).toBeUndefined();
    expect(scriptSrc('\fsrc\f=\f"main.js"')).toBe('main.js');
  });

  it('accepts local scripts whatever their quoting', () => {
    for (const tag of [
      '<script type="module" crossorigin src="./assets/popup.js"></script>',
      "<script src='main.js'></script>",
      '<script src=main.js></script>',
      '<script src=assets/main.js type=module></script>',
      '<SCRIPT SRC="main.js"></SCRIPT>',
    ]) {
      expect(badScript(page(tag)), tag).toBeUndefined();
    }
  });

  it('still rejects remote, protocol-relative and inline scripts in every quoting form', () => {
    for (const tag of [
      "<script src='https://example.com/x.js'></script>",
      '<script src="https://example.com/x.js"></script>',
      '<script src=https://example.com/x.js></script>',
      "<script src='//example.com/x.js'></script>",
      '<script src=//example.com/x.js></script>',
      "<script src='data:text/javascript,alert(1)'></script>",
      '<script>alert(1)</script>',
      "<script src='main.js'>alert(1)</script>",
      '<script type="module"></script>',
      '<script src></script>',
    ]) {
      expect(badScript(page(tag)), tag).toBe(tag);
    }
  });

  it('reads the real src attribute, not one in another name or value', () => {
    for (const tag of [
      '<script data-src="main.js" src="https://example.com/x.js"></script>',
      '<script title=" src=main.js" src=\'//example.com/x.js\'></script>',
      '<script src="https://example.com/x.js" src="main.js"></script>',
      // U+00A0 isn't HTML whitespace: the first attribute is named `src\u00a0`.
      '<script src\u00a0="main.js" src="https://example.com/x.js"></script>',
      '<script x\u00a0src="main.js" src="https://example.com/x.js"></script>',
    ]) {
      expect(badScript(page(tag)), tag).toBe(tag);
    }
  });

  it('rejects a src a browser reads as remote though its text is not', () => {
    for (const tag of [
      '<script src=" https://example.com/x.js"></script>',
      '<script src="ht\ttps://example.com/x.js"></script>',
      "<script src='ht\ntps://example.com/x.js'></script>",
      '<script src="https&#58;//example.com/x.js"></script>',
      '<script src="/\\example.com/x.js"></script>',
    ]) {
      expect(badScript(page(tag)), tag).toBe(tag);
    }
  });
});
