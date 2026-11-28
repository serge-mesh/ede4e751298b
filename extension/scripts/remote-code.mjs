// The page half of the build's "no remote or dynamic code" check (README §2; security.md): every
// script a page holds loads from the package, and none is inline. Kept apart from build.mjs so the
// tests can run it without Vite.
//
// The page is parsed as a browser parses it (jsdom's HTML parser, which runs no scripts), and each
// `src` is resolved as a browser resolves it (WHATWG URL), so quoting, whitespace, entities,
// duplicate or malformed attributes and backslashes can't make the check read a different script
// or URL than the browser loads.

import { JSDOM } from 'jsdom';

const HTML_NS = 'http://www.w3.org/1999/xhtml';

/** Where the page stands in for the URL check: any other origin is outside the package. */
const BASE = new URL('https://package.invalid/pages/page.html');

/**
 * True for a `src` that loads from outside the package: one that resolves to another origin
 * (another scheme, a host, `data:` or `blob:`), or an empty one.
 * @param {string} src the attribute's value, entities decoded
 */
export function remoteSrc(src) {
  if (src.trim() === '') {
    return true;
  }
  try {
    return new URL(src, BASE).origin !== BASE.origin;
  } catch {
    return true;
  }
}

/**
 * The first script in `html` that is inline or may load from outside the package, as its markup,
 * or `undefined` when every script loads from the package. An SVG script (it loads with `href`)
 * counts as one that may.
 * @param {string} html
 * @returns {string | undefined}
 */
export function badScript(html) {
  const doc = new JSDOM(html).window.document;
  for (const s of doc.querySelectorAll('script')) {
    const src = s.getAttribute('src');
    if (s.namespaceURI !== HTML_NS || src === null || remoteSrc(src) || (s.textContent ?? '').trim() !== '') {
      return s.outerHTML;
    }
  }
  return undefined;
}
