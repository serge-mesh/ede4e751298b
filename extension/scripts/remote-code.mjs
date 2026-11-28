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

/**
 * Where the page stands for the URL check, under the extension's own (non-special) scheme, where
 * `https:host/x.js` is an absolute URL, and under a special one, where a backslash is a slash. A
 * src must stay on the page's scheme and host under both.
 */
const BASES = [
  new URL('chrome-extension://package-check/pages/page.html'),
  new URL('https://package.invalid/pages/page.html'),
];

/**
 * True for a `src` that loads from outside the package: one that resolves to another scheme or
 * host (an absolute or protocol-relative URL, `data:`, `blob:`), or an empty one.
 * @param {string} src the attribute's value, entities decoded
 */
export function remoteSrc(src) {
  if (src.trim() === '') {
    return true;
  }
  return BASES.some((base) => {
    try {
      const url = new URL(src, base);
      return url.protocol !== base.protocol || url.host !== base.host;
    } catch {
      return true;
    }
  });
}

/**
 * The first script in `html` that is inline or may load from outside the package, as its markup,
 * or `undefined` when every script loads from the package. Also returned, as markup: an SVG script
 * (it loads with `href`); a `<base href>` (it moves where every relative src resolves); a
 * `<noscript>` (this parser reads its content as markup, a browser with scripting on as raw text,
 * so the two can see different scripts); and, as `<script`, any page whose text holds more
 * `<script` tags than the parsed page has script elements (one hidden in a comment, attribute,
 * template or raw text, where this parser and a browser might disagree). The pages need none.
 * @param {string} html
 * @returns {string | undefined}
 */
export function badScript(html) {
  const doc = new JSDOM(html).window.document;
  const [unwanted] = doc.querySelectorAll('base[href], noscript');
  if (unwanted !== undefined) {
    return unwanted.outerHTML;
  }
  const scripts = [...doc.querySelectorAll('script')];
  for (const s of scripts) {
    const src = s.getAttribute('src');
    if (s.namespaceURI !== HTML_NS || src === null || remoteSrc(src) || (s.textContent ?? '').trim() !== '') {
      return s.outerHTML;
    }
  }
  if ([...html.matchAll(/<script/gi)].length > scripts.length) {
    return '<script';
  }
  return undefined;
}
