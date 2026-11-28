// The page half of the build's "no remote or dynamic code" check (README §2; security.md): every
// script a page holds loads from the package, and none is inline. Kept apart from build.mjs so the
// tests can run it without Vite.

/**
 * The `src` a script tag's attribute text gives, as a browser reads it: the first `src` attribute
 * (names are case-insensitive), with its value double-quoted, single-quoted or unquoted (`''`
 * for one with no value); `undefined` for none.
 * @param {string} attrs the text between `<script` and `>`
 * @returns {string | undefined}
 */
export function scriptSrc(attrs) {
  // HTML's whitespace is ASCII only (tab, LF, FF, CR, space): any other, such as U+00A0, is part
  // of the name or value, so `\s` would read a different attribute than the browser does.
  for (const m of attrs.matchAll(/([^\t\n\f\r "'>/=]+)(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:"([^"]*)"|'([^']*)'|([^\t\n\f\r >]+)))?/g)) {
    if ((m[1] ?? '').toLowerCase() === 'src') {
      return m[2] ?? m[3] ?? m[4] ?? '';
    }
  }
  return undefined;
}

/**
 * True for a `src` that may load from outside the package: one with a scheme, protocol-relative,
 * or one a browser could read differently from the text (an entity, a backslash). Browsers drop
 * tabs and newlines anywhere in a URL and trim spaces and controls around it, so this does too.
 * @param {string} src
 */
export function remoteSrc(src) {
  const chars = [...src.replace(/[\t\n\r]/g, '')];
  const space = (/** @type {string | undefined} */ c) => c !== undefined && c.charCodeAt(0) <= 0x20;
  while (space(chars[0])) {
    chars.shift();
  }
  while (space(chars.at(-1))) {
    chars.pop();
  }
  const url = chars.join('');
  return url === '' || /[\\&]/.test(url) || /^[a-z][a-z0-9+.-]*:|^\/\//i.test(url);
}

/**
 * The first script in `html` that is inline or may load from outside the package, as its tag
 * text, or `undefined` when every script loads from the package.
 * @param {string} html
 * @returns {string | undefined}
 */
export function badScript(html) {
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)) {
    const src = scriptSrc(m[1] ?? '');
    if (src === undefined || remoteSrc(src) || (m[2] ?? '').trim() !== '') {
      return m[0];
    }
  }
  return undefined;
}
