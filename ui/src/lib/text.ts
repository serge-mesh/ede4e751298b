// Text from outside core (query names, client/device/edge names, feed rules, verdict details,
// alert and DNSSEC details) is rendered only as React text, with control characters shown
// escaped (core.md §12). Bidi and zero-width format characters are escaped too, so a name
// can't reorder or hide what is displayed around it.

// C0 controls, DEL, C1 controls, and Unicode format characters that change how text reads
// (bidi embeddings/overrides/isolates, zero-width joiners, BOM, line/paragraph separators).
// eslint-disable-next-line no-control-regex
const CONTROL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]", "g");

const NAMED: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

export function escapeControl(text: string): string {
  return text.replace(CONTROL, (ch) => {
    const named = NAMED[ch];
    if (named) return named;
    const code = ch.charCodeAt(0);
    return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u{${code.toString(16)}}`;
  });
}

/** Escapes control characters, but keeps line breaks (for multi-line text such as rule files). */
export function escapeControlKeepLines(text: string): string {
  return text
    .split("\n")
    .map((line) => escapeControl(line))
    .join("\n");
}

/** Any value as display text: strings escaped, others JSON-encoded then escaped. */
export function displayValue(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return escapeControl(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return escapeControl(JSON.stringify(v));
  } catch {
    return "";
  }
}

/** Pretty JSON for detail views, escaped for display (still rendered as React text). */
export function prettyJson(v: unknown): string {
  try {
    return escapeControlKeepLines(JSON.stringify(v, null, 2) ?? "");
  } catch {
    return "";
  }
}

/** The UTF-8 size of a string, without encoding it (a manual feed's file can be at the download cap). */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}
