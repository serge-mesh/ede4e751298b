// What Import… and config restore read (feeds.md §4, core.md §2), without holding a large file in
// React state: a chosen file is inspected from its head once, refused before it is read when core
// couldn't take it, and its request body built once on submit, as a Blob of bounded parts (api.md
// §7: a body may be up to 32 times the download cap).
import { formatBytes, formatNumber } from "./format";
import { utf8Length } from "./text";

/** How much of a file's start is read to tell what it is. */
export const HEAD_BYTES = 256 * 1024;

/** `feeds.max_download_mib`'s default (core.md §5), the cap taken when the settings can't be read. */
export const DEFAULT_DOWNLOAD_MIB = 256;
/** An import body may be up to this many times the download size cap after decompression (api.md §7). */
export const BODY_FACTOR = 32;

/** The download size cap in bytes, and whether it was read from the settings (else core's default). */
export interface DownloadCap {
  bytes: number;
  fromSettings: boolean;
}

export type ImportKind = "json-export" | "file-export" | "misp-export" | "misp-list" | "json" | "list";

/** The feed settings an export declares (a JSON export's `feed`, a file header, a MISP `picket_feed`). */
export interface DeclaredSettings {
  id?: string;
  name?: string;
  provider?: string | null;
  format?: string;
  format_options?: unknown;
  rule_policy?: unknown;
  category?: string;
  warn_on?: unknown;
  misp_type?: string;
}

export interface ImportInfo {
  kind: ImportKind;
  /** What the export says about its feed; for a MISP list without `picket_feed`, only its format. */
  declared: DeclaredSettings | null;
  /**
   * The head didn't settle the kind: a JSON object whose top level doesn't end in it (a
   * `picket_feed` after a long `list`, or `list` itself, may follow), or a line-format file whose
   * header runs past it (a `picket-feed-export` may follow within its first 64 lines). The body
   * build reads on (`importBody`) before the query is chosen, as core reads the whole file
   * (feeds.md §4).
   */
  partial?: boolean;
}

const isWs = (c: string) => c === " " || c === "\t" || c === "\n" || c === "\r";

function skipWs(s: string, i: number): number {
  while (i < s.length && isWs(s[i])) i++;
  return i;
}

/** The index after the JSON string starting at `i` (a `"`), or -1 if it doesn't end in `s`. */
function skipString(s: string, i: number): number {
  for (let j = i + 1; j < s.length; j++) {
    if (s[j] === "\\") j++;
    else if (s[j] === '"') return j + 1;
  }
  return -1;
}

/** The index after the JSON value starting at `i`, or -1 if it doesn't end in `s`. */
function skipValue(s: string, i: number): number {
  const c = s[i];
  if (c === '"') return skipString(s, i);
  if (c === "{" || c === "[") {
    let depth = 0;
    for (let j = i; j < s.length; j++) {
      const d = s[j];
      if (d === '"') {
        j = skipString(s, j);
        if (j < 0) return -1;
        j--;
      } else if (d === "{" || d === "[") depth++;
      else if (d === "}" || d === "]") {
        depth--;
        if (depth === 0) return j + 1;
      }
    }
    return -1;
  }
  let j = i;
  while (j < s.length && !isWs(s[j]) && s[j] !== "," && s[j] !== "}" && s[j] !== "]") j++;
  return j < s.length ? j : -1;
}

/**
 * The top-level keys of a JSON object, in order, with the raw text of each value that ends
 * within `s` (a file's head): enough to tell an export from a MISP list without parsing a
 * file of up to 32 times the download cap.
 */
export function topLevelKeys(s: string): { keys: string[]; values: Map<string, string>; closed: boolean } | null {
  let i = skipWs(s, 0);
  if (s[i] !== "{") return null;
  i++;
  const keys: string[] = [];
  const values = new Map<string, string>();
  let closed = false;
  for (;;) {
    i = skipWs(s, i);
    if (i >= s.length) break;
    if (s[i] === "}") {
      closed = true;
      break;
    }
    if (s[i] !== '"') return keys.length ? { keys, values, closed: true } : null;
    const end = skipString(s, i);
    if (end < 0) break;
    let key: string;
    try {
      key = JSON.parse(s.slice(i, end)) as string;
    } catch {
      return null;
    }
    i = skipWs(s, end);
    if (s[i] !== ":") break;
    i = skipWs(s, i + 1);
    keys.push(key);
    const vEnd = skipValue(s, i);
    if (vEnd < 0) break;
    values.set(key, s.slice(i, vEnd));
    i = skipWs(s, vEnd);
    if (s[i] === ",") i++;
    else {
      closed = i < s.length;
      break;
    }
  }
  return { keys, values, closed };
}

/** The kind of a JSON object by its top-level keys, as core tells them (feeds.md §4). */
function kindOfKeys(keys: string[]): "json-export" | "misp-export" | "misp-list" | "json" {
  if (keys[0] === "picket_feed_export") return "json-export";
  if (keys.includes("picket_feed")) return "misp-export";
  if (keys.includes("list")) return "misp-list";
  return "json";
}

/**
 * The top-level keys of a JSON object read as it streams, chunk by chunk (no string of the file
 * is built): what a file whose head didn't hold its whole top level declares past it. Only what
 * tells the kind is kept (the first key, and whether `picket_feed` and `list` appear), however
 * many keys the file has.
 */
export class TopLevelKeys {
  /** The first top-level key (undefined before it). */
  private first: string | undefined = undefined;
  private picketFeed = false;
  private list = false;
  private depth = 0;
  private inString = false;
  private escaped = false;
  private expectKey = false;
  /** The raw text of the top-level key being read; null when not reading one or past 256 chars. */
  private key: string | null = null;
  private keyLen = 0;

  push(chunk: string): void {
    for (let i = 0; i < chunk.length; i++) {
      const c = chunk[i];
      if (this.inString) {
        if (this.escaped) this.escaped = false;
        else if (c === "\\") this.escaped = true;
        else if (c === '"') {
          this.inString = false;
          if (this.key !== null) {
            try {
              this.take(JSON.parse(`"${this.key}"`) as string);
            } catch {
              // Not a key core would read either.
            }
          }
          this.key = null;
          continue;
        }
        if (this.key !== null) {
          // Keys this long are none core looks for: stop keeping their text.
          if (++this.keyLen > 256) this.key = null;
          else this.key += c;
        }
        continue;
      }
      if (c === '"') {
        this.inString = true;
        if (this.depth === 1 && this.expectKey) {
          this.key = "";
          this.keyLen = 0;
        }
        this.expectKey = false;
      } else if (c === "{" || c === "[") {
        this.depth++;
        this.expectKey = this.depth === 1 && c === "{";
      } else if (c === "}" || c === "]") this.depth--;
      else if (c === "," && this.depth === 1) this.expectKey = true;
    }
  }

  /** The keys `kindOfKeys` reads, at most three: the first, then `picket_feed` and `list` if they appear later. */
  get keys(): string[] {
    const out = this.first === undefined ? [] : [this.first];
    if (this.picketFeed) out.push("picket_feed");
    if (this.list) out.push("list");
    return out;
  }

  /** The kind of the object by its keys so far. */
  kind(): "json-export" | "misp-export" | "misp-list" | "json" {
    return kindOfKeys(this.keys);
  }

  private take(key: string): void {
    if (this.first === undefined) this.first = key;
    else if (key === "picket_feed") this.picketFeed = true;
    else if (key === "list") this.list = true;
  }
}

function parseObject(raw: string | undefined): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function settingsFrom(o: Record<string, unknown> | null): DeclaredSettings | null {
  if (!o) return null;
  const str = (v: unknown) => (typeof v === "string" ? v : undefined);
  return {
    id: str(o.id),
    name: str(o.name),
    provider: typeof o.provider === "string" ? o.provider : null,
    format: str(o.format),
    format_options: o.format_options,
    rule_policy: o.rule_policy,
    category: str(o.category),
    warn_on: o.warn_on,
    misp_type: str(o.misp_type),
  };
}

/** Rust's `char::is_whitespace` (Unicode White_Space), which core's `str::trim` uses (JS's differs: U+FEFF, U+0085). */
function isRustWs(c: string): boolean {
  const n = c.charCodeAt(0);
  return (n >= 0x09 && n <= 0x0d) || n === 0x20 || n === 0x85 || n === 0xa0 || n === 0x1680 || (n >= 0x2000 && n <= 0x200a) || n === 0x2028 || n === 0x2029 || n === 0x202f || n === 0x205f || n === 0x3000;
}

/** core reads a header from a file's first 64 lines (feeds/transfer.rs `read_header`). */
export const HEADER_LINES = 64;
/** A header key longer than this is none core reads; a longer value isn't kept (only shown settings miss it). */
const KEY_MAX = 64;
const VALUE_MAX = 64 * 1024;

/**
 * A line-format file export's header, read as core reads it (feeds/transfer.rs `read_header`)
 * from text arriving in chunks, so a file whose header runs past its head is still told right
 * (feeds.md §4): at most the first 64 lines, each read whole (core sets no line length) and
 * trimmed of Unicode whitespace; a line that isn't a comment (`!` or `#`), or says
 * `picket-first-seen`, ends it; `key: value` lines (split at the first `:`) name settings; an
 * export only when one says `picket-feed-export`. Only a key's first characters and a value of up
 * to 64 KiB are kept, so no string of a long line is built.
 */
export class HeaderReader {
  private lines = 0;
  private done = false;
  private isExport = false;
  private readonly out: Record<string, unknown> = {};
  /** Where in the current line: before its first character, after `!`/`#`, in the key, after `:`, in the value. */
  private at: "lead" | "keyLead" | "key" | "valueLead" | "value" = "lead";
  private any = false;
  /** The key and value so far (null past their bound), and whitespace not yet known to be inside them. */
  private key: string | null = "";
  private value: string | null = "";
  private ws = "";

  /** True once the header can't change: it ended, or 64 lines were read. */
  get finished(): boolean {
    return this.done;
  }

  push(chunk: string): void {
    for (let i = 0; i < chunk.length && !this.done; i++) {
      const c = chunk[i];
      if (c === "\n") this.endLine();
      else this.char(c);
    }
  }

  /** The end of the text: a last line without a line break counts as a line. */
  end(): void {
    if (!this.done && this.any) this.endLine();
    this.done = true;
  }

  /** The settings the header declares, or null when it isn't an export's. */
  result(): DeclaredSettings | null {
    return this.isExport ? settingsFrom(this.out) : null;
  }

  private char(c: string): void {
    this.any = true;
    const ws = isRustWs(c);
    switch (this.at) {
      case "lead":
        if (ws) return;
        if (c === "!" || c === "#") this.at = "keyLead";
        else this.done = true;
        return;
      case "keyLead":
        if (ws) return;
        this.at = "key";
        this.char(c);
        return;
      case "key":
        if (c === ":") {
          this.at = "valueLead";
          this.ws = "";
        } else this.key = this.grow(this.key, c, ws, KEY_MAX);
        return;
      case "valueLead":
        if (ws) return;
        this.at = "value";
        this.char(c);
        return;
      case "value":
        this.value = this.grow(this.value, c, ws, VALUE_MAX);
        return;
    }
  }

  /** Adds `c` to a trimmed key or value: inner whitespace is kept, trailing whitespace held back. */
  private grow(s: string | null, c: string, ws: boolean, max: number): string | null {
    if (s === null) return null;
    if (ws) {
      // Past the bound, any later character makes it too long anyway.
      if (this.ws.length <= max) this.ws += c;
      return s;
    }
    const next = s + this.ws + c;
    this.ws = "";
    return next.length > max ? null : next;
  }

  private endLine(): void {
    const { at, key, value } = this;
    // A blank line, or one that isn't a comment, ends the header.
    if (at === "lead") this.done = true;
    else if (at === "valueLead" || at === "value") this.entry(key, at === "value" ? value : "");
    this.lines++;
    if (this.lines >= HEADER_LINES) this.done = true;
    this.at = "lead";
    this.any = false;
    this.key = "";
    this.value = "";
    this.ws = "";
  }

  private entry(k: string | null, v: string | null): void {
    if (k === "picket-feed-export") this.isExport = true;
    else if (k === "picket-first-seen") this.done = true;
    else if (v === null) return;
    else if (k === "feed") this.out.id = v;
    else if (k === "name" || k === "provider" || k === "format" || k === "category") this.out[k] = v;
    else if (k === "format_options" || k === "rule_policy" || k === "warn_on") {
      try {
        this.out[k] = JSON.parse(v);
      } catch {
        // core skips a value it can't read too.
      }
    }
  }
}

/** A whole text's header (`HeaderReader`). */
export function readHeader(s: string): DeclaredSettings | null {
  const r = new HeaderReader();
  r.push(s);
  r.end();
  return r.result();
}

/** What an import's head says it is (feeds.md §4: an export of either form, or a plain list file). */
export function inspectImport(text: string, whole = true): ImportInfo {
  const head = textWithoutBom(text);
  const json = topLevelKeys(head);
  if (json) {
    const kind = kindOfKeys(json.keys);
    // A JSON export is one by its first key; any other object may hold more keys past the head.
    const partial = !whole && !json.closed && kind !== "json-export" ? true : undefined;
    if (kind === "json-export") return { kind, declared: settingsFrom(parseObject(json.values.get("feed"))) };
    if (kind === "misp-export") {
      const s = settingsFrom(parseObject(json.values.get("picket_feed")));
      return { kind, declared: { ...(s ?? {}), format: "misp-warninglist" }, partial };
    }
    if (kind === "misp-list") return { kind, declared: { format: "misp-warninglist" }, partial };
    return { kind, declared: null, partial };
  }
  // A line-format file: its header as far as the head goes; past it, the body build reads on.
  const r = new HeaderReader();
  r.push(head);
  if (whole) r.end();
  const header = r.result();
  const partial = r.finished ? undefined : true;
  return header ? { kind: "file-export", declared: header, partial } : { kind: "list", declared: null, partial };
}

/** True when the import brings its own feed settings (core ignores the admin's then). */
export function declaresSettings(kind: ImportKind): boolean {
  return kind === "json-export" || kind === "file-export" || kind === "misp-export";
}

export const KIND_LABEL: Record<ImportKind, string> = {
  "json-export": "a JSON export",
  "file-export": "a file export",
  "misp-export": "a MISP warninglist export",
  "misp-list": "a MISP warninglist",
  json: "JSON that isn't an export (read as a plain list)",
  list: "a plain list file",
};

/** A file's (or a slice's) text, decoded as UTF-8. */
export async function blobText(b: Blob): Promise<string> {
  return await b.text();
}

/** Reads the head of a chosen file once, to tell what it is. */
export async function inspectFile(file: Blob): Promise<ImportInfo> {
  return inspectImport(await blobText(file.slice(0, HEAD_BYTES)), file.size <= HEAD_BYTES);
}

/**
 * A Blob built from strings without holding them all: they are gathered up to `bound` UTF-16 units,
 * then made a Blob part of their own, so building a body holds one copy of it (the parts) and one
 * bounded batch of strings, never every escaped chunk at once.
 */
export class BlobParts {
  private readonly parts: Blob[] = [];
  private batch: string[] = [];
  private size = 0;

  constructor(private readonly bound = 1024 * 1024) {}

  /** The UTF-16 units waiting to become a part. */
  get pending(): number {
    return this.size;
  }

  push(s: string): void {
    this.batch.push(s);
    this.size += s.length;
    if (this.size >= this.bound) this.flush();
  }

  blob(type: string): Blob {
    this.flush();
    return new Blob(this.parts, { type });
  }

  private flush(): void {
    if (this.batch.length === 0) return;
    this.parts.push(new Blob(this.batch));
    this.batch = [];
    this.size = 0;
  }
}

/** Splits a text into slices of about `size` UTF-16 units, never between the halves of a surrogate pair. */
function* slices(text: string, size = 64 * 1024): Generator<string> {
  for (let i = 0; i < text.length; ) {
    let end = Math.min(i + size, text.length);
    const c = text.charCodeAt(end - 1);
    if (end < text.length && c >= 0xd800 && c <= 0xdbff) end++;
    yield text.slice(i, end);
    i = end;
  }
}

/**
 * `{"file": "…"}` holding a text that arrives in chunks (api.md §7): each chunk is JSON-escaped on
 * its own into bounded parts (`BlobParts`), so no string of the whole text, escaped or not, is
 * built. `onText` sees each chunk (to read a JSON file's top-level keys on the way).
 */
async function jsonFileBody(chunks: AsyncIterable<string> | Iterable<string>, onText?: (chunk: string) => void): Promise<Blob> {
  const parts = new BlobParts();
  parts.push('{"file":"');
  for await (const chunk of chunks) {
    if (!chunk) continue;
    onText?.(chunk);
    parts.push(JSON.stringify(chunk).slice(1, -1));
  }
  parts.push('"}');
  return parts.blob("application/json");
}

/** A file's text decoded as UTF-8 as it streams (a leading BOM dropped, as `Blob.text()` does). */
async function* decoded(file: Blob): AsyncGenerator<string> {
  if (typeof file.stream === "function" && typeof TextDecoderStream === "function") {
    const reader = file.stream().pipeThrough(new TextDecoderStream()).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield value;
    }
  }
  yield* slices(await blobText(file));
}

/** `{"file": "…"}` holding a file's text (api.md §7), built as the file streams (`jsonFileBody`). */
export async function fileJsonBody(file: Blob, onText?: (chunk: string) => void): Promise<Blob> {
  return jsonFileBody(decoded(file), onText);
}

const BOM = [0xef, 0xbb, 0xbf];

/**
 * A JSON document sent as it is (a JSON export, a config restore) without a leading UTF-8 BOM:
 * core reads the body as JSON and refuses one (`400 expected '{'`), while `Blob.text()`, which
 * told the dialog what the file is, drops it.
 */
export async function withoutBom(file: Blob): Promise<Blob> {
  return (await startsWithBom(file)) ? file.slice(3, file.size, file.type || "application/json") : file;
}

/** Pasted text without a leading BOM (U+FEFF), for the same reason. */
export function textWithoutBom(text: string): string {
  return text.startsWith("\uFEFF") ? text.slice(1) : text;
}

/** What Import… holds: a chosen file (read when sent) or pasted text, and what its head says. */
export interface ImportSourceValue {
  file: File | null;
  text: string;
  info: ImportInfo | null;
}

export const EMPTY_SOURCE: ImportSourceValue = { file: null, text: "", info: null };

/** Something to send: pasted text, or a chosen file once its head was read (`info`). */
export function hasSource(s: ImportSourceValue): boolean {
  return s.file !== null ? s.info !== null : s.text.length > 0;
}

/**
 * The import body (api.md §7), built once: a JSON export as it is (first key
 * `picket_feed_export`, no BOM), anything else as `{"file": "…"}` (a file export, a MISP list or
 * a plain list); and the kind it was sent as. When the head didn't settle the kind (`partial`), the
 * text is read on while the body is built (a JSON object's top-level keys, or a line-format
 * file's header as core reads it), so what past the head makes it an export decides the kind as
 * it does for core (feeds.md §4), and the import's query never sends a setting such a file
 * declares.
 */
export async function importBody(src: ImportSourceValue): Promise<{ body: Blob; kind: ImportKind }> {
  const info = src.info ?? inspectImport(src.text.slice(0, HEAD_BYTES), src.text.length <= HEAD_BYTES);
  const lineFormat = info.kind === "list" || info.kind === "file-export";
  const keys = info.partial && !lineFormat ? new TopLevelKeys() : null;
  const header = info.partial && lineFormat ? new HeaderReader() : null;
  const onText = keys ? (t: string) => keys.push(t) : header ? (t: string) => header.push(t) : undefined;
  const kindNow = (): ImportKind => {
    if (keys) return keys.kind();
    if (!header) return info.kind;
    header.end();
    return header.result() ? "file-export" : "list";
  };
  if (src.file) {
    if (info.kind === "json-export") return { body: await withoutBom(src.file), kind: info.kind };
    const body = await fileJsonBody(src.file, onText);
    return { body, kind: kindNow() };
  }
  const text = textWithoutBom(src.text);
  if (info.kind === "json-export") return { body: new Blob([text], { type: "application/json" }), kind: info.kind };
  const body = await jsonFileBody(slices(text), onText);
  return { body, kind: kindNow() };
}

async function startsWithBom(file: Blob): Promise<boolean> {
  const head = new Uint8Array(await file.slice(0, 3).arrayBuffer());
  return head.length === 3 && head.every((b, i) => b === BOM[i]);
}

/**
 * Why core would refuse an import for its size (`413`), told before the file is read (api.md §7):
 * a JSON export is sent as it is, and its body may be up to 32 times the download size cap; any
 * other file is sent as `{"file": "…"}`, and the file the import makes of that text must fit the
 * cap itself. A file's text is at least its bytes after a BOM (decoding never shrinks it). Null
 * when it may fit (core still checks what it makes).
 */
export async function importSizeProblem(src: ImportSourceValue, cap: DownloadCap): Promise<string | null> {
  const info = src.info ?? inspectImport(src.text.slice(0, HEAD_BYTES), src.text.length <= HEAD_BYTES);
  const asIs = info.kind === "json-export";
  const limit = asIs ? cap.bytes * BODY_FACTOR : cap.bytes;
  const size = src.file ? src.file.size - ((await startsWithBom(src.file)) ? BOM.length : 0) : utf8Length(textWithoutBom(src.text));
  if (size <= limit) return null;
  // Sizes that round alike are given in bytes too.
  const close = formatBytes(size) === formatBytes(limit);
  const show = (n: number) => (close ? `${formatBytes(n)} (${formatNumber(n)} bytes)` : formatBytes(n));
  const source = cap.fromSettings ? "feeds.max_download_mib" : "core's default for feeds.max_download_mib: the settings couldn't be read";
  return asIs
    ? `This export is ${show(size)}; core takes at most ${show(limit)}: 32 times the download size cap of ${formatBytes(cap.bytes)} (${source}).`
    : `This file is ${show(size)}; core takes at most ${show(limit)}: the file an import makes must fit the download size cap (${source}).`;
}
