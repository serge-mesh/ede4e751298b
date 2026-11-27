import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema";
import { ApiError, networkError, toApiError } from "./errors";

export const API_BASE = "/api/ui/v1";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isMutating(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

/**
 * The protections every mutating request needs (core.md §12): `X-Picket-UI: 1` and a JSON body
 * (`Content-Type: application/json`), which forces a CORS preflight that core never approves.
 * POST and PUT always carry a body (`{}` when the call has none); basic auth is the browser's.
 */
export function protectRequest(request: Request): Request {
  request.headers.set("Accept", "application/json");
  if (!isMutating(request.method)) return request;
  if (request.method !== "DELETE" && request.body === null) {
    const headers = new Headers(request.headers);
    headers.set("X-Picket-UI", "1");
    headers.set("Content-Type", "application/json");
    return new Request(request.url, {
      method: request.method,
      headers,
      body: "{}",
      signal: request.signal,
      credentials: "same-origin",
    });
  }
  request.headers.set("X-Picket-UI", "1");
  request.headers.set("Content-Type", "application/json");
  return request;
}

const protectionMiddleware: Middleware = {
  onRequest({ request }) {
    return protectRequest(request);
  },
};

/** The typed client generated from core's OpenAPI document (api.md §7). */
export const client = createClient<paths>({
  baseUrl: "",
  credentials: "same-origin",
  // Resolve fetch at call time (tests stub it).
  fetch: (req: Request) => globalThis.fetch(req),
});
client.use(protectionMiddleware);

/**
 * Awaits an openapi-fetch call and returns its data, or throws an ApiError built from core's
 * error shape (or a network error).
 */
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  let res: { data?: T; error?: unknown; response: Response };
  try {
    res = await call;
  } catch (e) {
    throw networkError(e);
  }
  if (!res.response.ok) throw toApiError(res.response, res.error ?? null);
  return res.data as T;
}

export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  query?: Record<string, QueryValue | QueryValue[]>;
  /** A JSON value, or a Blob that already holds the JSON text (a large body built once, api.md §7). */
  body?: unknown;
  signal?: AbortSignal;
  /** Return the raw Response (downloads); errors are still thrown. */
  raw?: boolean;
  headers?: Record<string, string>;
}

/** A request URL: `undefined` and `null` leave a parameter out; `""` sends it empty (e.g. `warn_on=`: none). */
export function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    const values = Array.isArray(v) ? v : [v];
    for (const x of values) {
      if (x === undefined || x === null) continue;
      qs.append(k, String(x));
    }
  }
  const s = qs.toString();
  return `${API_BASE}${path}${s ? `?${s}` : ""}`;
}

async function readBody(r: Response): Promise<unknown> {
  const type = r.headers.get("content-type") ?? "";
  if (r.status === 204) return undefined;
  if (type.includes("json")) {
    try {
      return await r.json();
    } catch {
      return null;
    }
  }
  return await r.text();
}

/**
 * A plain request for paths the generated client doesn't know yet (endpoints a later core
 * wave adds), downloads, and anything needing the raw response. Same protections and errors.
 */
export async function request<T = unknown>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    signal: opts.signal,
    headers: { ...opts.headers },
  };
  if (opts.body instanceof Blob) init.body = opts.body;
  else if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  let req = new Request(buildUrl(path, opts.query), init);
  req = protectRequest(req);
  let r: Response;
  try {
    r = await globalThis.fetch(req);
  } catch (e) {
    throw networkError(e);
  }
  if (!r.ok) {
    const body = await readBody(r).catch(() => null);
    throw toApiError(r, body, path.split("?")[0]);
  }
  if (opts.raw) return r as unknown as T;
  return (await readBody(r)) as T;
}

export interface DownloadOptions {
  /** Cancels the download: the request, or the body while it arrives (which closes the connection). */
  signal?: AbortSignal;
  /** What has arrived of the body, and its Content-Length when the response gives one. */
  onProgress?: (received: number, total: number | null) => void;
}

/** Downloads a response as a file, named from Content-Disposition when core gives one. */
export async function download(path: string, query?: RequestOptions["query"], fallbackName = "download", opts: DownloadOptions = {}) {
  const r = await request<Response>("GET", path, { query, raw: true, signal: opts.signal });
  const blob = await readBlob(r, opts);
  const cd = r.headers.get("content-disposition") ?? "";
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
  const name = m ? decodeURIComponent(m[1]) : fallbackName;
  saveBlob(blob, name);
}

/** Arrived body bytes gathered into one Blob part at a time (kept by the browser, off the script's heap). */
const GATHER_BYTES = 8 * 1024 * 1024;
/** Progress is reported at most once per this many bytes, and at the end. */
const PROGRESS_BYTES = 1024 * 1024;

const cancelled = () => new DOMException("The download was cancelled.", "AbortError");

/**
 * A response body as one Blob, read as it arrives so the page can show progress and stop it: a
 * cancel (`signal`) cancels the body, which closes the connection, so core ends its side (a
 * config export frees core's one export slot when its stream ends, config/export.rs).
 */
async function readBlob(r: Response, { signal, onProgress }: DownloadOptions): Promise<Blob> {
  const type = r.headers.get("content-type") ?? "";
  if (!r.body) return r.blob();
  const length = Number(r.headers.get("content-length") ?? "");
  const total = r.headers.has("content-length") && Number.isSafeInteger(length) && length >= 0 ? length : null;
  const reader = r.body.getReader();
  const stop = () => void reader.cancel().catch(() => undefined);
  if (signal?.aborted) stop();
  signal?.addEventListener("abort", stop);
  const parts: Blob[] = [];
  let pending: Uint8Array<ArrayBuffer>[] = [];
  let pendingBytes = 0;
  let received = 0;
  let reported = 0;
  onProgress?.(0, total);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      // A cancelled body ends as if done: what arrived is incomplete.
      if (signal?.aborted) throw cancelled();
      if (done) break;
      pending.push(value);
      pendingBytes += value.byteLength;
      received += value.byteLength;
      if (pendingBytes >= GATHER_BYTES) {
        parts.push(new Blob(pending));
        pending = [];
        pendingBytes = 0;
      }
      if (received - reported >= PROGRESS_BYTES) {
        reported = received;
        onProgress?.(received, total);
      }
    }
  } finally {
    signal?.removeEventListener("abort", stop);
  }
  if (pending.length) parts.push(new Blob(pending));
  onProgress?.(received, total);
  return new Blob(parts, { type });
}

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  // Only the file name part, so a name with slashes can't point anywhere else.
  a.download = name.split(/[\\/]/).pop() || "download";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export { ApiError };
