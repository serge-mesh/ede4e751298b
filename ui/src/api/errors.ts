import type { components } from "./schema";
import { isNotBuiltEndpoint, isNotBuiltSeries, unknownSeriesOf } from "./availability";

export type Issue = components["schemas"]["Issue"];

/** Every UI API failure, mapped from core's error shape `{error: {code, message, issues}}`. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly issues: Issue[];
  /** Seconds from `Retry-After`, when core sent one (429, 503). */
  readonly retryAfter: number | null;
  /** The UI API path the request went to (after /api/ui/v1), when known. */
  readonly path: string | undefined;

  constructor(status: number, code: string, message: string, issues: Issue[] = [], retryAfter: number | null = null, path?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.issues = issues;
    this.retryAfter = retryAfter;
    this.path = path;
  }

  /** Issues keyed by field path (`block_response.ipv4`), for inline form errors. */
  fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const i of this.issues) {
      if (i.field && i.severity === "error" && !out[i.field]) out[i.field] = i.message;
    }
    return out;
  }
}

/** Core's message for an API path it doesn't serve (a later wave builds it). */
export const NO_SUCH_ENDPOINT = "no such UI API endpoint";

/**
 * True when core doesn't serve this yet: its explicit `501`, or, for an endpoint or chart series
 * in the registry of ones core hasn't built (api/availability.ts), a `404` naming no such
 * endpoint or a `422 unknown series`. The same answer for anything else is an error (a typo in
 * the UI's own paths or series). Screens show "not available yet" and light up once core adds
 * the endpoint.
 */
export function isNotAvailable(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false;
  if (e.status === 501) return true;
  if (e.status === 404 && (e.message === NO_SUCH_ENDPOINT || e.code === "no_endpoint")) return isNotBuiltEndpoint(e.path);
  if (e.status === 422) {
    const series = unknownSeriesOf(e.message);
    return series !== null && isNotBuiltSeries(series);
  }
  return false;
}

const STATUS_TEXT: Record<number, string> = {
  0: "Core can't be reached. Check the network or whether picket-core is running.",
  401: "Sign-in needed: reload the page and enter the admin password.",
  403: "Core refused the request.",
  404: "Not found.",
  405: "Core doesn't take this request here.",
  408: "The request took too long to reach core; nothing was changed. Try again.",
  409: "Someone changed this in the meantime. Reload it and apply your change again.",
  413: "Too large: past core's size limit.",
  422: "Core refused the values.",
  429: "Too many requests or failed logins from this address; try again shortly.",
  500: "Core hit an internal error.",
  501: "Not available in this version of core yet.",
  503: "Core is busy or unavailable; try again.",
};

function parseRetryAfter(r: Response): number | null {
  const v = r.headers.get("retry-after");
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** The path after /api/ui/v1 of a request URL, if it is one. */
export function apiPath(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const p = new URL(url, "http://x").pathname;
    return p.startsWith("/api/ui/v1/") ? p.slice("/api/ui/v1".length) : undefined;
  } catch {
    return undefined;
  }
}

/** Maps a failed response (status and parsed body, if any) to an ApiError. */
export function toApiError(response: Response, body: unknown, path: string | undefined = apiPath(response.url)): ApiError {
  const status = response.status;
  const retry = parseRetryAfter(response);
  const err = (body as { error?: { code?: unknown; message?: unknown; issues?: unknown } } | null)?.error;
  if (err && typeof err === "object") {
    const code = typeof err.code === "string" ? err.code : "error";
    const message =
      typeof err.message === "string" && err.message ? err.message : (STATUS_TEXT[status] ?? `HTTP ${status}`);
    const issues = Array.isArray(err.issues) ? (err.issues as Issue[]) : [];
    return new ApiError(status, code, message, issues, retry, path);
  }
  return new ApiError(status, `http_${status}`, STATUS_TEXT[status] ?? `HTTP ${status}`, [], retry, path);
}

export function networkError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  if (e instanceof DOMException && e.name === "AbortError") {
    return new ApiError(0, "aborted", "The request was cancelled.");
  }
  return new ApiError(0, "network", STATUS_TEXT[0]);
}

/** A short user-facing message for any error. */
export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 422 && e.issues.length > 0) {
      return e.issues.map((i) => i.message).join("; ");
    }
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return "Something went wrong.";
}

/** True for a refusal that names its problems (`422` with issues, e.g. code `validation`). */
export function hasIssues(e: unknown): e is ApiError {
  return e instanceof ApiError && e.status === 422 && e.issues.length > 0;
}
