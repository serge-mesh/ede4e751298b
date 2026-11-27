import { vi } from "vitest";
import fixtures from "./fixtures/core.json";
import { answerViolations, contractViolations, refusalViolations } from "./contract";
import { w5Get } from "./core-w5";

/**
 * Requests a mock answered with success although core would refuse them (test/contract.ts). The
 * test setup fails a test that leaves any here; a route that answers 4xx, or says it `refuses`,
 * models core's refusal itself and isn't checked.
 */
const violations: string[] = [];

export function takeViolations(): string[] {
  return violations.splice(0);
}

/** Notes what core wouldn't send or answer (e.g. a UI event frame a test emits: test/setup.ts). */
export function noteViolations(found: string[]) {
  violations.push(...found);
}

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export interface Route {
  method?: string;
  /** Path after /api/ui/v1, e.g. `/profiles` or a RegExp. */
  path: string | RegExp;
  status?: number;
  /** The answer, or a function of the call giving it (or a promise of it, to hold the response back). */
  body?: unknown | ((call: Call) => unknown);
  headers?: Record<string, string>;
  /** The route answers core's refusals itself (`reply(4xx, …)` for what core refuses): the contract check is left to it. */
  refuses?: boolean;
  /**
   * A GET route whose body function only reads the test's state (no side effects): the contract
   * may call it for core's state (e.g. the settings' LAN CA, which a stateful mock changes).
   */
  pure?: boolean;
}

const PREFIX = "/api/ui/v1";

const REPLY = Symbol("reply");

/** A route body function's answer with its own status (e.g. a 409 from a stateful mock of core). */
export function reply(status: number, body: unknown): unknown {
  return { [REPLY]: true, status, body };
}

function isReply(v: unknown): v is { status: number; body: unknown } {
  return !!v && typeof v === "object" && REPLY in v;
}
const NO_ENDPOINT = { error: { code: "not_found", message: "no such UI API endpoint" } };

/**
 * Replaces fetch with a router over `routes`, then the fixtures captured from a real core
 * (GET only; core.json, then the wave-5 captures in core-w5.ts), then `{step_s, series: []}` for
 * metrics, then core's 404 for unknown endpoints.
 */
export function mockApi(routes: Route[] = []) {
  const calls: Call[] = [];
  const fx = fixtures as Record<string, unknown>;
  /**
   * What a GET of `p` answers here without side effects: a static mock route's body or a `pure`
   * route's answer now, else the fixture (test/contract.ts rules that need core's state).
   */
  const lookup = (p: string): unknown => {
    for (const r of routes) {
      if ((r.method ?? "GET") !== "GET" || (typeof r.path === "string" ? r.path !== p : !r.path.test(p))) continue;
      if (typeof r.body !== "function") return r.body;
      if (!r.pure) return undefined;
      const b = (r.body as (c: Call) => unknown)({ method: "GET", path: p, query: new URLSearchParams(), headers: new Headers(), body: undefined });
      return b instanceof Promise || isReply(b) ? undefined : b;
    }
    return fx[p];
  };
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const url = new URL(req.url, window.location.origin);
    const path = url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) || "/" : url.pathname;
    let body: unknown = undefined;
    const text = req.method === "GET" || req.method === "HEAD" ? "" : await req.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }
    const call: Call = { method: req.method, path, query: url.searchParams, headers: req.headers, body };
    calls.push(call);
    const refused = url.pathname.startsWith(PREFIX) ? contractViolations(req.method, path, url.searchParams, body, lookup) : [];
    const respond = (status: number, b: unknown, headers: Record<string, string> = {}) =>
      new Response(status === 204 ? null : typeof b === "string" ? b : JSON.stringify(b), {
        status,
        headers: { "content-type": typeof b === "string" ? "text/plain" : "application/json", ...headers },
      });
    for (const r of routes) {
      if (r.method && r.method !== req.method) continue;
      if (typeof r.path === "string" ? r.path !== path : !r.path.test(path)) continue;
      if ((r.status ?? 200) < 400 && !r.refuses && refused.length) {
        violations.push(...refused);
        return respond(422, { error: { code: "invalid", message: `mock: core would refuse this: ${refused.join("; ")}` } });
      }
      // A body function may answer later (a promise): a response held back while the test acts.
      const b = typeof r.body === "function" ? await (r.body as (c: Call) => unknown)(call) : r.body;
      const [status, answer] = isReply(b) ? [b.status, b.body ?? {}] : [r.status ?? 200, b ?? {}];
      // An error core can't give on an endpoint whose refusals the UI tells apart, or not for this
      // request (test/contract.ts), and an answer the UI reads a new field of in another shape.
      if (url.pathname.startsWith(PREFIX)) violations.push(...refusalViolations(req.method, path, status, answer, refused), ...answerViolations(req.method, path, status, answer));
      return respond(status, answer, r.headers);
    }
    if (refused.length) {
      violations.push(...refused);
      return respond(422, { error: { code: "invalid", message: `mock: core would refuse this: ${refused.join("; ")}` } });
    }
    if (req.method === "GET" && path in fx) return respond(200, fx[path]);
    const w5 = req.method === "GET" ? w5Get(path, url.searchParams) : undefined;
    if (w5 !== undefined) return respond(200, w5);
    if (req.method === "GET" && path === "/metrics") return respond(200, { step_s: 300, series: [] });
    return respond(404, NO_ENDPOINT);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock, fixtures: fx };
}

export function mutations(calls: Call[]) {
  return calls.filter((c) => c.method !== "GET");
}
