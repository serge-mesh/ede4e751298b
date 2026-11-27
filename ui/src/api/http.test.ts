import { describe, expect, it } from "vitest";
import { mockApi } from "@/test/mock-api";
import { client, request, unwrap } from "./http";
import { ApiError, errorMessage, isNotAvailable } from "./errors";
import { registerNotBuilt } from "@/test/registry";

describe("UI API client protections (core.md §12)", () => {
  it("sends X-Picket-UI: 1 and a JSON content type on every mutating request of the typed client", async () => {
    const { calls } = mockApi([{ method: "POST", path: "/profiles", status: 201, body: { id: "kids", warnings: [] } }]);
    await unwrap(client.POST("/api/ui/v1/profiles", { body: { id: "kids", name: "Kids" } }));
    const c = calls.at(-1)!;
    expect(c.method).toBe("POST");
    expect(c.headers.get("x-picket-ui")).toBe("1");
    expect(c.headers.get("content-type")).toMatch(/^application\/json/);
    expect(c.body).toEqual({ id: "kids", name: "Kids" });
  });

  it("gives a bodiless POST a JSON body, so core's JSON check passes", async () => {
    const { calls } = mockApi([{ method: "POST", path: "/feed-providers/hagezi/check", status: 202, body: { result: "started" } }]);
    await unwrap(client.POST("/api/ui/v1/feed-providers/{id}/check", { params: { path: { id: "hagezi" } } }));
    const c = calls.at(-1)!;
    expect(c.headers.get("x-picket-ui")).toBe("1");
    expect(c.headers.get("content-type")).toMatch(/^application\/json/);
    expect(c.body).toEqual({});
  });

  it("marks DELETE (with or without a body) and PUT through the plain request helper too", async () => {
    const { calls } = mockApi([
      { method: "DELETE", path: "/alerts", body: { deleted: 2 } },
      { method: "DELETE", path: "/profiles/kids", body: { id: "kids", warnings: [] } },
      { method: "PUT", path: "/settings", body: {} },
    ]);
    await request("DELETE", "/alerts", { body: { ids: [1, 2] } });
    await unwrap(client.DELETE("/api/ui/v1/profiles/{id}", { params: { path: { id: "kids" } } }));
    await request("PUT", "/settings", { body: { default_profile: null } });
    for (const c of calls) {
      expect(c.headers.get("x-picket-ui")).toBe("1");
      expect(c.headers.get("content-type")).toMatch(/^application\/json/);
    }
    expect(calls[0].body).toEqual({ ids: [1, 2] });
    expect(calls[2].body).toEqual({ default_profile: null });
  });

  it("doesn't add the mutation header to reads", async () => {
    const { calls } = mockApi();
    await unwrap(client.GET("/api/ui/v1/identity"));
    expect(calls[0].headers.get("x-picket-ui")).toBeNull();
  });

  it("encodes path parameters as parameters of the API's own routes", async () => {
    const { calls } = mockApi([{ method: "GET", path: /^\/feeds\//, body: {} }]);
    await request("GET", `/feeds/${encodeURIComponent("a/../b?x")}/status`);
    expect(calls[0].path).toBe("/feeds/a%2F..%2Fb%3Fx/status");
  });
});

describe("error mapping", () => {
  it("maps core's error shape to an ApiError with code, message and field issues", async () => {
    const issues = [
      { severity: "error", entity: "profile", id: "Bad", field: "id", code: "bad_profile_id", message: "not a profile id" },
      { severity: "warning", entity: "profile", id: "Bad", field: null, code: "w", message: "a warning" },
    ];
    mockApi([{ method: "POST", path: "/profiles", status: 422, body: { error: { code: "validation", message: "refused", issues } } }]);
    const e = await unwrap(client.POST("/api/ui/v1/profiles", { body: { id: "Bad" } })).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(422);
    expect(e.code).toBe("validation");
    expect(e.message).toBe("refused");
    expect(e.fieldErrors()).toEqual({ id: "not a profile id" });
    expect(errorMessage(e)).toBe("not a profile id; a warning");
  });

  it("maps a non-JSON error (e.g. a proxy page) to a status message, never its body", async () => {
    mockApi([{ method: "GET", path: "/identity", status: 502, body: "<html><script>alert(1)</script></html>" }]);
    const e = (await request("GET", "/identity").catch((x) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(502);
    expect(e.message).not.toContain("<");
  });

  it("maps 401 and 429 (with Retry-After) to sign-in and back-off messages", async () => {
    mockApi([
      { method: "GET", path: "/identity", status: 401, body: "authentication required\n" },
      { method: "GET", path: "/settings", status: 429, body: "too many failed logins\n", headers: { "retry-after": "60" } },
    ]);
    const a = (await request("GET", "/identity").catch((x) => x)) as ApiError;
    expect(a.status).toBe(401);
    expect(a.message).toMatch(/reload the page/i);
    const b = (await request("GET", "/settings").catch((x) => x)) as ApiError;
    expect(b.status).toBe(429);
    expect(b.retryAfter).toBe(60);
  });

  it("maps a network failure to status 0", async () => {
    const { fetchMock } = mockApi();
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const e = await unwrap(client.GET("/api/ui/v1/identity")).catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(0);
  });

  it("tells endpoints core doesn't serve yet from real 404s", async () => {
    registerNotBuilt({ endpoints: ["/future-endpoint"], series: ["future_series"] });
    mockApi([
      { method: "GET", path: "/config/export", status: 501, body: { error: { code: "not_implemented", message: "not implemented yet: config export" } } },
      { method: "GET", path: "/profiles/nope", status: 404, body: { error: { code: "not_found", message: 'no profile "nope"' } } },
      { method: "GET", path: "/metrics", status: 422, body: { error: { code: "invalid", message: 'unknown series "future_series"' } } },
      { method: "GET", path: "/logs", status: 404, body: { error: { code: "not_found", message: "no such UI API endpoint" } } },
    ]);
    const notBuilt = await request("GET", "/future-endpoint").catch((x) => x);
    // Core 826b4d6 serves logs: its 404 is a real error now, never "not available yet".
    const served = await request("GET", "/logs").catch((x) => x);
    const notImpl = await request("GET", "/config/export").catch((x) => x);
    const missing = await request("GET", "/profiles/nope").catch((x) => x);
    const series = await request("GET", "/metrics", { query: { series: "future_series" } }).catch((x) => x);
    expect(isNotAvailable(notBuilt)).toBe(true);
    expect(isNotAvailable(notImpl)).toBe(true);
    expect(isNotAvailable(series)).toBe(true);
    expect(isNotAvailable(missing)).toBe(false);
    expect(isNotAvailable(served)).toBe(false);
  });
});
