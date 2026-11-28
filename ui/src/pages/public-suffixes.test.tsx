// A grouped public-suffix warning's page (#49, compiler/guard.rs `psl_summarise`): the counts,
// the preview and the suffixes added since it was last shown, and the full list behind it with
// each suffix's rules, a page at a time from `GET /bundles/{id}/public-suffixes` (a suffix's
// rules past the first few from `GET /bundles/{id}/public-suffixes/rules`).
import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, type Call } from "@/test/mock-api";
import { W5 } from "@/test/core-w5";
import { renderApp } from "@/test/render";

const T = { timeout: 8000 };

const SUFFIXES = Array.from({ length: 12 }, (_, i) => `s${String(i).padStart(2, "0")}.uk`);

describe("public_suffix warnings", () => {
  it("show the counts, the preview, what's new, and every suffix with its rules page by page", async () => {
    const base = W5["/alerts/{category_blocked}"] as { alert: Record<string, unknown> };
    const alert = {
      ...base.alert,
      id: 401,
      type: "operational",
      severity: "warning",
      kind: "bundle_warning",
      dedupe_key: "bundle_warning:b1:public_suffix:f1",
      title: "Bundle b1 blocks 12 public suffixes (feed f1)",
      edge: null,
      feed: "f1",
      bundle: "b1",
      details: {
        warning: "public_suffix",
        bundle: "b1",
        feed: "f1",
        suffixes: 12,
        rules: 13,
        preview: SUFFIXES.slice(0, 10),
        more: 2,
        added: ["s11.uk"],
        added_count: 1,
        suffix_digest: "0123456789abcdef",
      },
    };
    const item = (s: string) =>
      s === "s00.uk"
        ? { feed: "f1", suffix: s, rules: [{ rule: "||s00.uk^", line: 1 }, { rule: "||s00.uk^$important", line: 13 }], rule_count: 2, rules_cursor: null }
        : s === "s01.uk"
          ? { feed: "f1", suffix: s, rules: [{ rule: "||s01.uk^$ctag=t0", line: 20 }], rule_count: 4, rules_cursor: "r1" }
          : { feed: "f1", suffix: s, rules: [{ rule: `||${s}^`, line: 2 }], rule_count: 1, rules_cursor: null };
    const { calls } = mockApi([
      { method: "GET", path: "/alerts/401", body: { alert, history: [] } },
      {
        method: "GET",
        path: "/bundles/b1/public-suffixes",
        body: (c: Call) =>
          c.query.get("cursor") === "next"
            ? { total: 12, items: SUFFIXES.slice(10).map(item), next_cursor: null }
            : { total: 12, items: SUFFIXES.slice(0, 10).map(item), next_cursor: "next" },
      },
      {
        method: "GET",
        path: "/bundles/b1/public-suffixes/rules",
        body: (c: Call) =>
          c.query.get("cursor") === "r2"
            ? { items: [{ rule: "||s01.uk^$ctag=t3", line: 23 }], next_cursor: null }
            : { items: [{ rule: "||s01.uk^$ctag=t1", line: 21 }, { rule: "||s01.uk^$ctag=t2", line: 22 }], next_cursor: "r2" },
      },
    ]);
    renderApp("/alerts/401");
    const box = await screen.findByTestId("public-suffixes", undefined, T);
    expect(box).toHaveTextContent("12 public suffixes through 13 rules from feed f1.");
    expect(box).toHaveTextContent("and 2 more");
    expect(within(box).getByTestId("public-suffixes-added")).toHaveTextContent("New since it was last shown (1): s11.uk");
    // The full list is read only when asked for.
    expect(calls.some((c) => c.path.endsWith("/public-suffixes"))).toBe(false);
    await userEvent.click(within(box).getByRole("button", { name: "Show every suffix and its rules" }));
    expect(await within(box).findByText("10 of 12 shown.", undefined, T)).toBeInTheDocument();
    expect(within(box).getByText("||s00.uk^$important")).toBeInTheDocument();
    const first = calls.find((c) => c.path.endsWith("/public-suffixes"))!;
    expect(first.query.get("feed")).toBe("f1");
    // A suffix named by more rules than its page lists (issue 115): the rest only when asked for.
    expect(within(box).queryByRole("button", { name: /more rules?$/ })).not.toBeNull();
    expect(calls.some((c) => c.path.endsWith("/public-suffixes/rules"))).toBe(false);
    await userEvent.click(within(box).getByRole("button", { name: "Show 3 more rules" }));
    expect(await within(box).findByText("||s01.uk^$ctag=t2", undefined, T)).toBeInTheDocument();
    const rulesCall = calls.find((c) => c.path.endsWith("/public-suffixes/rules"))!;
    expect([rulesCall.query.get("feed"), rulesCall.query.get("suffix"), rulesCall.query.get("cursor")]).toEqual(["f1", "s01.uk", "r1"]);
    await userEvent.click(within(box).getByRole("button", { name: "Show 1 more rule" }));
    expect(await within(box).findByText("||s01.uk^$ctag=t3", undefined, T)).toBeInTheDocument();
    expect(within(box).queryByRole("button", { name: /more rules?$/ })).toBeNull();
    await userEvent.click(within(box).getByRole("button", { name: "Load more suffixes" }));
    expect(await within(box).findByText("12 of 12 shown.", undefined, T)).toBeInTheDocument();
    expect(within(box).queryByRole("button", { name: "Load more suffixes" })).toBeNull();
  });
});
