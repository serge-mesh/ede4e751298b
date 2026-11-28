import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { mockApi } from "@/test/mock-api";
import { renderApp } from "@/test/render";

// Every page, rendered against responses captured from a real picket-core (src/test/fixtures),
// with core's 404 for the endpoints a later wave adds.
const PAGES: [string, string | RegExp][] = [
  ["/", "Dashboard"],
  ["/query-log", "Query log"],
  ["/alerts", "Alerts"],
  ["/edges", "Edges"],
  ["/edges/e-cacc845b", /gw <img/],
  ["/listeners", "Listeners"],
  ["/clients", "Clients"],
  ["/clients/device/da:a1:19:00:00:01", /Device/],
  ["/profiles", "Profiles"],
  ["/profiles/new", "New profile"],
  ["/profiles/default", "Default"],
  ["/profiles/default/trial/block-common", /Trial of/],
  ["/upstreams", "Upstreams and forward zones"],
  ["/temporary-allows", "Temporary allows"],
  ["/feed-providers", "Feed providers"],
  ["/feed-providers/hagezi", "HaGeZi"],
  ["/feeds", "Feeds"],
  ["/feeds/manual-block", /manual-block|Manual block/i],
  ["/bundles", "Bundles"],
  ["/bundles/block-common", "block-common"],
  ["/warninglists", "Warninglists"],
  ["/lookup-providers", "Lookup providers"],
  ["/dnssec", "DNSSEC"],
  ["/system", "System"],
  ["/browser-extension", "Browser extension"],
  ["/settings", "Settings"],
  ["/feeds/manual-block?tab=overview", /manual-block|Manual block/i],
  ["/feeds/manual-block?tab=entries", /manual-block|Manual block/i],
  ["/feeds/manual-block?tab=runs", /manual-block|Manual block/i],
  ["/feeds/manual-block?tab=metrics", /manual-block|Manual block/i],
  ["/feeds/manual-block?tab=settings", /manual-block|Manual block/i],
  ["/edges/e-cacc845b?tab=system", /gw <img/],
  ["/edges/e-cacc845b?tab=settings", /gw <img/],
  ["/edges/e-cacc845b?tab=listeners", /gw <img/],
  ["/edges/e-cacc845b?tab=events", /gw <img/],
  ["/edges/e-cacc845b?tab=config", /gw <img/],
  ["/bundles/block-common?tab=feeds", "block-common"],
  ["/bundles/block-common?tab=shards", "block-common"],
  ["/bundles/block-common?tab=versions", "block-common"],
  ["/bundles/block-common?tab=warnings", "block-common"],
  ["/bundles/block-common?tab=explain", "block-common"],
  ["/bundles/block-common?tab=cold", "block-common"],
  ["/bundles/block-common?tab=settings", "block-common"],
  ["/feed-providers/hagezi?tab=files", "HaGeZi"],
  ["/feed-providers/hagezi?tab=feeds", "HaGeZi"],
  ["/feed-providers/hagezi?tab=checks", "HaGeZi"],
  ["/feed-providers/hagezi?tab=settings", "HaGeZi"],
  ["/feed-providers/hagezi?tab=backtest", "HaGeZi"],
  ["/settings?tab=password", "Settings"],
  ["/settings?tab=web", "Settings"],
  ["/settings?tab=retention", "Settings"],
  ["/settings?tab=resolver", "Settings"],
  ["/settings?tab=crosscheck", "Settings"],
  ["/settings?tab=dnssec", "Settings"],
  ["/settings?tab=feeds", "Settings"],
  ["/settings?tab=alerts", "Settings"],
  ["/settings?tab=edges", "Settings"],
  ["/settings?tab=secrets", "Settings"],
  ["/settings?tab=export", "Settings"],
  ["/settings?tab=changes", "Settings"],
  ["/upstreams?tab=groups", "Upstreams and forward zones"],
  ["/upstreams?tab=zones", "Upstreams and forward zones"],
];

describe("every page renders against a real core's responses", () => {
  it.each(PAGES)("%s", async (path, heading) => {
    mockApi();
    const { queryClient } = renderApp(path);
    expect(await screen.findByRole("heading", { level: 1, name: heading }, { timeout: 8000 })).toBeInTheDocument();
    await waitFor(() => expect(queryClient.isFetching()).toBe(0), { timeout: 8000 });
    expect(screen.queryByText(/Something went wrong/i)).toBeNull();
    // No unexpected failures: endpoints core lacks show "not available yet", not an error.
    expect(screen.queryAllByTestId("error-state").map((e) => e.textContent)).toEqual([]);
  });

  it("shows an unknown path as not found", async () => {
    mockApi();
    renderApp("/no/such/page");
    expect(await screen.findByText("Page not found", undefined, { timeout: 8000 })).toBeInTheDocument();
  });
});
