import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, mutations, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import fixtures from "@/test/fixtures/core.json";
import type { FeedDef } from "@/api/types";

const T = { timeout: 8000 };

const MANUAL = (fixtures as Record<string, unknown>)["/feeds/manual-block"] as FeedDef;
const PROVIDER: FeedDef = { ...MANUAL, id: "hagezi-tif", name: "HaGeZi TIF", provider: "hagezi", file: "adblock/tif.txt", system: false };

/** A feed core keeps: GETs answer the saved feed (alone and in the list), a PUT replaces it. */
function feedCore(start: FeedDef) {
  let saved = structuredClone(start);
  const others = ((fixtures as Record<string, unknown>)["/feeds"] as { items: FeedDef[] }).items.filter((f) => f.id !== start.id);
  const { calls } = mockApi([
    { method: "GET", path: `/feeds/${start.id}`, body: () => saved, pure: true },
    { method: "GET", path: "/feeds", body: () => ({ items: [...others, saved], next_cursor: null }), pure: true },
    {
      method: "PUT",
      path: `/feeds/${start.id}`,
      body: (c: Call) => {
        saved = c.body as FeedDef;
        return { id: start.id, warnings: [] };
      },
    },
  ]);
  return { calls, saved: () => saved };
}

const puts = (calls: Call[], id: string) => mutations(calls).filter((c) => c.method === "PUT" && c.path === `/feeds/${id}`);

async function openRename(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Rename" }, T));
  const name = (await screen.findByLabelText("Name", undefined, T)) as HTMLInputElement;
  await waitFor(() => expect(name).toHaveFocus(), T);
  return name;
}

describe("renaming a feed from its detail page (issue 96)", () => {
  it("opens Settings with Name focused and selected, above the rule policy, with what a rename keeps", async () => {
    const user = userEvent.setup();
    feedCore(MANUAL);
    renderApp("/feeds/manual-block");
    const name = await openRename(user);
    expect(screen.getByRole("tab", { name: "Settings" })).toHaveAttribute("aria-selected", "true");
    expect(name.value).toBe("Manual block");
    expect([name.selectionStart, name.selectionEnd]).toEqual([0, "Manual block".length]);
    // Name comes before the rule policy switches.
    const policy = screen.getByRole("group", { name: "Rule policy" });
    expect(name.compareDocumentPosition(policy) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText("Changing the display name keeps the feed ID, source and bundle memberships.")).toBeInTheDocument();
  });

  it("focuses Name once: coming back to Settings later leaves the focus alone", async () => {
    const user = userEvent.setup();
    feedCore(MANUAL);
    renderApp("/feeds/manual-block");
    await openRename(user);
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await user.click(screen.getByRole("tab", { name: "Settings" }));
    const name = await screen.findByLabelText("Name", undefined, T);
    expect(name).not.toHaveFocus();
    // Rename again, from Settings itself.
    await user.click(screen.getByRole("button", { name: "Rename" }));
    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveFocus(), T);
  });

  it("saves a manual feed's new name alone, without the entry-replacement warning, and shows it in the heading and the feeds list", async () => {
    const user = userEvent.setup();
    const { calls } = feedCore(MANUAL);
    const { router } = renderApp("/feeds/manual-block");
    const name = await openRename(user);
    await user.keyboard("Blocked by hand");
    expect(screen.queryByText("Saving replaces the feed's entries")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(puts(calls, "manual-block")).toHaveLength(1), T);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const body = puts(calls, "manual-block")[0].body as FeedDef;
    expect(body).toEqual({ ...MANUAL, name: "Blocked by hand" });
    expect(await screen.findByRole("heading", { name: "Blocked by hand" }, T)).toBeInTheDocument();
    expect(name.value).toBe("Blocked by hand");
    expect(router.state.location.pathname).toBe("/feeds/manual-block");
    // The feeds list shows the new name under the same id.
    await router.navigate({ to: "/feeds" });
    const row = (await screen.findByText("Blocked by hand", undefined, T)).closest("tr")!;
    expect(within(row).getAllByRole("link").some((a) => a.getAttribute("href") === "/feeds/manual-block")).toBe(true);
  });

  it("renames a provider feed, keeping its provider, file and the rest of its settings", async () => {
    const user = userEvent.setup();
    const { calls } = feedCore(PROVIDER);
    const { router } = renderApp("/feeds/hagezi-tif?tab=settings");
    await openRename(user);
    await user.keyboard("Threat intel");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(puts(calls, "hagezi-tif")).toHaveLength(1), T);
    expect(puts(calls, "hagezi-tif")[0].body).toEqual({ ...PROVIDER, name: "Threat intel" });
    expect(await screen.findByRole("heading", { name: "Threat intel" }, T)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/feeds/hagezi-tif");
  });

  it("sends nothing when the new name is discarded", async () => {
    const user = userEvent.setup();
    const { calls } = feedCore(MANUAL);
    renderApp("/feeds/manual-block");
    await openRename(user);
    await user.keyboard("Something else");
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(screen.getByLabelText("Name")).toHaveValue("Manual block");
    expect(puts(calls, "manual-block")).toHaveLength(0);
    expect(screen.getByRole("heading", { name: "Manual block" })).toBeInTheDocument();
  });
});
