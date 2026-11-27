// Review of the UI polish at e9a51c1 (dev/briefs/r08/codex.md X5): text a form's controls hold
// that isn't in its value yet (unparsed JSON, a tag or map key typed but not added) is a draft too:
// it keeps its tab mounted, its sheet asks before dropping it, its form offers Discard changes, and
// a change saved elsewhere asks instead of replacing it.
import * as React from "react";
import { describe, expect, it } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi } from "@/test/mock-api";
import { W5 } from "@/test/core-w5";
import { renderApp } from "@/test/render";
import { SchemaForm } from "@/components/schema-form/schema-form";
import { DraftScope, useDiscardGuard } from "@/components/common/drafts";
import { TooltipProvider } from "@/components/ui/tooltip";

const T = { timeout: 8000 };
type Rec = Record<string, unknown>;

describe("X5: control text not yet in the form's value counts as a draft (Codex r08 X5)", () => {
  const PROVIDER = W5["/lookup-providers/q9"] as Rec;
  const PRETTY = JSON.stringify(PROVIDER.config, null, 2);
  const BAD = '{"qtype": "A",';
  /** A lookup provider whose module core doesn't list: its config is edited as JSON text. */
  function provider() {
    let current: Rec = PROVIDER;
    mockApi([
      { method: "GET", path: "/lookup-providers", body: () => ({ items: [current], next_cursor: null }) },
      { method: "GET", path: "/lookup-providers/q9", body: () => current },
      { method: "GET", path: "/lookup-modules", body: [] },
    ]);
    return { set: (p: Rec) => (current = p) };
  }
  const json = () => document.getElementById("lcfg-json-root") as HTMLTextAreaElement | null;

  it("an entity form's unparsed JSON keeps its tab mounted and counts as its changes: Discard changes drops it", async () => {
    const user = userEvent.setup();
    provider();
    renderApp("/lookup-providers/q9?tab=settings");
    await waitFor(() => expect(json()).not.toBeNull(), T);
    expect(json()).toHaveValue(PRETTY);
    fireEvent.change(json()!, { target: { value: BAD } });
    expect(screen.getByText(/^Not valid JSON/)).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Status" })).toHaveAttribute("aria-selected", "true"), T);
    // Kept, out of sight.
    expect(json()).not.toBeNull();
    expect(json()).not.toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Settings" }));
    expect(json()).toBeVisible();
    expect(json()).toHaveValue(BAD);
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(json()).toHaveValue(PRETTY);
    expect(screen.queryByText(/^Not valid JSON/)).toBeNull();
    // Clean again: the tab isn't kept.
    await user.click(screen.getByRole("tab", { name: "Status" }));
    await waitFor(() => expect(json()).toBeNull(), T);
  });

  it("a change saved elsewhere doesn't replace unparsed JSON: the form asks, Keep my changes keeps the text, Reload drops it", async () => {
    const user = userEvent.setup();
    const core = provider();
    const { queryClient } = renderApp("/lookup-providers/q9?tab=settings");
    await waitFor(() => expect(json()).not.toBeNull(), T);
    fireEvent.change(json()!, { target: { value: BAD } });
    core.set({ ...PROVIDER, sync_timeout_ms: 200 });
    await act(() => queryClient.invalidateQueries());
    const alert = await screen.findByText("This lookup provider changed elsewhere", undefined, T);
    expect(json()).toHaveValue(BAD);
    await user.click(within(alert.closest("[role=alert]") as HTMLElement).getByRole("button", { name: "Keep my changes" }));
    expect(json()).toHaveValue(BAD);
    expect(screen.getByLabelText("Sync timeout ms")).toHaveValue("200");
    core.set({ ...PROVIDER, sync_timeout_ms: 300 });
    await act(() => queryClient.invalidateQueries());
    const again = await screen.findByText("This lookup provider changed elsewhere", undefined, T);
    await user.click(within(again.closest("[role=alert]") as HTMLElement).getByRole("button", { name: "Reload" }));
    expect(json()).toHaveValue(PRETTY);
    expect(screen.getByLabelText("Sync timeout ms")).toHaveValue("300");
  });

  it("an entity sheet asks before Escape drops a tag typed but not added", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/clients");
    await user.click(await screen.findByRole("button", { name: /New client/ }, T));
    const form = await screen.findByRole("form", { name: "New client" }, T);
    await user.type(within(form).getByLabelText("Tags"), "kids");
    await user.keyboard("{Escape}");
    await user.click(within(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).getByRole("button", { name: "Keep editing" }));
    // The question took the focus, so leaving the input added the tag.
    expect(within(screen.getByRole("form", { name: "New client" })).getByRole("button", { name: "Remove kids" })).toBeInTheDocument();
  });

  it("an upstream's port with text that isn't a number asks too (the text is the form's value)", async () => {
    const user = userEvent.setup();
    const { fixtures } = mockApi();
    const upstream = (fixtures["/upstreams"] as { items: { id: string }[] }).items.find((u) => u.id === "cf-doh");
    mockApi([{ method: "GET", path: "/upstreams/cf-doh", body: () => upstream }]);
    renderApp("/upstreams");
    await user.click(await screen.findByRole("button", { name: "Edit cf-doh" }, T));
    const port = within(await screen.findByRole("form", { name: "Edit upstream" }, T)).getByLabelText("Port");
    await user.clear(port);
    await user.type(port, "44x");
    await user.keyboard("{Escape}");
    expect(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).toBeInTheDocument();
  });

  it("Settings → Alerts keeps a threshold key typed but not added while another tab shows; Discard changes drops it", async () => {
    const user = userEvent.setup();
    mockApi();
    renderApp("/settings?tab=alerts");
    const key = await screen.findByLabelText("New key", undefined, T);
    await user.type(key, "lookup_down");
    await user.click(screen.getByRole("tab", { name: "Retention" }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Retention" })).toHaveAttribute("aria-selected", "true"), T);
    await user.click(screen.getByRole("tab", { name: "Alerts" }));
    expect(screen.getByLabelText("New key")).toHaveValue("lookup_down");
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(screen.getByLabelText("New key")).toHaveValue("");
  });

  /** A sheet's discard guard around a schema form (components/common/drafts.tsx). */
  function Sheet() {
    const [open, setOpen] = React.useState(true);
    const guard = useDiscardGuard(() => setOpen(false));
    const [value, setValue] = React.useState<unknown>({ extra: { a: 1 }, labels: {} });
    if (!open) return <p>Closed</p>;
    return (
      <TooltipProvider>
        <DraftScope onDirty={guard.onDirty}>
          <SchemaForm
            schema={{ type: "object", properties: { extra: { description: "Free-form JSON." }, labels: { type: "object", additionalProperties: { type: "string" } } } }}
            value={value}
            onChange={setValue}
            idPrefix="sheet"
          />
        </DraftScope>
        <button type="button" onClick={guard.requestClose}>
          Close
        </button>
        {guard.dialog}
      </TooltipProvider>
    );
  }

  const extra = () => document.getElementById("sheet-extra") as HTMLTextAreaElement;

  it("a sheet asks before dropping unparsed JSON or a map key typed but not added; closes at once when clean", async () => {
    const user = userEvent.setup();
    const { unmount } = render(<Sheet />);
    fireEvent.change(extra(), { target: { value: '{"a": 2,' } });
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(within(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).getByRole("button", { name: "Keep editing" }));
    expect(extra()).toHaveValue('{"a": 2,');
    unmount();
    render(<Sheet />);
    await user.type(screen.getByLabelText("New key"), "site");
    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(within(await screen.findByRole("alertdialog", { name: "Discard your changes?" }, T)).getByRole("button", { name: "Keep editing" }));
    await user.clear(screen.getByLabelText("New key"));
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(await screen.findByText("Closed")).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });
});
