// Issue 76: a GitHub preset's feeds exist only once its provider has listed the repository, so
// an install can return before they join the bundle. The preset dialog shows a pending install
// (waiting, or why its feeds won't join) instead of "installed", and the install's toast says
// it is waiting instead of reporting an empty feed list as done.
import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { toast } from "sonner";
import { mockApi } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import { presetPendingText } from "@/pages/feed-providers";

const T = { timeout: 8000 };

type Rec = Record<string, unknown>;

const waiting = { bundle: "block-common", files: ["adblock/tif.txt", "adblock/ultimate.txt"], state: "waiting" as const };

describe("preset installs waiting for their feeds", () => {
  it("says what a pending install waits for, or why its feeds won't join", () => {
    expect(presetPendingText(waiting)).toBe("Waiting for the provider to list adblock/tif.txt, adblock/ultimate.txt: each feed joins block-common when it appears.");
    expect(presetPendingText({ ...waiting, files: ["abp_big.txt"], state: "source_changed" })).toMatch(/^The provider now reads another source, so abp_big\.txt won't be added to block-common\./);
    expect(presetPendingText({ ...waiting, state: "bundle_missing" })).toMatch(/^The bundle block-common no longer exists/);
    expect(presetPendingText({ ...waiting, state: "refused", detail: "too many feeds" })).toBe("block-common refused the feeds: too many feeds. Fix the bundle and install the preset again.");
  });

  it("shows the pending state in the dialog and a waiting toast for an install that isn't done", async () => {
    const user = userEvent.setup();
    const info = vi.spyOn(toast, "info");
    const success = vi.spyOn(toast, "success");
    const { fixtures } = mockApi([
      {
        method: "GET",
        path: "/feed-presets",
        body: () =>
          (fixtures["/feed-presets"] as Rec[]).map((p) =>
            p.id === "hagezi" ? { ...p, installed: true, pending: waiting } : p.id === "oisd-big" ? { ...p, installed: false, pending: { bundle: "block-common", files: ["abp_big.txt"], state: "source_changed" } } : p,
          ),
      },
      {
        method: "POST",
        path: "/feed-presets/hagezi",
        body: { provider: "hagezi", feeds: [], created: false, bundle_added: false, file_restored: false, pending: waiting },
      },
    ]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /From a preset/ }, T));
    const dialog = await screen.findByRole("dialog", undefined, T);
    const row = (title: string) => within(dialog).getByText(title, { exact: false, selector: "div.font-medium" }).closest("li")!;
    await within(dialog).findByText(/waiting for its feeds/, undefined, T);
    const hagezi = row("HaGeZi");
    expect(within(hagezi).queryByText("installed")).toBeNull();
    expect(within(hagezi).getByText(presetPendingText(waiting))).toBeInTheDocument();
    const oisd = row("OISD big");
    expect(within(oisd).getByText("needs attention")).toBeInTheDocument();
    expect(within(oisd).getByText(/now reads another source/)).toBeInTheDocument();
    await user.click(within(hagezi).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(info).toHaveBeenCalled(), T);
    expect(info.mock.calls[0][0]).toBe(`Installing. ${presetPendingText(waiting)}`);
    expect(success).not.toHaveBeenCalled();
    info.mockRestore();
    success.mockRestore();
  });
});
