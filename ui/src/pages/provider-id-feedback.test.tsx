// The new feed provider dialog's id: a local syntax error, and core's refusal of an id that is
// well formed but taken (`id_taken`: a one-file provider's feed takes the provider's id, so
// another feed may not hold it), shown beside the field until the id changes.
import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, mutations, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";

const T = { timeout: 8000 };
const TAKEN = 'feed "lists" exists and isn\'t this provider\'s: a http provider\'s feed takes the provider\'s id; pick another id, or delete that feed';

const refusal = (id: string) =>
  reply(422, {
    error: {
      code: "validation",
      message: "the change was refused",
      issues: [{ severity: "error", entity: "feed_provider", id, field: "id", code: "id_taken", message: TAKEN }],
    },
  });

describe("the new feed provider dialog's id", () => {
  it("shows core's id_taken beside the id until the id changes, then creates under the new one", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      {
        method: "POST",
        path: "/feed-providers",
        refuses: true,
        body: (c: Call) => {
          const id = (c.body as { id: string }).id;
          return id === "lists" ? refusal(id) : reply(201, { id, warnings: [] });
        },
      },
    ]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /New provider/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Lists");
    await user.click(within(dialog).getByLabelText("Download module"));
    await user.click(await screen.findByRole("option", { name: /^http / }));
    await user.type(within(dialog).getAllByLabelText(/^url/i)[0], "https://lists.example/lists.txt");
    const id = within(dialog).getByLabelText("Id");
    expect(id).toHaveValue("lists");
    expect(id).not.toHaveAttribute("aria-invalid");

    await user.click(within(dialog).getByRole("button", { name: "Create provider" }));
    const help = await within(dialog).findByText(TAKEN, undefined, T);
    expect(help).toHaveAttribute("id", "np-id-help");
    expect(help).toHaveClass("text-destructive");
    expect(id).toHaveAttribute("aria-invalid", "true");
    expect(id).toHaveAccessibleDescription(TAKEN);
    // The toast says it too; the dialog stays open, the id as typed (never renamed).
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(id).toHaveValue("lists");

    // A local syntax error shows first; a well-formed new id drops core's stale refusal.
    await user.type(id, " x");
    expect(within(dialog).getByText(/1–64 of a-z/)).toBeInTheDocument();
    expect(within(dialog).queryByText(TAKEN)).toBeNull();
    expect(id).toHaveAttribute("aria-invalid", "true");
    await user.clear(id);
    await user.type(id, "lists-2");
    expect(within(dialog).queryByText(TAKEN)).toBeNull();
    expect(id).not.toHaveAttribute("aria-invalid");
    expect(within(dialog).getByText("It never changes once created.")).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Create provider" }));
    await waitFor(() => expect(mutations(calls).filter((c) => c.path === "/feed-providers")).toHaveLength(2), T);
    expect(mutations(calls).map((c) => (c.body as { id: string }).id)).toEqual(["lists", "lists-2"]);
    expect(await screen.findByText("Created provider lists-2", undefined, T)).toBeInTheDocument();
  });

  it("drops the refusal when renaming changes the derived id, and shows it again for the refused id", async () => {
    const user = userEvent.setup();
    mockApi([{ method: "POST", path: "/feed-providers", refuses: true, body: (c: Call) => refusal((c.body as { id: string }).id) }]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /New provider/ }, T));
    const dialog = await screen.findByRole("dialog");
    const name = within(dialog).getByLabelText("Name");
    await user.type(name, "Lists");
    await user.click(within(dialog).getByLabelText("Download module"));
    await user.click(await screen.findByRole("option", { name: /^http / }));
    await user.type(within(dialog).getAllByLabelText(/^url/i)[0], "https://lists.example/lists.txt");
    await user.click(within(dialog).getByRole("button", { name: "Create provider" }));
    await within(dialog).findByText(TAKEN, undefined, T);
    // The id follows the name: renaming changes the id, so the refusal no longer applies …
    await user.type(name, " More");
    expect(within(dialog).getByLabelText("Id")).toHaveValue("lists-more");
    expect(within(dialog).queryByText(TAKEN)).toBeNull();
    // … and back to the refused id, it does again (it's still taken).
    await user.type(name, "{Backspace}{Backspace}{Backspace}{Backspace}{Backspace}");
    expect(within(dialog).getByLabelText("Id")).toHaveValue("lists");
    expect(within(dialog).getByText(TAKEN)).toBeInTheDocument();
  });
});
