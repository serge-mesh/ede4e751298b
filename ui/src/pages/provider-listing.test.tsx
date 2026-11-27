// A feed provider's Files tab on core's S3 ListObjectsV2-style `GET feed-providers/{id}/listing`
// (`prefix` + `delimiter=/`: a folder's folders and files merged in key order, both counting toward
// `limit`; `q`: a search of every path; api.md §7 paging): folders above files with their counts,
// the folder in the URL (Back walks up) with a breadcrumb, 500 entries a page with Load more (a
// folder a later page brings still lists above the files), the browser's sort by name, Add as
// feed (`POST feed-providers/{id}/files`) on a later page, the search (100 a page, each match
// linking to its folder), and the empty, no-listing, limited and failed-page states.
import { describe, expect, it } from "vitest";
import { act, cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, reply, type Call } from "@/test/mock-api";
import { renderApp } from "@/test/render";
import fixtures from "@/test/fixtures/core.json";

const T = { timeout: 8000 };
const PATH = "/feed-providers/hagezi/listing";
const ADD = "/feed-providers/hagezi/files";

/**
 * The mock's cursor: unpadded URL-safe base64 of the last key returned. (core's puts a marker
 * before the key, feeds/api.rs `key_page`; the UI passes either back as it came.)
 */
const cursorOf = (key: string) => Buffer.from(key, "utf8").toString("base64url");
const keyOf = (cursor: string) => Buffer.from(cursor, "base64url").toString("utf8");

interface Row {
  file: string;
  selected: boolean;
  feed: string | null;
}
interface Prefix {
  prefix: string;
  files: number;
  feeds: number;
}
type Entry = { key: string; row: Row } | { key: string; prefix: Prefix };

/** core's search case: each character lowercased (Unicode), on both sides (feeds/select.rs `FilesView::search`). */
function lower(s: string | null): string | undefined {
  return s === null ? undefined : [...s].map((c) => c.toLowerCase()).join("");
}

/** core's listing (feeds/select.rs `FilesView::list`/`search`, feeds/api.rs `provider_listing`) of `rows` for a call. */
function list(rows: Row[], call: Call, listing: { files: number; whole: boolean } | null = { files: rows.length, whole: true }) {
  const prefix = call.query.get("prefix") ?? "";
  const grouped = call.query.get("delimiter") === "/";
  const q = lower(call.query.get("q"));
  const cursor = call.query.get("cursor");
  const limit = Number(call.query.get("limit") ?? 100);
  const entries: Entry[] = [];
  for (const row of [...rows].sort((a, b) => (a.file < b.file ? -1 : 1))) {
    if (!row.file.startsWith(prefix)) continue;
    if (q !== undefined) {
      if (lower(row.file)!.includes(q)) entries.push({ key: row.file, row });
      continue;
    }
    const slash = grouped ? row.file.indexOf("/", prefix.length) : -1;
    if (slash < 0) {
      entries.push({ key: row.file, row });
      continue;
    }
    const p = row.file.slice(0, slash + 1);
    const last = entries.at(-1);
    if (last && "prefix" in last && last.prefix.prefix === p) {
      last.prefix.files += 1;
      last.prefix.feeds += row.feed ? 1 : 0;
    } else entries.push({ key: p, prefix: { prefix: p, files: 1, feeds: row.feed ? 1 : 0 } });
  }
  const rest = entries.filter((e) => !cursor || e.key > keyOf(cursor));
  const page = rest.slice(0, limit);
  return {
    prefixes: page.flatMap((e) => ("prefix" in e ? [e.prefix] : [])),
    items: page.flatMap((e) => ("row" in e ? [e.row] : [])),
    next_cursor: rest.length > limit ? cursorOf(page[page.length - 1].key) : null,
    listing,
  };
}

const big = (i: number) => `big/f${String(i).padStart(3, "0")}.txt`;
/** The root's README.md and hosts.txt; adblock/ (pro.txt with a feed, tif.txt, sub/deep.txt); big/ (600 files and zz/x.txt). */
const rows = (): Row[] => [
  { file: "README.md", selected: false, feed: null },
  { file: "hosts.txt", selected: false, feed: null },
  { file: "adblock/pro.txt", selected: true, feed: "hagezi-adblock-pro" },
  { file: "adblock/tif.txt", selected: true, feed: null },
  { file: "adblock/sub/deep.txt", selected: false, feed: null },
  ...Array.from({ length: 600 }, (_, i) => ({ file: big(i), selected: false, feed: null })),
  { file: "big/zz/x.txt", selected: false, feed: null },
];

const gets = (calls: Call[]) => calls.filter((c) => c.method === "GET" && c.path === PATH);
const table = () => screen.getByRole("table", { name: "Provider files" });
/** The table's rows' first cells, in order. */
const names = () => within(table()).getAllByRole("row").slice(1).map((r) => r.querySelector("td")?.textContent ?? "");
const crumbs = () => within(screen.getByRole("navigation", { name: "breadcrumb" })).getAllByRole("listitem").map((li) => li.textContent);
/** The row whose first cell reads `name` (a folder's name and its `/` are two text nodes). */
const rowOf = (name: string) => {
  const row = within(table())
    .getAllByRole("row")
    .find((r) => r.querySelector("td")?.textContent === name);
  if (!row) throw new Error(`no row ${name}: ${names().join(", ")}`);
  return row;
};

/**
 * Tests that render a folder of 500+ rows (the UI's page size) in jsdom: about 7 s on a quiet
 * machine, but up to 30 s on a CI runner shared with the Rust job, so they get a wide timeout.
 */
const BIG_FOLDER_TIMEOUT = 120_000;

describe("a provider's files by folder", () => {
  it("lists the root's folders, with their counts, above its files; a folder opens through the URL, the breadcrumb and Back walk up", async () => {
    const user = userEvent.setup();
    const data = rows();
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    const { router } = renderApp("/feed-providers/hagezi?tab=files");
    await screen.findByRole("link", { name: "adblock/" }, T);
    expect(names()).toEqual(["adblock/", "big/", "README.md", "hosts.txt"]);
    expect(within(rowOf("adblock/")).getByText("3 files, 1 feed")).toBeInTheDocument();
    expect(within(rowOf("big/")).getByText("601 files, 0 feeds")).toBeInTheDocument();
    expect(crumbs()).toEqual(["HaGeZi"]);
    const first = gets(calls)[0].query;
    expect([first.get("prefix"), first.get("delimiter"), first.get("limit")]).toEqual([null, "/", "500"]);

    await user.click(screen.getByRole("link", { name: "adblock/" }));
    await waitFor(() => expect(names()).toEqual(["sub/", "pro.txt", "tif.txt"]), T);
    expect(router.state.location.search).toMatchObject({ tab: "files", prefix: "adblock/" });
    expect(gets(calls).at(-1)?.query.get("prefix")).toBe("adblock/");
    expect(within(rowOf("pro.txt")).getByRole("link", { name: "hagezi-adblock-pro" })).toBeInTheDocument();
    expect(within(rowOf("tif.txt")).getByText("selected")).toBeInTheDocument();
    expect(crumbs()).toEqual(["HaGeZi", "adblock"]);

    await user.click(screen.getByRole("link", { name: "sub/" }));
    await waitFor(() => expect(names()).toEqual(["deep.txt"]), T);
    expect(crumbs()).toEqual(["HaGeZi", "adblock", "sub"]);
    act(() => router.history.back());
    await waitFor(() => expect(names()).toEqual(["sub/", "pro.txt", "tif.txt"]), T);
    expect(router.state.location.search).toMatchObject({ prefix: "adblock/" });
    await user.click(within(screen.getByRole("navigation", { name: "breadcrumb" })).getByRole("link", { name: "HaGeZi" }));
    await waitFor(() => expect(names()).toEqual(["adblock/", "big/", "README.md", "hosts.txt"]), T);
    expect(router.state.location.search).not.toHaveProperty("prefix");
  });

  it("reads a big folder 500 entries at a time; Load more appends, and a folder a later page brings lists above the files", async () => {
    const user = userEvent.setup();
    const data = rows();
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    renderApp("/feed-providers/hagezi?tab=files&prefix=big%2F");
    await screen.findByText("f499.txt", undefined, T);
    expect(names()).toHaveLength(500);
    expect(screen.queryByText("f500.txt")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("f599.txt", undefined, T);
    expect(gets(calls).at(-1)?.query.get("cursor")).toBe(cursorOf(big(499)));
    expect(names()).toHaveLength(601);
    expect(names()[0]).toBe("zz/");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  }, BIG_FOLDER_TIMEOUT);

  it("sorts the current folder by name in the browser, folders and files each, and says it covers only the entries loaded", async () => {
    const user = userEvent.setup();
    const data = rows();
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    renderApp("/feed-providers/hagezi?tab=files");
    await screen.findByRole("link", { name: "adblock/" }, T);
    const name = () => screen.getByRole("button", { name: "Name" });
    expect(name().closest("th")).toHaveAttribute("aria-sort", "ascending");
    expect(screen.queryByText(/sorting by name covers those/)).toBeNull();
    await user.click(name());
    expect(names()).toEqual(["big/", "adblock/", "hosts.txt", "README.md"]);
    expect(name().closest("th")).toHaveAttribute("aria-sort", "descending");
    await user.click(name());
    expect(names()).toEqual(["adblock/", "big/", "README.md", "hosts.txt"]);
    const reads = gets(calls).length;
    // Another folder starts ascending; with more to load, a note says what the sort covers.
    await user.click(name());
    await user.click(screen.getByRole("link", { name: "big/" }));
    await screen.findByText("f499.txt", undefined, T);
    expect(name().closest("th")).toHaveAttribute("aria-sort", "ascending");
    await user.click(name());
    expect(names().slice(0, 2)).toEqual(["f499.txt", "f498.txt"]);
    expect(screen.getByText(/sorting by name covers those/)).toHaveTextContent("The folder holds more than the 500 entries loaded");
    await user.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("f599.txt", undefined, T);
    expect(names().slice(0, 3)).toEqual(["zz/", "f599.txt", "f598.txt"]);
    expect(names().at(-1)).toBe("f000.txt");
    expect(screen.queryByText(/sorting by name covers those/)).toBeNull();
    expect(gets(calls).slice(reads).every((c) => c.query.get("prefix") === "big/")).toBe(true);
  }, BIG_FOLDER_TIMEOUT);

  it("Add as feed on a later page reads every loaded page again, once, and keeps the row in view", async () => {
    const user = userEvent.setup();
    const data = rows();
    const { calls } = mockApi([
      { method: "GET", path: PATH, body: (c: Call) => list(data, c) },
      {
        method: "POST",
        path: ADD,
        body: (c: Call) => {
          const row = data.find((r) => r.file === (c.body as { file: string }).file)!;
          row.feed = "hagezi-big-f550";
          return { id: "hagezi", warnings: [], feeds_added: [row.feed] };
        },
      },
    ]);
    renderApp("/feed-providers/hagezi?tab=files&prefix=big%2F");
    await user.click(await screen.findByRole("button", { name: "Load more" }, T));
    await screen.findByText("f550.txt", undefined, T);
    await user.click(within(rowOf("f550.txt")).getByRole("button", { name: /Add as feed/ }));
    expect(await within(rowOf("f550.txt")).findByRole("link", { name: "hagezi-big-f550" }, T)).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST" && c.path === ADD)?.body).toEqual({ file: "big/f550.txt", feed: { format: "adblock" } });
    expect(gets(calls).slice(2).map((c) => c.query.get("cursor"))).toEqual([null, cursorOf(big(499))]);
  }, BIG_FOLDER_TIMEOUT);

  it("searches every path, 100 matches a page, the search in the URL; each match links to its folder, which leaves the search", async () => {
    const user = userEvent.setup();
    const data = rows();
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    const { router } = renderApp("/feed-providers/hagezi?tab=files&prefix=adblock%2F");
    await screen.findByText("pro.txt", undefined, T);
    const search = screen.getByRole("textbox", { name: "Search files" });
    expect(search).toHaveAttribute("maxLength", "256");
    await user.type(search, "9{Enter}");
    const matches = await screen.findByRole("table", { name: "Matching files" }, T);
    expect(router.state.location.search).toMatchObject({ prefix: "adblock/", q: "9" });
    const last = gets(calls).at(-1)!.query;
    expect([last.get("q"), last.get("limit"), last.get("prefix"), last.get("delimiter")]).toEqual(["9", "100", null, null]);
    // The big files whose number holds a 9 (19 in each hundred): 114, the first 100 here.
    expect(within(matches).getAllByRole("row")).toHaveLength(101);
    await user.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Matching files" })).getAllByRole("row")).toHaveLength(115), T);
    const row = within(screen.getByRole("table", { name: "Matching files" })).getByText("big/f599.txt").closest("tr") as HTMLElement;
    await user.click(within(row).getByRole("link", { name: "big/" }));
    await screen.findByRole("table", { name: "Provider files" }, T);
    expect(router.state.location.search).toMatchObject({ prefix: "big/" });
    expect(router.state.location.search).not.toHaveProperty("q");
    expect(screen.getByRole("textbox", { name: "Search files" })).toHaveValue("");
    await user.type(screen.getByRole("textbox", { name: "Search files" }), "nothing-like-it{Enter}");
    expect(await screen.findByText(/No file's path holds/, undefined, T)).toHaveTextContent("No file's path holds nothing-like-it.");
    await user.click(screen.getByRole("button", { name: /Clear/ }));
    expect(await screen.findByRole("table", { name: "Provider files" }, T)).toBeInTheDocument();
    expect(router.state.location.search).toMatchObject({ prefix: "big/" });
    expect(router.state.location.search).not.toHaveProperty("q");
  }, BIG_FOLDER_TIMEOUT);

  it("Back out of a search shows the folder again, with its breadcrumb; Forward the search, its text in the box", async () => {
    const user = userEvent.setup();
    const data = [...rows(), { file: "docs/École.txt", selected: false, feed: null }];
    mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    const { router } = renderApp("/feed-providers/hagezi?tab=files&prefix=adblock%2F");
    await screen.findByText("pro.txt", undefined, T);
    await user.type(screen.getByRole("textbox", { name: "Search files" }), "éCOLE{Enter}");
    const matches = await screen.findByRole("table", { name: "Matching files" }, T);
    expect(within(matches).getByText("docs/École.txt")).toBeInTheDocument();
    act(() => router.history.back());
    await waitFor(() => expect(names()).toEqual(["sub/", "pro.txt", "tif.txt"]), T);
    expect(crumbs()).toEqual(["HaGeZi", "adblock"]);
    expect(screen.getByRole("textbox", { name: "Search files" })).toHaveValue("");
    act(() => router.history.forward());
    expect(await screen.findByRole("table", { name: "Matching files" }, T)).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Search files" })).toHaveValue("éCOLE");
  });

  it("sorts folders by the name shown, not core's key order: hosts/ before hosts-extra/ and hosts.d/", async () => {
    const user = userEvent.setup();
    const data: Row[] = ["hosts.d/b.txt", "hosts-extra/c.txt", "hosts/a.txt", "hosts.txt"].map((file) => ({ file, selected: false, feed: null }));
    mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    renderApp("/feed-providers/hagezi?tab=files");
    await screen.findByRole("link", { name: "hosts/" }, T);
    expect(names()).toEqual(["hosts/", "hosts-extra/", "hosts.d/", "hosts.txt"]);
    await user.click(screen.getByRole("button", { name: "Name" }));
    expect(names()).toEqual(["hosts.d/", "hosts-extra/", "hosts/", "hosts.txt"]);
  });

  it("names a folder named nothing (empty), and reads a typed prefix without its last / as that folder", async () => {
    const data: Row[] = ["a//b.txt", "a/x.txt", "adblock/sub/deep.txt", "adblock/pro.txt"].map((file) => ({ file, selected: false, feed: null }));
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    const first = renderApp("/feed-providers/hagezi?tab=files&prefix=a%2F");
    await screen.findByText("x.txt", undefined, T);
    expect(names()).toEqual(["(empty)/", "x.txt"]);
    first.unmount();
    renderApp("/feed-providers/hagezi?tab=files&prefix=a%2F%2F");
    await screen.findByText("b.txt", undefined, T);
    expect(crumbs()).toEqual(["HaGeZi", "a", "(empty)"]);
    cleanup();
    renderApp("/feed-providers/hagezi?tab=files&prefix=adblock");
    await screen.findByText("pro.txt", undefined, T);
    expect(names()).toEqual(["sub/", "pro.txt"]);
    expect(gets(calls).at(-1)?.query.get("prefix")).toBe("adblock/");
  });

  it("an http provider (one URL, one feed) has no Files tab: its overview shows its URL and its feed", async () => {
    const provider = {
      ...(fixtures["/feed-providers/hagezi"] as object),
      id: "fh",
      name: "FH",
      module: "http",
      config: { url: "https://lists.example/big/list.txt?v=1" },
      files: [{ match: "response", feed: { format: "plain" } }],
      exclude: [],
    };
    const { calls } = mockApi([
      { method: "GET", path: "/feed-providers/fh", body: provider },
      { method: "GET", path: "/feed-providers/fh/status", body: { ...(fixtures["/feed-providers/hagezi/status"] as object), provider: "fh", module: "http", feeds: ["fh"] } },
    ]);
    // A link to its Files tab shows the overview.
    renderApp("/feed-providers/fh?tab=files");
    expect(await screen.findByRole("link", { name: "fh" }, T)).toHaveAttribute("href", "/feeds/fh");
    expect(screen.getAllByText("https://lists.example/big/list.txt?v=1").length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByRole("tab", { name: "Files" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(calls.some((c) => c.path === "/feed-providers/fh/listing")).toBe(false);
  });

  it("adding a feed by URL says which provider and feed read it", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      {
        method: "POST",
        path: "/feed-providers-add-url",
        body: {
          provider: "lists-example-a-txt",
          created_provider: true,
          file: "response",
          feed: "lists-example-a-txt",
          notice: null,
          outcome: { id: "lists-example-a-txt", warnings: [], feeds_added: ["lists-example-a-txt"] },
        },
      },
    ]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /Paste a feed URL/ }, T));
    await user.type(screen.getByLabelText("Feed URL"), "https://lists.example/a.txt");
    await user.click(screen.getByRole("button", { name: "Add feed" }));
    expect(await screen.findByText(/Created provider/, undefined, T)).toBeInTheDocument();
    const hrefs = screen.getAllByRole("link", { name: "lists-example-a-txt" }).map((a) => a.getAttribute("href"));
    expect(hrefs).toEqual(["/feed-providers/lists-example-a-txt", "/feeds/lists-example-a-txt"]);
    expect(calls.find((c) => c.method === "POST" && c.path === "/feed-providers-add-url")?.body).toMatchObject({ url: "https://lists.example/a.txt" });
  });

  it("adding a URL that has its feed says so, and the settings chosen go with the request", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([
      {
        method: "POST",
        path: "/feed-providers-add-url",
        body: {
          provider: "fh",
          created_provider: false,
          existing: true,
          file: "response",
          feed: "fh",
          notice: null,
          outcome: { id: "fh", warnings: [], feeds_added: [] },
        },
      },
    ]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /Paste a feed URL/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Feed URL"), "https://lists.example/hosts.txt");
    await user.click(within(dialog).getByLabelText("Format"));
    await user.click(await screen.findByRole("option", { name: "hosts" }));
    await user.click(within(dialog).getByRole("button", { name: "Add feed" }));
    expect(await screen.findByText(/Already added: feed/, undefined, T)).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "fh" }).map((a) => a.getAttribute("href"))).toEqual(["/feeds/fh", "/feed-providers/fh"]);
    expect(screen.queryByText(/Created provider/)).toBeNull();
    expect(calls.find((c) => c.method === "POST" && c.path === "/feed-providers-add-url")?.body).toMatchObject({ url: "https://lists.example/hosts.txt", feed: { format: "hosts" } });
    const sent = (calls.find((c) => c.method === "POST" && c.path === "/feed-providers-add-url")?.body as { feed: object }).feed;
    expect(Object.keys(sent).filter((k) => ["id", "provider", "file", "system", "name"].includes(k))).toEqual([]);
  });

  it("a new http provider's feed is created with the format chosen in the form", async () => {
    const user = userEvent.setup();
    const { calls } = mockApi([{ method: "POST", path: "/feed-providers", status: 201, body: (c: Call) => ({ id: (c.body as { id: string }).id, warnings: [] }) }]);
    renderApp("/feed-providers");
    await user.click(await screen.findByRole("button", { name: /New provider/ }, T));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Hosts List");
    await user.click(within(dialog).getByLabelText("Download module"));
    await user.click(await screen.findByRole("option", { name: /^http / }));
    await user.type(within(dialog).getAllByLabelText(/^url/i)[0], "https://lists.example/hosts.txt");
    await user.click(within(dialog).getByLabelText("Format"));
    await user.click(await screen.findByRole("option", { name: "hosts" }));
    await user.click(within(dialog).getByRole("button", { name: "Create provider" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/feed-providers")).toBe(true), T);
    expect(calls.find((c) => c.method === "POST" && c.path === "/feed-providers")?.body).toMatchObject({
      id: "hosts-list",
      module: "http",
      files: [{ match: "response", feed: { format: "hosts" } }],
    });
    // Nothing core sets itself (files/check_template refuses id, provider, file, system).
    const feed = (calls.find((c) => c.method === "POST" && c.path === "/feed-providers")?.body as { files: { feed: object }[] }).files[0].feed;
    expect(Object.keys(feed).filter((k) => ["id", "provider", "file", "system", "name"].includes(k))).toEqual([]);
  });

  it("shows a github provider's Files tab when core's module list can't be read", async () => {
    const data = rows();
    mockApi([
      { method: "GET", path: "/download-modules", refuses: true, body: reply(500, { error: { code: "internal", message: "core failed" } }) },
      { method: "GET", path: PATH, body: (c: Call) => list(data, c) },
    ]);
    renderApp("/feed-providers/hagezi?tab=files");
    expect(await screen.findByRole("tab", { name: "Files" }, T)).toHaveAttribute("aria-selected", "true");
    await screen.findByText("README.md", undefined, T);
  });

  it("reads a hand-typed q or prefix that looks like a number as text", async () => {
    const data = [...rows(), { file: "123/x.txt", selected: false, feed: null }, { file: "a-123.txt", selected: false, feed: null }];
    const { calls } = mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c) }]);
    const first = renderApp("/feed-providers/hagezi?tab=files&q=123");
    expect(await screen.findByRole("table", { name: "Matching files" }, T)).toBeInTheDocument();
    expect(gets(calls).at(-1)?.query.get("q")).toBe("123");
    expect(screen.getByRole("textbox", { name: "Search files" })).toHaveValue("123");
    first.unmount();
    renderApp("/feed-providers/hagezi?tab=files&prefix=123");
    await screen.findByText("x.txt", undefined, T);
    expect(gets(calls).at(-1)?.query.get("prefix")).toBe("123/");
  });

  it("says when there's no listing yet", async () => {
    mockApi([{ method: "GET", path: PATH, body: (c: Call) => list([], c, null) }]);
    renderApp("/feed-providers/hagezi?tab=files");
    expect(await screen.findByText("No listing yet: it arrives with the provider's next check.", undefined, T)).toBeInTheDocument();
  });

  it("an unknown folder lists nothing; a limited listing says so", async () => {
    const data = rows();
    mockApi([{ method: "GET", path: PATH, body: (c: Call) => list(data, c, { files: data.length, whole: false }) }]);
    renderApp("/feed-providers/hagezi?tab=files&prefix=gone%2F");
    expect(await screen.findByText("Nothing under this folder in the latest listing.", undefined, T)).toBeInTheDocument();
    expect(screen.getByText("The module limited the listing to what files can select")).toBeInTheDocument();
    expect(crumbs()).toEqual(["HaGeZi", "gone"]);
  });

  it("keeps the rows when Load more fails, and Retry reads that page", async () => {
    const user = userEvent.setup();
    const data = rows();
    let fail = false;
    mockApi([
      {
        method: "GET",
        path: PATH,
        refuses: true,
        body: (c: Call) => (fail && c.query.get("cursor") ? reply(500, { error: { code: "internal", message: "boom" } }) : list(data, c)),
      },
    ]);
    renderApp("/feed-providers/hagezi?tab=files&prefix=big%2F");
    await screen.findByText("f499.txt", undefined, T);
    fail = true;
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(await screen.findByTestId("next-page-error", undefined, T)).toHaveTextContent("Couldn't load more files");
    expect(screen.getByText("f499.txt")).toBeInTheDocument();
    fail = false;
    await user.click(within(screen.getByTestId("next-page-error")).getByRole("button", { name: /Retry/ }));
    expect(await screen.findByText("f599.txt", undefined, T)).toBeInTheDocument();
  }, BIG_FOLDER_TIMEOUT);
});
