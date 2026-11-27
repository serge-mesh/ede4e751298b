// An `edge_tls_version_refused` alert's detail view: the edge's DoT and DoH listeners speak only
// TLS 1.3, and a client whose ClientHello offers no TLS 1.3 is refused and reported (api.md §5
// `tls_version_refused`; core raises the alert in logs/ingest.rs).
import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { mockApi } from "@/test/mock-api";
import { W5 } from "@/test/core-w5";
import { renderApp } from "@/test/render";

const T = { timeout: 8000 };

/** An alert's page, its alert as core gives it (`GET alerts/{id}`) with these fields. */
function alertPage(id: number, details: Record<string, unknown>) {
  const base = W5["/alerts/{category_blocked}"] as { alert: Record<string, unknown> };
  const alert = {
    ...base.alert,
    id,
    type: "operational",
    severity: "warning",
    kind: "edge_tls_version_refused",
    dedupe_key: `edge_tls_version_refused:e-1:${String(details.device ?? details.client)}`,
    title: `Edge gw: ${String(details.device ?? details.client)} offers no TLS 1.3, so listener ${String(details.listener)} refuses it`,
    edge: "e-1",
    feed: null,
    bundle: null,
    count: 4,
    details: { edge: "e-1", ...details },
  };
  mockApi([{ method: "GET", path: `/alerts/${id}`, body: { alert, history: [] } }]);
  renderApp(`/alerts/${id}`);
}

describe("edge_tls_version_refused: the device, the listener, what it offered, and what to do", () => {
  it("a named device on DoT offering TLS 1.2", async () => {
    alertPage(401, { device: "old-printer", client: "192.168.1.51", listener: "lan-dot", transport: "dot", sni: "dns.home.arpa", offered: "tls12" });
    const v = await screen.findByTestId("tls-version-refused", undefined, T);
    expect(within(v).getByText("old-printer (192.168.1.51)")).toBeInTheDocument();
    expect(within(v).getByText("lan-dot (DoT)")).toBeInTheDocument();
    expect(within(v).getByText("dns.home.arpa")).toBeInTheDocument();
    expect(within(v).getByText("TLS 1.2")).toBeInTheDocument();
    expect(v).toHaveTextContent("This client only supports TLS 1.2; Picket's listeners require TLS 1.3. Update the client, or point it at plain DNS on port 53.");
  });

  it("an unnamed device on DoH, no SNI, offering TLS 1.1 or older", async () => {
    alertPage(402, { device: null, client: "192.168.1.60", listener: "lan-doh", transport: "doh", sni: null, offered: "tls11_or_older" });
    const v = await screen.findByTestId("tls-version-refused", undefined, T);
    expect(within(v).getByText("192.168.1.60")).toBeInTheDocument();
    expect(within(v).getByText("lan-doh (DoH)")).toBeInTheDocument();
    expect(within(v).getByText("none sent")).toBeInTheDocument();
    expect(within(v).getByText("TLS 1.1 or older")).toBeInTheDocument();
    expect(within(v).queryByText("MAC")).not.toBeInTheDocument();
    expect(v).toHaveTextContent("This client only supports TLS 1.1 or older; Picket's listeners require TLS 1.3.");
  });

  it("a device behind a client name, told apart by its MAC; a version list without any TLS version the UI knows", async () => {
    alertPage(405, { device: "kids", mac: "02:00:00:00:00:01", client: "192.168.1.51", listener: "lan-dot", transport: "dot", sni: "dns.home.arpa", offered: "no_tls13" });
    const v = await screen.findByTestId("tls-version-refused", undefined, T);
    expect(within(v).getByText("kids (192.168.1.51)")).toBeInTheDocument();
    expect(within(v).getByText("02:00:00:00:00:01")).toBeInTheDocument();
    expect(within(v).getByText("a version list without TLS 1.3 or TLS 1.0–1.2")).toBeInTheDocument();
    expect(v).toHaveTextContent("This client doesn't support TLS 1.3, which Picket's listeners require.");
  });

  it("what a newer edge reports that this UI doesn't know is shown as given, with the general hint", async () => {
    alertPage(403, { device: "tv", client: "192.168.1.70", listener: "lan-dot", transport: "dot", offered: "ssl3\u0007" });
    const v = await screen.findByTestId("tls-version-refused", undefined, T);
    // Control characters show escaped (core.md §12).
    expect(within(v).getByText("ssl3\\x07")).toBeInTheDocument();
    expect(v).toHaveTextContent("This client doesn't support TLS 1.3, which Picket's listeners require. Update the client, or point it at plain DNS on port 53.");
  });

  it("a value naming an Object.prototype member is unknown, not a lookup into the prototype (review r10 U6)", async () => {
    alertPage(404, { device: "tv", client: "192.168.1.71", listener: "lan-dot", transport: "constructor", offered: "constructor" });
    const v = await screen.findByTestId("tls-version-refused", undefined, T);
    expect(within(v).getByText("constructor")).toBeInTheDocument();
    expect(within(v).getByText("lan-dot (constructor)")).toBeInTheDocument();
    expect(v).not.toHaveTextContent("undefined");
    expect(v).toHaveTextContent("This client doesn't support TLS 1.3, which Picket's listeners require.");
  });
});
