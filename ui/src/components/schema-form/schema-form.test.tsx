import * as React from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TooltipProvider } from "@/components/ui/tooltip";
import dns from "@/test/fixtures/dns-module-schema.json";
import { openapiRoot } from "@/lib/openapi";
import type { SchemaRoot } from "@/lib/schema";
import { SchemaForm, type SchemaFormProps } from "./schema-form";

const dnsRoot = dns as unknown as SchemaRoot;

/** A controlled form that records every value it emits. */
function Harness(props: Omit<SchemaFormProps, "value" | "onChange"> & { initial: unknown; onValue?: (v: unknown) => void }) {
  const [value, setValue] = React.useState<unknown>(props.initial);
  return (
    <TooltipProvider>
      <SchemaForm
        {...props}
        value={value}
        onChange={(v) => {
          setValue(v);
          props.onValue?.(v);
        }}
      />
    </TooltipProvider>
  );
}

describe("SchemaForm: module Config schemas", () => {
  it("renders every field of the schema with its label and description tooltip", () => {
    render(<Harness schema={dnsRoot} root={dnsRoot} initial={{ transport: "dot", servers: [] }} />);
    expect(screen.getByText("Transport")).toBeInTheDocument();
    expect(screen.getByText("Servers")).toBeInTheDocument();
    expect(screen.getByText("Qtype")).toBeInTheDocument();
    expect(screen.getByText("Rules")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "About Transport" })).toBeInTheDocument();
  });

  it("shows the x-picket-warning text while the field holds a listed value", () => {
    const { rerender } = render(<Harness schema={dnsRoot} root={dnsRoot} initial={{ transport: "udp", servers: [] }} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/Plain DNS is unencrypted/);
    rerender(<Harness key="dot" schema={dnsRoot} root={dnsRoot} initial={{ transport: "doh", servers: [] }} />);
    expect(screen.queryByText(/Plain DNS is unencrypted/)).toBeNull();
  });

  it("adds array items from the item schema and edits their fields", async () => {
    const user = userEvent.setup();
    const onValue = vi.fn();
    render(<Harness schema={dnsRoot} root={dnsRoot} initial={{ transport: "dot", servers: [] }} onValue={onValue} />);
    const servers = screen.getByText("Servers").closest("[data-field]") as HTMLElement;
    await user.click(within(servers).getByRole("button", { name: /add/i }));
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ servers: [{ ip: "", port: null, tls_host: null, trust_store: null, path: null }] }));
    await user.type(within(servers).getByLabelText("Ip"), "9.9.9.9");
    expect(onValue.mock.lastCall?.[0].servers[0].ip).toBe("9.9.9.9");
    // A nullable integer: empty means null, a number is a number.
    await user.type(within(servers).getByLabelText("Port"), "853");
    expect(onValue.mock.lastCall?.[0].servers[0].port).toBe(853);
    await user.clear(within(servers).getByLabelText("Port"));
    expect(onValue.mock.lastCall?.[0].servers[0].port).toBeNull();
  });

  it("toggles a nullable object between unset (null) and its defaults", async () => {
    const user = userEvent.setup();
    const onValue = vi.fn();
    render(<Harness schema={dnsRoot} root={dnsRoot} initial={{ transport: "dot", servers: [], self_test: null }} onValue={onValue} />);
    await user.click(screen.getByRole("checkbox", { name: "Set self_test" }));
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ self_test: { name: "", expect: "block", cron: "" } }));
    expect(screen.getByLabelText("Cron")).toBeInTheDocument();
  });

  it("shows server-side errors by field path", () => {
    render(<Harness schema={dnsRoot} root={dnsRoot} initial={{ servers: [{ ip: "x" }] }} errors={{ "servers.0.ip": "not an IP address" }} />);
    const input = screen.getByLabelText("Ip");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("not an IP address")).toBeInTheDocument();
  });

  it("renders descriptions and values as text, never HTML", () => {
    const schema = {
      type: "object",
      properties: { note: { type: "string", description: "<img src=x onerror=alert(1)> `code`" } },
    };
    const { container } = render(<Harness schema={schema} initial={{ note: "<b>bold</b>" }} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByLabelText("Note")).toHaveValue("<b>bold</b>");
  });
});

describe("SchemaForm: entity schemas from the OpenAPI document", () => {
  it("edits a list of strings as tags", async () => {
    const user = userEvent.setup();
    const onValue = vi.fn();
    render(<Harness schema={{ $ref: "#/components/schemas/ClientDef" }} root={openapiRoot} initial={{ name: "tv", macs: [], source_ips: [], tags: [] }} onValue={onValue} mode="create" />);
    const input = screen.getByLabelText("Source ips");
    await user.type(input, "192.168.1.0/24{Enter}");
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ source_ips: ["192.168.1.0/24"] }));
    await user.click(screen.getByRole("button", { name: "Remove 192.168.1.0/24" }));
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ source_ips: [] }));
  });

  it("renders the selected variant of a tagged union and its fields", () => {
    render(<Harness schema={{ $ref: "#/components/schemas/FeedProviderDef" }} root={openapiRoot} initial={{ trigger: { kind: "cron", cron: "5 * * * *", jitter: "0s", min_interval: "2m" } }} />);
    expect(screen.getByLabelText("Cron")).toHaveValue("5 * * * *");
    expect(screen.queryByLabelText("Queue url")).toBeNull();
  });

  it("switches a union's variant, keeping the fields both share", async () => {
    const user = userEvent.setup();
    const onValue = vi.fn();
    render(<Harness schema={{ $ref: "#/components/schemas/FeedProviderDef" }} root={openapiRoot} initial={{ trigger: { kind: "dynamic", min_interval: "5m" } }} onValue={onValue} />);
    await user.click(screen.getByRole("combobox", { name: "trigger: kind" }));
    await user.click(await screen.findByRole("option", { name: "cron" }));
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ trigger: expect.objectContaining({ kind: "cron", min_interval: "5m", cron: "" }) }));
  });

  it("shows read-only fields as text in edit mode and hides them when creating", () => {
    const value = { id: "hagezi-tif", name: "TIF", provider: "hagezi", file: "adblock/tif.txt", format: "adblock" };
    const { unmount } = render(<Harness schema={{ $ref: "#/components/schemas/FeedDef" }} root={openapiRoot} initial={value} mode="edit" />);
    expect(screen.getByText("adblock/tif.txt")).toBeInTheDocument();
    expect(screen.queryByLabelText("File")).toBeNull();
    unmount();
    render(<Harness schema={{ $ref: "#/components/schemas/FeedDef" }} root={openapiRoot} initial={{}} mode="create" />);
    expect(screen.queryByText("Provider")).toBeNull();
  });

  it("uses overrides for custom widgets, keeping the default available", () => {
    render(
      <Harness
        schema={{ $ref: "#/components/schemas/ProfileDef" }}
        root={openapiRoot}
        initial={{ id: "kids", block: ["block-common"] }}
        overrides={{ block: ({ value }) => <div data-testid="bundle-picker">{(value as string[]).join(",")}</div> }}
      />,
    );
    expect(screen.getByTestId("bundle-picker")).toHaveTextContent("block-common");
  });
});
