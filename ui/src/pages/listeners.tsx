import * as React from "react";
import { PageHeader } from "@/components/common/page";
import { EntityList } from "@/components/common/entity-list";
import { OrderedPicker } from "@/components/common/ordered-picker";
import { Mono, SafeText } from "@/components/common/text";
import { Badge } from "@/components/ui/badge";
import { useEdges, useIdentity } from "@/api/queries";
import type { ListenerDef } from "@/api/types";
import type { FieldOverride } from "@/components/schema-form/schema-form";
import type { DataTableColumn } from "@/components/common/data-table";

function tlsText(l: ListenerDef): string {
  if (!l.tls) return l.proto === "dns" ? "—" : "none";
  if (l.tls.managed) return `managed: ${l.tls.managed}`;
  if (l.tls.cert_file) return `files: ${l.tls.cert_file}`;
  return "—";
}

export function ListenersPage() {
  const edges = useEdges();
  const identity = useIdentity();
  const edgeName = React.useMemo(() => new Map((edges.data ?? []).map((e) => [e.id ?? "", e.name || e.id || ""])), [edges.data]);
  const columns = React.useMemo<DataTableColumn<ListenerDef>[]>(
    () => [
      { id: "name", header: "Name", accessorFn: (l) => l.name || l.id, cell: ({ row }) => <SafeText>{row.original.name || row.original.id}</SafeText> },
      { id: "proto", header: "Protocol", accessorFn: (l) => l.proto, cell: ({ getValue }) => <Badge variant="outline">{String(getValue())}</Badge> },
      { id: "bind", header: "Bind", accessorFn: (l) => l.bind, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "tls", header: "TLS", accessorFn: tlsText, cell: ({ getValue }) => <SafeText mono>{String(getValue())}</SafeText> },
      { id: "api", header: "Bypass API", accessorFn: (l) => (l.api ? "on" : "off") },
      {
        id: "edges",
        header: "Edges",
        accessorFn: (l) => (l.edges ?? []).map((e) => edgeName.get(e) ?? e).join(", "),
        cell: ({ row }) =>
          (row.original.edges ?? []).length === 0 ? (
            <span className="text-muted-foreground">none</span>
          ) : (
            <span className="flex flex-wrap gap-1">
              {(row.original.edges ?? []).map((e) => (
                <Badge key={e} variant="secondary">
                  <SafeText>{edgeName.get(e) ?? e}</SafeText>
                </Badge>
              ))}
            </span>
          ),
      },
    ],
    [edgeName],
  );
  const overrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      edges: ({ value, onChange, disabled, id }) => (
        <OrderedPicker
          id={id}
          ordered={false}
          value={(value as string[] | undefined) ?? []}
          onChange={onChange}
          disabled={disabled}
          addLabel="Assign to an edge…"
          emptyText="Not assigned to any edge."
          options={(edges.data ?? []).map((e) => ({ value: e.id ?? "", label: e.name || e.id }))}
        />
      ),
      tls: ({ renderDefault }) => (
        <div className="space-y-1">
          {renderDefault()}
          <p className="text-xs text-muted-foreground">
            A managed name must be under the LAN CA's zones ({(identity.data?.lanca_zones ?? ["home.arpa"]).join(", ")}); others are refused on save.
          </p>
        </div>
      ),
    }),
    [edges.data, identity.data],
  );
  return (
    <div>
      <PageHeader
        title="Listeners"
        description="Inbound endpoints (DNS over UDP and TCP, DoT, DoH) assigned to edges. A listener has no profile of its own: the DoH path, DoT name, client list and default profile pick one."
      />
      <EntityList kind="listeners" columns={columns} form={{ overrides, order: ["proto", "bind", "edges"] }} empty="No listeners yet." />
    </div>
  );
}
