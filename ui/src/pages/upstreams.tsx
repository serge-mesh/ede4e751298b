import * as React from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { PageHeader } from "@/components/common/page";
import { EntityList } from "@/components/common/entity-list";
import { IdSelect, OrderedPicker } from "@/components/common/ordered-picker";
import { Mono, SafeText } from "@/components/common/text";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useEntities } from "@/api/queries";
import type { ForwardZoneDef, UpstreamDef, UpstreamGroupDef } from "@/api/types";
import type { FieldOverride } from "@/components/schema-form/schema-form";
import type { DataTableColumn } from "@/components/common/data-table";

const PLAIN = new Set(["udp", "tcp"]);

export function UpstreamsPage() {
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const upstreams = useEntities("upstreams");
  const groups = useEntities("upstream-groups");
  const upstreamById = React.useMemo(() => new Map((upstreams.data ?? []).map((u) => [u.id ?? "", u])), [upstreams.data]);

  const upstreamCols = React.useMemo<DataTableColumn<UpstreamDef>[]>(
    () => [
      { id: "name", header: "Name", accessorFn: (u) => u.name || u.id, cell: ({ row }) => <SafeText>{row.original.name || row.original.id}</SafeText> },
      { id: "id", header: "Id", accessorFn: (u) => u.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "protocol", header: "Protocol", accessorFn: (u) => u.protocol, cell: ({ getValue }) => <Badge variant={PLAIN.has(String(getValue())) ? "outline" : "secondary"}>{String(getValue())}</Badge> },
      { id: "endpoint", header: "Endpoint", accessorFn: (u) => `${u.ip}:${u.port}`, cell: ({ getValue }) => <Mono>{String(getValue())}</Mono> },
      { id: "tls", header: "TLS name", accessorFn: (u) => u.tls_host ?? "", cell: ({ getValue }) => <SafeText mono>{String(getValue())}</SafeText> },
      { id: "operator", header: "Operator", accessorFn: (u) => u.operator ?? "", cell: ({ getValue }) => <SafeText>{String(getValue())}</SafeText> },
    ],
    [],
  );
  const groupCols = React.useMemo<DataTableColumn<UpstreamGroupDef>[]>(
    () => [
      { id: "name", header: "Name", accessorFn: (g) => g.name || g.id, cell: ({ row }) => <SafeText>{row.original.name || row.original.id}</SafeText> },
      { id: "id", header: "Id", accessorFn: (g) => g.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "strategy", header: "Strategy", accessorFn: (g) => g.strategy },
      { id: "upstreams", header: "Upstreams", accessorFn: (g) => (g.upstreams ?? []).join(", "), cell: ({ getValue }) => <SafeText mono>{String(getValue())}</SafeText> },
      {
        id: "kind",
        header: "Transport",
        accessorFn: (g) => {
          const kinds = new Set((g.upstreams ?? []).map((u) => (PLAIN.has(upstreamById.get(u)?.protocol ?? "") ? "plain" : "encrypted")));
          return kinds.size > 1 ? "mixed" : ([...kinds][0] ?? "—");
        },
        cell: ({ getValue }) => (getValue() === "mixed" ? <Badge variant="destructive">mixed (refused)</Badge> : String(getValue())),
      },
    ],
    [upstreamById],
  );
  const zoneCols = React.useMemo<DataTableColumn<ForwardZoneDef>[]>(
    () => [
      { id: "zone", header: "Zone", accessorFn: (z) => z.zone, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "id", header: "Id", accessorFn: (z) => z.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "group", header: "Upstream group", accessorFn: (z) => z.group },
      { id: "fallback", header: "When the group is down", accessorFn: (z) => (z.fallback === "default" ? "the profile's group" : "SERVFAIL") },
    ],
    [],
  );
  const groupOverrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      upstreams: ({ value, onChange, disabled, id }) => {
        const v = (value as string[] | undefined) ?? [];
        const kinds = new Set(v.map((u) => (PLAIN.has(upstreamById.get(u)?.protocol ?? "") ? "plain" : "encrypted")));
        return (
          <div className="space-y-1">
            <OrderedPicker
              id={id}
              value={v}
              onChange={onChange}
              disabled={disabled}
              addLabel="Add an upstream…"
              options={(upstreams.data ?? []).map((u) => ({ value: u.id ?? "", label: u.name || u.id, hint: `${u.protocol} ${u.ip}` }))}
            />
            {kinds.size > 1 && <p className="text-xs text-destructive">A group's upstreams must be all plain (udp, tcp) or all encrypted (DoT, DoH): a plain group keeps the client's DO.</p>}
          </div>
        );
      },
    }),
    [upstreams.data, upstreamById],
  );
  const zoneOverrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      group: ({ value, onChange, disabled, id }) => (
        <IdSelect id={id} value={value as string} onChange={(v) => onChange(v ?? "")} disabled={disabled} options={(groups.data ?? []).map((g) => ({ value: g.id ?? "", label: g.name || g.id }))} />
      ),
    }),
    [groups.data],
  );
  const upstreamOverrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      protocol: ({ renderDefault, value }) => (
        <div className="space-y-1">
          {renderDefault()}
          {PLAIN.has(String(value)) && <p className="text-xs text-muted-foreground">Plain upstreams must be private or loopback addresses.</p>}
        </div>
      ),
    }),
    [],
  );
  const tab = search.tab ?? "upstreams";
  return (
    <div>
      <PageHeader title="Upstreams and forward zones" description="Upstreams are configured by IP plus TLS name, so they are never resolved. Forward zones route a DNS zone to its own group." />
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: { tab: t }, replace: true })}>
        <TabsList>
          <TabsTrigger value="upstreams">Upstreams</TabsTrigger>
          <TabsTrigger value="groups">Upstream groups</TabsTrigger>
          <TabsTrigger value="zones">Forward zones</TabsTrigger>
        </TabsList>
        <TabsContent value="upstreams">
          <EntityList kind="upstreams" columns={upstreamCols} form={{ overrides: upstreamOverrides, order: ["protocol", "ip", "port", "tls_host", "operator"] }} />
        </TabsContent>
        <TabsContent value="groups">
          <EntityList kind="upstream-groups" columns={groupCols} form={{ overrides: groupOverrides, order: ["strategy", "upstreams"] }} />
        </TabsContent>
        <TabsContent value="zones">
          <EntityList
            kind="forward-zones"
            columns={zoneCols}
            form={{ overrides: zoneOverrides, order: ["zone", "group", "fallback"] }}
            description="A profile lists the zones it uses; their names skip bundles, lookups and response checks."
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
