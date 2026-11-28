import * as React from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { PageHeader } from "@/components/common/page";
import { EntityList } from "@/components/common/entity-list";
import { IdSelect } from "@/components/common/ordered-picker";
import { CopyButton } from "@/components/common/copy-button";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { Badge } from "@/components/ui/badge";
import { useBundleStatuses, useEntities } from "@/api/queries";
import type { BundleDef, BundleStatus } from "@/api/types";
import type { FieldOverride } from "@/components/schema-form/schema-form";
import type { DataTableColumn } from "@/components/common/data-table";

/** Bundle form widgets: feed pickers; tier and hot_max_mib only for block bundles. */
export function useBundleFormProps(action?: string) {
  const feeds = useEntities("feeds");
  const overrides = React.useMemo<Record<string, FieldOverride>>(() => {
    const out: Record<string, FieldOverride> = {};
    for (let i = 0; i < 256; i++) {
      out[`feeds.${i}.feed`] = ({ value, onChange, disabled, id }) => (
        <IdSelect
          id={id}
          value={value as string}
          onChange={(v) => onChange(v ?? "")}
          disabled={disabled}
          options={(feeds.data ?? []).map((f) => ({ value: f.id ?? "", label: f.name && f.name !== f.id ? `${f.id} (${f.name})` : f.id }))}
        />
      );
      if (action && action !== "block") out[`feeds.${i}.tier`] = () => <p className="text-xs text-muted-foreground">Block bundles only.</p>;
    }
    if (action && action !== "block") out.hot_max_mib = () => <p className="text-xs text-muted-foreground">Block bundles only.</p>;
    return out;
  }, [feeds.data, action]);
  return { overrides, order: ["action", "feeds", "max_shard_keys", "hot_max_mib"] };
}

export function BundlesPage() {
  const navigate = useNavigate();
  const statuses = useBundleStatuses();
  const byId = React.useMemo(() => new Map((statuses.data ?? []).map((s) => [s.bundle, s])), [statuses.data]);
  const form = useBundleFormProps();
  const columns = React.useMemo<DataTableColumn<BundleDef>[]>(
    () => [
      {
        id: "id",
        header: "Bundle",
        accessorFn: (b) => b.id,
        cell: ({ row }) => (
          <span className="flex flex-col">
            <Link to="/bundles/$bundleId" params={{ bundleId: row.original.id ?? "" }} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
              <Mono>{row.original.id}</Mono>
            </Link>
            {row.original.name && row.original.name !== row.original.id && (
              <span className="text-xs text-muted-foreground">
                <SafeText>{row.original.name}</SafeText>
              </span>
            )}
          </span>
        ),
      },
      { id: "action", header: "Action", accessorFn: (b) => b.action, cell: ({ getValue }) => <Badge variant="outline">{String(getValue() ?? "block")}</Badge> },
      { id: "feeds", header: "Feeds", accessorFn: (b) => (b.feeds ?? []).length },
      {
        id: "status",
        header: "Build",
        accessorFn: (b) => byId.get(b.id ?? "")?.status ?? "",
        cell: ({ row }) => <BuildBadge s={byId.get(row.original.id ?? "")} />,
      },
      { id: "built", header: "Built", accessorFn: (b) => byId.get(b.id ?? "")?.built_at ?? "", cell: ({ row }) => <TimeAgo value={byId.get(row.original.id ?? "")?.built_at} /> },
      {
        id: "alerts",
        header: "Open alerts",
        accessorFn: (b) => byId.get(b.id ?? "")?.open_alerts ?? 0,
        cell: ({ getValue }) => (Number(getValue()) ? <Badge variant="warning">{String(getValue())}</Badge> : "—"),
      },
      {
        id: "list",
        header: "Browser list",
        enableSorting: false,
        accessorFn: (b) => byId.get(b.id ?? "")?.browser_list ?? "",
        cell: ({ row }) => {
          const url = byId.get(row.original.id ?? "")?.browser_list;
          return url ? (
            <span className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
              <Mono className="text-xs">{url}</Mono>
              <CopyButton value={`${window.location.origin}${url}`} label="Copy the browser-list URL" />
            </span>
          ) : (
            "—"
          );
        },
      },
    ],
    [byId],
  );
  return (
    <div>
      <PageHeader
        title="Bundles"
        description="Named, versioned rule sets built from chosen feeds. dns and ip rules compile into edge bundles, browser rules into hosted browser lists."
      />
      <EntityList kind="bundles" columns={columns} form={form} onOpen={(b) => void navigate({ to: "/bundles/$bundleId", params: { bundleId: b.id ?? "" } })} newLabel="New bundle" />
    </div>
  );
}

export function BuildBadge({ s }: { s?: BundleStatus }) {
  if (!s) return <span className="text-muted-foreground">—</span>;
  if (s.building) return <Badge variant="secondary">building</Badge>;
  if (s.status === "failed") return <Badge variant="destructive">failed</Badge>;
  if (s.status === "never") return <Badge variant="outline">not built</Badge>;
  return <Badge variant="success">ok</Badge>;
}
