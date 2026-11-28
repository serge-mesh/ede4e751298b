import * as React from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { toast } from "sonner";
import { FlaskConicalIcon, MonitorSmartphoneIcon, PlusIcon, TriangleAlertIcon } from "lucide-react";
import { PageHeader, Section } from "@/components/common/page";
import { EntityList } from "@/components/common/entity-list";
import { EntityForm } from "@/components/common/entity-editor";
import { IdSelect, OrderedPicker } from "@/components/common/ordered-picker";
import { CopyField } from "@/components/common/copy-button";
import { Confirm } from "@/components/common/confirm";
import { ErrorState, LoadingState } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useBrowserLists, useEntities, useEntity, useModifyEntity, useSettings } from "@/api/queries";
import { errorMessage } from "@/api/errors";
import type { BundleDef, ListenerDef, LookupProviderDef, ProfileDef } from "@/api/types";
import { ObjectArrayItems, type FieldOverride } from "@/components/schema-form/schema-form";
import { openapiRoot } from "@/lib/openapi";
import { formatCompact } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import type { DataTableColumn } from "@/components/common/data-table";

export function ProfilesPage() {
  const navigate = useNavigate();
  const settings = useSettings();
  const def = settings.data?.settings.default_profile;
  const formProps = useProfileFormProps();
  const columns = React.useMemo<DataTableColumn<ProfileDef>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.name || p.id,
        cell: ({ row }) => (
          <span className="flex items-center gap-2">
            <SafeText>{row.original.name || row.original.id}</SafeText>
            {row.original.id === def && <Badge variant="secondary">default</Badge>}
          </span>
        ),
      },
      { id: "id", header: "Id", accessorFn: (p) => p.id, cell: ({ getValue }) => <Mono>{String(getValue() ?? "")}</Mono> },
      { id: "allow", header: "Allow bundles", accessorFn: (p) => (p.allow ?? []).join(", "), cell: ({ getValue }) => <SafeText mono>{String(getValue())}</SafeText> },
      { id: "block", header: "Block bundles", accessorFn: (p) => (p.block ?? []).join(", "), cell: ({ getValue }) => <SafeText mono>{String(getValue())}</SafeText> },
      {
        id: "trial",
        header: "On trial",
        accessorFn: (p) => (p.trial_bundles ?? []).length,
        cell: ({ getValue }) => (Number(getValue()) ? <Badge variant="outline">{String(getValue())}</Badge> : "—"),
      },
      { id: "upstream", header: "Upstream group", accessorFn: (p) => p.upstream },
      { id: "log", header: "Log", accessorFn: (p) => p.log },
    ],
    [def],
  );
  return (
    <div>
      <PageHeader
        title="Profiles"
        description="The decision recipe for a set of clients. No inheritance: duplicate a profile to start from it."
        actions={
          <Button onClick={() => void navigate({ to: "/profiles/new" })}>
            <PlusIcon /> New profile
          </Button>
        }
      />
      <EntityList
        kind="profiles"
        columns={columns}
        onOpen={(p) => void navigate({ to: "/profiles/$profileId", params: { profileId: p.id ?? "" } })}
        newLabel="New profile (quick)"
        form={formProps}
      />
    </div>
  );
}

function bundleOptions(bundles: BundleDef[] | undefined, actions: string[]) {
  return (bundles ?? [])
    .filter((b) => actions.includes(b.action ?? "block"))
    .map((b) => ({ value: b.id ?? "", label: b.id, hint: b.name && b.name !== b.id ? b.name : undefined }));
}

const LOG_NOTES: Record<string, string> = {
  full: "Every query is logged; core can check them all.",
  blocked:
    "Only blocked queries are logged: allowed queries aren't async-looked-up, DNSSEC-validated, wire-checked or trial-checked, and add nothing to top allowed names. Sync-lookup retries and cold-lookup checks still work.",
  off: "Nothing from this profile reaches core: no attribution, alerts, lookups, DNSSEC checks or trial checks.",
};

/** The profile form's widgets: bundle pickers (ordered by drag), group and zone pickers, notes. */
export function useProfileFormProps() {
  const bundles = useEntities("bundles");
  const groups = useEntities("upstream-groups");
  const zones = useEntities("forward-zones");
  const providers = useEntities("lookup-providers");
  const clients = useEntities("clients");
  const overrides = React.useMemo<Record<string, FieldOverride>>(() => {
    const picker = (actions: string[], ordered: boolean, addLabel: string, empty: string): FieldOverride =>
      function BundlePicker({ value, onChange, disabled, id }) {
        return (
          <OrderedPicker
            id={id}
            ordered={ordered}
            value={(value as string[] | undefined) ?? []}
            onChange={onChange}
            disabled={disabled}
            addLabel={addLabel}
            emptyText={empty}
            options={bundleOptions(bundles.data, actions)}
          />
        );
      };
    return {
      allow: picker(["allow"], true, "Add an allow bundle…", "No allow bundles."),
      block: picker(["block"], true, "Add a block bundle…", "No block bundles."),
      trial_bundles: ({ value, onChange, disabled, id }) => (
        <div className="space-y-1">
          <OrderedPicker
            id={id}
            ordered={false}
            value={(value as string[] | undefined) ?? []}
            onChange={onChange}
            disabled={disabled}
            addLabel="Put a block bundle on trial…"
            emptyText="No bundles on trial."
            options={bundleOptions(bundles.data, ["block"])}
          />
          <p className="text-xs text-muted-foreground">Compiled, never sent to an edge for this profile, and checked against logged queries on core.</p>
        </div>
      ),
      forward_zones: ({ value, onChange, disabled, id }) => (
        <OrderedPicker
          id={id}
          ordered={false}
          value={(value as string[] | undefined) ?? []}
          onChange={onChange}
          disabled={disabled}
          addLabel="Add a forward zone…"
          emptyText="No forward zones."
          options={(zones.data ?? []).map((z) => ({ value: z.id ?? "", label: z.id, hint: z.zone }))}
        />
      ),
      upstream: ({ value, onChange, disabled, id }) => (
        <IdSelect id={id} value={value as string} onChange={(v) => onChange(v ?? "")} disabled={disabled} options={(groups.data ?? []).map((g) => ({ value: g.id ?? "", label: g.name ? `${g.name} (${g.id})` : g.id }))} />
      ),
      alert_lookup_providers: ({ value, onChange, disabled, id }) => (
        <div className="space-y-1.5">
          <IdSelect
            id={`${id}-mode`}
            value={value === null || value === undefined ? "__default" : "__list"}
            onChange={(v) => onChange(v === "__default" ? null : ((value as string[] | null) ?? []))}
            disabled={disabled}
            options={[
              { value: "__default", label: "Every lookup provider whose category is security" },
              { value: "__list", label: "These lookup providers ([] turns them off)" },
            ]}
          />
          {Array.isArray(value) && (
            <OrderedPicker
              id={id}
              ordered={false}
              value={value as string[]}
              onChange={onChange}
              disabled={disabled}
              addLabel="Add a lookup provider…"
              emptyText="None: no lookup provider's Blocks alert."
              options={(providers.data ?? []).map((p) => ({ value: p.id ?? "", label: p.id, hint: p.category }))}
            />
          )}
        </div>
      ),
      lookup_providers: ({ c, id, path, value, onChange, disabled }) => {
        const byId = new Map<string, LookupProviderDef>((providers.data ?? []).map((p) => [p.id ?? "", p]));
        return (
          <ObjectArrayItems
            c={c}
            id={id}
            path={path}
            items={Array.isArray(value) ? value : []}
            onChange={onChange}
            disabled={disabled}
            depth={2}
            root={openapiRoot}
            emptyText="No lookup providers attached."
            addLabel="Add a lookup provider"
            removeLabel={(i) => `Remove lookup provider ${i + 1}`}
            heading={(item, i) => {
              const provider = (item as { provider?: unknown } | null)?.provider;
              const pid = typeof provider === "string" ? provider : "";
              if (!pid) return <span className="tabular-nums">Lookup provider #{i + 1}</span>;
              const lp = byId.get(pid);
              return (
                <>
                  <span className="tabular-nums">#{i + 1}</span>
                  <span className="truncate text-foreground">
                    <SafeText>{lp?.name ? `${lp.name} (${lp.id})` : pid}</SafeText>
                  </span>
                </>
              );
            }}
          />
        );
      },
      allowed_sources: ({ renderDefault }) => (
        <div className="space-y-1">
          {renderDefault()}
          <p className="text-xs text-muted-foreground">
            Address ranges, MACs and client names{clients.data?.length ? ` (clients: ${clients.data.slice(0, 5).map((c) => escapeControl(c.name ?? "")).join(", ")}${clients.data.length > 5 ? ", …" : ""})` : ""}. A profile that doesn't admit
            a client is skipped during assignment, and refused when the DoH path or DoT name names it.
          </p>
        </div>
      ),
      log: ({ renderDefault, value }) => (
        <div className="space-y-1">
          {renderDefault()}
          <p className="text-xs text-muted-foreground">{LOG_NOTES[String(value)] ?? ""}</p>
        </div>
      ),
      "block_response.type": ({ renderDefault, value }) => (
        <div className="space-y-2">
          {renderDefault()}
          {value === "custom_ip" && (
            <Alert variant="warning">
              <TriangleAlertIcon />
              <AlertTitle>Custom block page</AlertTitle>
              <AlertDescription>
                Under firewall enforce, clients reach the block-page host only if it is on their own subnet or in the edge's static_allow, because block answers open no
                firewall entries. Clients with the browser extension still get its block page when the custom page fails to load (as over HTTPS).
              </AlertDescription>
            </Alert>
          )}
        </div>
      ),
    };
  }, [bundles.data, groups.data, zones.data, providers.data, clients.data]);
  // Lookup attachments: provider and bundle pickers inside each array item.
  const withLookups = React.useMemo<Record<string, FieldOverride>>(() => {
    const out: Record<string, FieldOverride> = { ...overrides };
    for (let i = 0; i < 32; i++) {
      out[`lookup_providers.${i}.provider`] = ({ value, onChange, disabled, id }) => (
        <IdSelect id={id} value={value as string} onChange={(v) => onChange(v ?? "")} disabled={disabled} options={(providers.data ?? []).map((p) => ({ value: p.id ?? "", label: p.name ? `${p.name} (${p.id})` : p.id, hint: p.module }))} />
      );
      for (const k of ["include_bundles", "exclude_bundles"]) {
        out[`lookup_providers.${i}.${k}`] = ({ value, onChange, disabled, id }) => (
          <OrderedPicker
            id={id}
            ordered={false}
            value={(value as string[] | undefined) ?? []}
            onChange={onChange}
            disabled={disabled}
            addLabel="Add a bundle…"
            emptyText="None."
            options={(bundles.data ?? []).map((b) => ({ value: b.id ?? "", label: b.id, hint: b.action }))}
          />
        );
      }
    }
    return out;
  }, [overrides, providers.data, bundles.data]);
  const labels = React.useMemo<Record<string, string>>(() => {
    const out: Record<string, string> = {
      allow: "Allow bundles (in order)",
      block: "Block bundles (in order)",
      trial_bundles: "Trial bundles",
      lookup_providers: "Lookup providers",
      sync_lookup_budget_ms: "Sync lookup budget (ms)",
      alert_lookup_providers: "Alert lookup providers",
    };
    for (let i = 0; i < 32; i++) {
      out[`lookup_providers.${i}.provider`] = "Provider";
      out[`lookup_providers.${i}.mode`] = "Mode";
      out[`lookup_providers.${i}.include_bundles`] = "Only for these bundles";
      out[`lookup_providers.${i}.exclude_bundles`] = "Except these bundles";
    }
    return out;
  }, []);
  return {
    overrides: withLookups,
    order: ["allowed_sources", "upstream", "log", "allow", "block", "trial_bundles", "lookup_providers", "sync_lookup_budget_ms"],
    labels,
  };
}

export function NewProfilePage() {
  const navigate = useNavigate();
  const props = useProfileFormProps();
  return (
    <div>
      <PageHeader title="New profile" description="Its id is a DNS label that never changes: it appears in DoH URLs and DoT names." />
      <Section>
        <EntityForm
          kind="profiles"
          {...props}
          onSaved={(o) => void navigate({ to: "/profiles/$profileId", params: { profileId: o.id } })}
          onCancel={() => void navigate({ to: "/profiles" })}
        />
      </Section>
    </div>
  );
}

/** The host clients use for a listener: its managed TLS name, else its first address. */
function listenerHost(l: ListenerDef): string | null {
  if (l.tls?.managed) return l.tls.managed;
  const ip = l.ips?.[0] ?? l.bind?.replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
  if (!ip || ip === "::" || ip === "0.0.0.0") return null;
  return ip.includes(":") ? `[${ip}]` : ip;
}

function port(bind: string | undefined): string | null {
  const m = /:(\d+)$/.exec(bind ?? "");
  return m ? m[1] : null;
}

/** DoH URLs (`/dns-query/<profile id>`) and DoT names (`<profile id>.<tls name>`). */
export function profileEndpoints(profileId: string, listeners: ListenerDef[]): { kind: "doh" | "dot"; value: string; listener: string }[] {
  const out: { kind: "doh" | "dot"; value: string; listener: string }[] = [];
  for (const l of listeners) {
    if (!(l.edges ?? []).length) continue;
    const host = listenerHost(l);
    if (!host) continue;
    if (l.proto === "doh") {
      const p = port(l.bind);
      out.push({ kind: "doh", value: `https://${host}${p && p !== "443" ? `:${p}` : ""}/dns-query/${profileId}`, listener: l.name || l.id || "" });
    } else if (l.proto === "dot" && l.tls?.managed) {
      out.push({ kind: "dot", value: `${profileId}.${l.tls.managed}`, listener: l.name || l.id || "" });
    }
  }
  return out;
}

/**
 * Enforce (core.md §12): moves a bundle from `trial_bundles` to the end of the block list, on the
 * profile as stored now; null when it isn't on trial any more.
 */
export function enforceTrial(p: ProfileDef, bundle: string): ProfileDef | null {
  if (!(p.trial_bundles ?? []).includes(bundle)) return null;
  return { ...p, trial_bundles: (p.trial_bundles ?? []).filter((b) => b !== bundle), block: [...(p.block ?? []).filter((b) => b !== bundle), bundle] };
}

export function ProfileDetailPage() {
  const { profileId } = useParams({ strict: false }) as { profileId: string };
  const navigate = useNavigate();
  const profile = useEntity("profiles", profileId);
  const listeners = useEntities("listeners");
  const lists = useBrowserLists();
  const save = useModifyEntity("profiles");
  const props = useProfileFormProps();
  // Once loaded, a failed refetch keeps the page (and the entity form's draft) mounted; the form says so (core.md §12).
  if (profile.data === undefined) return profile.error ? <ErrorState error={profile.error} onRetry={() => void profile.refetch()} /> : <LoadingState rows={8} />;
  const p = profile.data;
  const endpoints = profileEndpoints(p.id ?? "", listeners.data ?? []);
  const pruned = lists.data?.find((l) => l.kind === "profile" && l.target === p.id);
  const full = lists.data?.find((l) => l.kind === "profile_full" && l.target === p.id);
  const enforce = (bundle: string) =>
    save.mutate(
      { id: p.id ?? "", change: (cur) => enforceTrial(cur, bundle) },
      { onSuccess: () => toast.success(`${escapeControl(bundle)} now enforced: last in the block list`), onError: (e) => toast.error(errorMessage(e)) },
    );
  return (
    <div className="space-y-4">
      <PageHeader
        title={<SafeText>{p.name || p.id}</SafeText>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            id <Mono>{p.id}</Mono> {p.system && <Badge variant="outline">system</Badge>}
            <Link to="/clients/profile/$profileId" params={{ profileId: p.id ?? "" }} className="inline-flex items-center gap-1 text-primary hover:underline">
              <MonitorSmartphoneIcon className="size-3.5" /> Its devices
            </Link>
          </span>
        }
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="DoH URLs and DoT names" description="A client that uses one of these is assigned this profile, if allowed_sources admits it.">
          {endpoints.length === 0 ? (
            <p className="text-sm text-muted-foreground">No assigned DoH listener, or DoT listener with a managed TLS name.</p>
          ) : (
            <ul className="space-y-1.5">
              {endpoints.map((e) => (
                <li key={e.value} className="flex flex-wrap items-center gap-2 text-sm">
                  <Badge variant="outline">{e.kind === "doh" ? "DoH" : "DoT"}</Badge>
                  <CopyField value={e.value} label={e.kind === "doh" ? "Copy DoH URL" : "Copy DoT name"} />
                  <span className="text-xs text-muted-foreground">
                    <SafeText>{e.listener}</SafeText>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
        <Section title="Browser lists" description="Turn on browser_list below to publish them. The pruned list leaves out the browser rules DNS already makes useless; the full one has all of them.">
          {!p.browser_list?.enabled ? (
            <p className="text-sm text-muted-foreground">Off for this profile.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {[
                ["Pruned", pruned],
                ["Full", full],
              ].map(([label, l]) =>
                l && typeof l === "object" ? (
                  <li key={String(label)} className="space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="w-14 text-muted-foreground">{String(label)}</span>
                      <CopyField value={`${window.location.origin}${l.url}`} label={`Copy the ${String(label).toLowerCase()} list URL`} />
                    </div>
                    <ListCounts stats={l.stats} />
                  </li>
                ) : (
                  <li key={String(label)} className="text-muted-foreground">
                    {String(label)}: not written yet
                  </li>
                ),
              )}
            </ul>
          )}
        </Section>
      </div>
      {(p.trial_bundles ?? []).length > 0 && (
        <Section title="Trial bundles" description="Checked against logged queries on core only. Enforce moves a bundle to the end of the block list, as a normal config change.">
          <ul className="space-y-2">
            {(p.trial_bundles ?? []).map((b) => (
              <li key={b} className="flex flex-wrap items-center gap-2">
                <FlaskConicalIcon className="size-4 text-muted-foreground" aria-hidden />
                <Link to="/profiles/$profileId/trial/$bundleId" params={{ profileId: p.id ?? "", bundleId: b }} className="font-mono text-sm hover:underline">
                  {escapeControl(b)}
                </Link>
                <Confirm title={`Enforce ${escapeControl(b)}?`} description="It leaves the trial list and goes last in the block list; edges receive it with the next config." confirmLabel="Enforce" onConfirm={() => enforce(b)}>
                  <Button size="sm" variant="outline" disabled={save.isPending}>
                    Enforce
                  </Button>
                </Confirm>
              </li>
            ))}
          </ul>
        </Section>
      )}
      <Section title="Profile settings" description="Every profile field. Hover the info icons for what each does.">
        <EntityForm kind="profiles" id={profileId} {...props} onDeleted={() => void navigate({ to: "/profiles" })} deleteDescription="Clients that name it lose their profile choice." />
      </Section>
    </div>
  );
}

function ListCounts({ stats }: { stats: unknown }) {
  if (!stats || typeof stats !== "object") return null;
  const entries = Object.entries(stats as Record<string, unknown>).filter(([, v]) => typeof v === "number");
  if (entries.length === 0) return null;
  return (
    <div className="pl-16 text-xs text-muted-foreground">
      {entries.map(([k, v]) => `${escapeControl(k)}: ${formatCompact(v as number)}`).join(" · ")}
    </div>
  );
}
