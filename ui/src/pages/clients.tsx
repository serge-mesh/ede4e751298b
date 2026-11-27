import * as React from "react";
import { Link, useParams, useSearch } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowDownIcon, ArrowUpIcon, GripVerticalIcon, PencilIcon, PlusIcon, UserPlusIcon } from "lucide-react";
import { PageHeader, Section, Stat } from "@/components/common/page";
import { QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { EntityForm } from "@/components/common/entity-editor";
import { DraftScope, useDiscardGuard } from "@/components/common/drafts";
import { IdSelect } from "@/components/common/ordered-picker";
import { TagInput } from "@/components/common/tag-input";
import { EdgeSelector, WindowPicker } from "@/components/common/window-picker";
import { TimeSeriesChart } from "@/components/charts/time-series";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { qk, useEntities, useSaveSettings, useSettings } from "@/api/queries";
import { client, request, unwrap } from "@/api/http";
import { errorMessage } from "@/api/errors";
import type { ChartLine, ClientDef, SeenDevice, Window } from "@/api/types";
import type { FieldOverride } from "@/components/schema-form/schema-form";
import { formatCompact, formatPercent } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import type { DeviceSearch } from "@/lib/search";
import { useWindowState } from "./dashboard";
import { AllowStateBadge } from "./temporary-allows";

/** UniFi's wording for a private (locally administered) MAC (core.md §12). */
export const PRIVATE_MAC_TEXT =
  "This device uses a private MAC address. Profile, allow and firewall settings may not stay assigned if the address changes.";

export function normalizeMac(mac: string): string | null {
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, "");
  if (hex.length !== 12) return null;
  return hex.match(/../g)!.join(":");
}

/** A locally administered MAC: bit 0x02 of the first byte. */
export function isPrivateMac(mac: string): boolean {
  const m = normalizeMac(mac);
  if (!m) return false;
  return (parseInt(m.slice(0, 2), 16) & 0x02) !== 0;
}

/** Hyper-V's prefix `00:15:5d`: a virtual adapter of the host or a VM. */
export function isHyperVMac(mac: string): boolean {
  return normalizeMac(mac)?.startsWith("00:15:5d") ?? false;
}

export function MacBadges({ mac }: { mac: string }) {
  return (
    <>
      {isPrivateMac(mac) && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="warning" tabIndex={0}>
              private MAC
            </Badge>
          </TooltipTrigger>
          <TooltipContent>{PRIVATE_MAC_TEXT}</TooltipContent>
        </Tooltip>
      )}
      {isHyperVMac(mac) && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" tabIndex={0}>
              Hyper-V
            </Badge>
          </TooltipTrigger>
          <TooltipContent>A Hyper-V virtual adapter, of the host or a VM.</TooltipContent>
        </Tooltip>
      )}
    </>
  );
}

export function MacList({ macs }: { macs: string[] }) {
  if (macs.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-col gap-0.5">
      {macs.map((m) => (
        <span key={m} className="flex flex-wrap items-center gap-1">
          <SafeText mono>{m}</SafeText>
          <MacBadges mac={m} />
        </span>
      ))}
    </span>
  );
}

/** What core says a MAC in a device's `macs` that isn't its own is (logs/query.rs `Device`, core c58ba80). */
export const SEEN_AT_ADDRESS_TEXT =
  "Logged at this device's address, by the edge that saw it last: maybe another device's (a shared address, or one handed on by DHCP), so it isn't taken as this device's MAC.";

/**
 * A seen device's MACs (core 07acc1c `Device`: only MACs core currently knows): its own (`mac`:
 * the key when it is a MAC; for a device keyed by a client name, the first of the MACs of the
 * client entry with that name now) with the private-MAC and Hyper-V marks. `mac` is null for a
 * device keyed by a client name no entry has now or whose entry lists no MACs (no `macs` either:
 * nothing is inferred), and for an address-keyed device, whose `macs` are only what was logged at
 * its address, which may be another device's: they show as such, without the marks that would
 * speak for this device.
 */
export function DeviceMacs({ device }: { device: Pick<SeenDevice, "mac" | "macs"> }) {
  if (device.mac !== null && device.mac !== undefined) return <MacList macs={device.macs} />;
  if (device.macs.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-col gap-0.5">
      {device.macs.map((m) => (
        <span key={m} className="flex flex-wrap items-center gap-1">
          <SafeText mono className="text-muted-foreground">
            {m}
          </SafeText>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="outline" tabIndex={0}>
                seen at its address
              </Badge>
            </TooltipTrigger>
            <TooltipContent>{SEEN_AT_ADDRESS_TEXT}</TooltipContent>
          </Tooltip>
        </span>
      ))}
    </span>
  );
}

/** An IP address as a device key (logs/query.rs: a device the edges key by its address). */
const isAddressKey = (key: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(key) || (key.includes(":") && /^[0-9a-f:.]+$/i.test(key));

/**
 * "Add as client" for a seen device (only those no client names): by its MAC when the edges keyed
 * it by that MAC, else by its addresses. Never by a MAC logged at the device's address (an
 * address-keyed device's `macs`): it may be another device's, and a client entry's MACs are
 * authoritative, so pinning it would move that other device into the new client. A device keyed
 * by a client name no entry has now (core 07acc1c: no `mac`, nothing inferred) is offered under
 * that name, so its history goes on under it.
 */
export function newClientOf(dev: SeenDevice): Partial<ClientDef> {
  const own = normalizeMac(dev.key);
  const formerName = !own && !isAddressKey(dev.key) && !dev.addresses.includes(dev.key) ? dev.key : "";
  const name = dev.name ?? dev.dhcp_name ?? dev.ptr ?? formerName;
  return own && dev.mac === own ? { name, macs: [own], source_ips: [] } : { name, macs: [], source_ips: dev.addresses };
}

/** `GET query-summary` (logs/query.rs `Summary`): a device's view (`device`) or a profile's (`profile`). */
function useQuerySummary(subject: { device: string } | { profile: string }, window: Window, edge: string) {
  return useQuery({
    queryKey: [...qk.querySummary, subject, window, edge],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/query-summary", { params: { query: { ...subject, window, edge } }, signal })),
    enabled: Object.values(subject)[0] !== "",
  });
}

export function ClientsPage() {
  const clients = useEntities("clients");
  const profiles = useEntities("profiles");
  const devices = useQuery({ queryKey: ["devices"], queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/devices", { signal })) });
  const [editing, setEditing] = React.useState<{ id?: string; initial?: Partial<ClientDef> } | null>(null);
  // Escape, a click outside or the close button ask first while the form holds unsaved changes.
  const guard = useDiscardGuard(() => setEditing(null));
  const profileOptions = React.useMemo(() => (profiles.data ?? []).map((p) => ({ value: p.id ?? "", label: p.name ? `${p.name} (${p.id})` : p.id })), [profiles.data]);
  const overrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      profile: ({ value, onChange, disabled, id }) => (
        <IdSelect id={id} value={value as string | null} onChange={onChange} nullable noneLabel="None: only names its devices" options={profileOptions} disabled={disabled} />
      ),
      macs: ({ value, onChange, disabled, id }) => {
        const macs = (value as string[] | undefined) ?? [];
        const bad = macs.filter((m) => !normalizeMac(m));
        return (
          <div className="space-y-1.5">
            <TagInput id={id} value={macs} onChange={(v) => onChange(v.map((m) => normalizeMac(m) ?? m))} disabled={disabled} placeholder="aa:bb:cc:dd:ee:ff" invalid={bad.length > 0} />
            {bad.length > 0 && <p className="text-xs text-destructive">Not a MAC address: {bad.map(escapeControl).join(", ")}</p>}
            {macs.some(isPrivateMac) && <p className="text-xs text-warning">{PRIVATE_MAC_TEXT}</p>}
            {macs.some(isHyperVMac) && <p className="text-xs text-muted-foreground">00:15:5d is Hyper-V's prefix: a virtual adapter of the host or a VM.</p>}
          </div>
        );
      },
    }),
    [profileOptions],
  );
  return (
    <div className="space-y-5">
      <PageHeader
        title="Clients"
        description="A client names a device by its MACs or source ranges, and may pick its profile. The list is checked in order: by MAC, then by source range."
        actions={
          <Button onClick={() => setEditing({})}>
            <PlusIcon /> New client
          </Button>
        }
      />
      <DefaultProfile />
      <Section title="Clients list">
        <QueryView query={clients} rows={5}>
          {(list) => <ClientTable clients={list} onEdit={(id) => setEditing({ id })} />}
        </QueryView>
      </Section>
      <Section
        title="Devices the edges have seen"
        description="From the logged queries of the retention window: each device by its client name, else its MAC, else its address, with the addresses it used. Core doesn't learn PTR or DHCP host names yet, so a device no client names shows its MAC or address."
      >
        <QueryView query={devices} what="Seen devices" rows={4} empty={<p className="text-sm text-muted-foreground">No devices seen yet.</p>} isEmpty={(d) => d.items.length === 0}>
          {(d) => (
            <DeviceTable devices={d.items} onAdd={(dev) => setEditing({ initial: newClientOf(dev) })} />
          )}
        </QueryView>
      </Section>
      <Sheet open={!!editing} onOpenChange={(o) => !o && guard.requestClose()}>
        <SheetContent className="sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>{editing?.id ? `Edit client ${escapeControl(editing.id)}` : "New client"}</SheetTitle>
            <SheetDescription>$client rules match its name, $ctag rules its tags.</SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing && (
              <DraftScope onDirty={guard.onDirty}>
                <EntityForm
                  key={editing.id ?? "new"}
                  kind="clients"
                  id={editing.id}
                  initial={editing.initial}
                  overrides={overrides}
                  hidden={["position"]}
                  order={["macs", "source_ips", "profile", "tags"]}
                  onSaved={() => setEditing(null)}
                  onDeleted={() => setEditing(null)}
                  onCancel={() => setEditing(null)}
                />
              </DraftScope>
            )}
          </div>
        </SheetContent>
      </Sheet>
      {guard.dialog}
    </div>
  );
}

function DefaultProfile() {
  const settings = useSettings();
  const profiles = useEntities("profiles");
  const save = useSaveSettings();
  const current = settings.data?.settings.default_profile ?? null;
  return (
    <Section title="Default profile" description="For devices no DoH path, DoT name or client entry assigns. With none, such queries are refused.">
      <div className="max-w-sm space-y-1.5">
        <Label htmlFor="default-profile" className="sr-only">
          Default profile
        </Label>
        <IdSelect
          id="default-profile"
          value={current}
          nullable
          noneLabel="None (refuse)"
          disabled={save.isPending || settings.isPending}
          options={(profiles.data ?? []).map((p) => ({ value: p.id ?? "", label: p.name ? `${p.name} (${p.id})` : p.id }))}
          onChange={(v) =>
            save.mutate({ patch: { default_profile: v } }, { onSuccess: () => toast.success("Default profile saved"), onError: (e) => toast.error(errorMessage(e)) })
          }
        />
      </div>
    </Section>
  );
}

function ClientTable({ clients, onEdit }: { clients: ClientDef[]; onEdit: (name: string) => void }) {
  const qc = useQueryClient();
  const [drag, setDrag] = React.useState<number | null>(null);
  const reorder = async (from: number, to: number) => {
    if (to < 0 || to >= clients.length || from === to) return;
    const next = [...clients];
    const [x] = next.splice(from, 1);
    next.splice(to, 0, x);
    const key = qk.config("clients");
    const previous = qc.getQueryData(key);
    // Optimistic: the order is ours alone, and a failure rolls it back.
    qc.setQueryData(key, next);
    try {
      await request("PUT", "/clients/order", { body: { names: next.map((c) => c.name) } });
      void qc.invalidateQueries({ queryKey: key });
    } catch (e) {
      qc.setQueryData(key, previous);
      toast.error(errorMessage(e));
    }
  };
  if (clients.length === 0) return <p className="text-sm text-muted-foreground">No clients yet. Add one, or add a seen device below.</p>;
  return (
    <Table aria-label="Clients">
      <TableHeader>
        <TableRow>
          <TableHead className="w-16">Order</TableHead>
          <TableHead>Name</TableHead>
          <TableHead>MACs</TableHead>
          <TableHead>Source ranges</TableHead>
          <TableHead>Profile</TableHead>
          <TableHead>Tags</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {clients.map((c, i) => (
          <TableRow
            key={c.name}
            draggable
            onDragStart={() => setDrag(i)}
            onDragOver={(e) => drag !== null && e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              if (drag !== null) void reorder(drag, i);
              setDrag(null);
            }}
            onDragEnd={() => setDrag(null)}
            className={drag === i ? "opacity-50" : undefined}
          >
            <TableCell>
              <span className="flex items-center gap-0.5">
                <GripVerticalIcon className="size-4 cursor-grab text-muted-foreground" aria-hidden />
                <Button variant="ghost" size="icon-sm" aria-label={`Move ${c.name} up`} disabled={i === 0} onClick={() => void reorder(i, i - 1)}>
                  <ArrowUpIcon />
                </Button>
                <Button variant="ghost" size="icon-sm" aria-label={`Move ${c.name} down`} disabled={i === clients.length - 1} onClick={() => void reorder(i, i + 1)}>
                  <ArrowDownIcon />
                </Button>
              </span>
            </TableCell>
            <TableCell className="font-medium">
              <SafeText>{c.name}</SafeText>
            </TableCell>
            <TableCell>
              <MacList macs={c.macs ?? []} />
            </TableCell>
            <TableCell>
              <SafeText mono>{(c.source_ips ?? []).join(", ")}</SafeText>
            </TableCell>
            <TableCell>
              {c.profile ? (
                <Link to="/profiles/$profileId" params={{ profileId: c.profile }} className="hover:underline">
                  <Mono>{c.profile}</Mono>
                </Link>
              ) : (
                <span className="text-muted-foreground">names only</span>
              )}
            </TableCell>
            <TableCell>
              <span className="flex flex-wrap gap-1">
                {(c.tags ?? []).map((t) => (
                  <Badge key={t} variant="secondary">
                    <SafeText>{t}</SafeText>
                  </Badge>
                ))}
              </span>
            </TableCell>
            <TableCell>
              <Button variant="ghost" size="icon-sm" aria-label={`Edit ${c.name}`} onClick={() => onEdit(c.name ?? "")}>
                <PencilIcon />
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function DeviceTable({ devices, onAdd }: { devices: SeenDevice[]; onAdd: (d: SeenDevice) => void }) {
  return (
    <Table aria-label="Seen devices">
      <TableHeader>
        <TableRow>
          <TableHead>Device</TableHead>
          <TableHead>MACs</TableHead>
          <TableHead>Addresses</TableHead>
          <TableHead>Edge</TableHead>
          <TableHead>Last seen</TableHead>
          <TableHead className="text-right">Queries</TableHead>
          <TableHead />
        </TableRow>
      </TableHeader>
      <TableBody>
        {devices.map((d, i) => (
          <TableRow key={`${d.key}-${i}`}>
            <TableCell>
              <Link to="/clients/device" search={{ key: d.key }} className="hover:underline">
                <SafeText>{d.client ?? d.name ?? d.dhcp_name ?? d.ptr ?? d.key}</SafeText>
              </Link>
              {d.client && <Badge variant="secondary" className="ml-2">client</Badge>}
            </TableCell>
            <TableCell>
              <DeviceMacs device={d} />
            </TableCell>
            <TableCell>
              <SafeText mono>{d.addresses.join(", ")}</SafeText>
            </TableCell>
            <TableCell>
              <SafeText>{d.edge}</SafeText>
            </TableCell>
            <TableCell>
              <TimeAgo value={d.last_seen} />
            </TableCell>
            <TableCell className="text-right tabular-nums">{formatCompact(d.queries)}</TableCell>
            <TableCell>
              {!d.client && (
                <Button size="sm" variant="outline" onClick={() => onAdd(d)}>
                  <UserPlusIcon /> Add as client
                </Button>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

type Summary = NonNullable<ReturnType<typeof useQuerySummary>["data"]>;

function SummaryView({ summary, window, edge, device }: { summary: Summary; window: string; edge: string; device?: boolean }) {
  const rate = summary.queries ? summary.blocked / summary.queries : null;
  const tops: [string, Summary["top"]][] = [
    ["Top names", summary.top],
    ["Top blocked names", summary.top_blocked],
  ];
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Stat label="Queries" value={formatCompact(summary.queries)} />
        <Stat label="Block rate" value={formatPercent(rate)} />
      </div>
      <Section title="Decisions over time">
        <TimeSeriesChart lines={summary.decisions as ChartLine[]} kind="stacked" ariaLabel="Decisions over time" specs={[{ match: () => true, label: (l) => l.labels?.decision ?? l.name }]} />
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        {tops.map(([title, items]) => (
          <Section key={title} title={title}>
            {!items?.length ? (
              <p className="text-sm text-muted-foreground">None in this window.</p>
            ) : (
              <ol className="space-y-1 text-sm">
                {items.map((it) => (
                  <li key={it.key} className="flex items-center justify-between gap-2">
                    <Link to="/query-log" search={{ qname: it.key, match: "exact", window, edge }} className="min-w-0 truncate font-mono text-xs hover:underline">
                      <SafeText>{it.key}</SafeText>
                    </Link>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {it.bundle && (
                        <span className="mr-2" title="The bundle that decided most of its blocks">
                          <Mono>{escapeControl(it.bundle)}</Mono>
                        </span>
                      )}
                      {formatCompact(it.count)}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </Section>
        ))}
      </div>
      <Section
        title="Temporary allows"
        description={
          <>
            {device ? "Those in force at some time in this window, newest first (the newest 50)." : "Its devices' allows in force at some time in this window, newest first (the newest 50)."} States are as of each edge's last report:
            an allow whose revoke the edge hasn't acknowledged yet still shows active here (
            <Link to="/temporary-allows" className="text-primary hover:underline">
              Temporary allows
            </Link>{" "}
            shows the revoke pending).
          </>
        }
      >
        {summary.temporary_allows.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <ul className="space-y-1 text-sm" aria-label="Temporary allows">
            {summary.temporary_allows.map((a) => (
              <li key={`${a.edge}/${a.allow_id}`} className="flex flex-wrap items-center gap-2">
                <SafeText mono>{a.target}</SafeText> <Badge variant="outline">{escapeControl(a.kind)}</Badge> <AllowStateBadge allow={a} />
                {/* A profile's view lists several devices' allows: whose each is. */}
                {!device && (
                  <span className="text-xs">
                    for <SafeText>{a.device ?? a.client ?? "?"}</SafeText>
                  </span>
                )}
                <span className="text-muted-foreground">
                  {a.ended_at ? (
                    <>
                      ended <TimeAgo value={a.ended_at} />
                    </>
                  ) : a.state === "revoked" && a.revoke_acked_at ? (
                    <>
                      revoked <TimeAgo value={a.revoke_acked_at} />
                    </>
                  ) : (
                    <>
                      until <TimeAgo value={a.expires_at} />
                    </>
                  )}
                </span>
                <span className="text-xs text-muted-foreground">
                  on <SafeText>{a.edge}</SafeText>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <p className="text-xs text-muted-foreground">Counted from the query log like the dashboard's top panels: only logged queries count.</p>
    </div>
  );
}

export function DeviceViewPage() {
  const params = useParams({ strict: false }) as { device?: string };
  const search = useSearch({ strict: false }) as DeviceSearch;
  const device = search.key ?? params.device ?? "";
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("dashboard");
  const q = useQuerySummary({ device }, window, edge);
  const isMac = !!normalizeMac(device);
  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            Device <SafeText mono>{device}</SafeText> {isMac && <MacBadges mac={device} />}
          </span>
        }
        description={<Link to="/clients" className="text-primary hover:underline">← Clients</Link>}
        actions={
          <>
            <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
            <EdgeSelector value={edge} onChange={setEdge} />
          </>
        }
      />
      <QueryView query={q} what="The device view" rows={6}>
        {(s) => <SummaryView summary={s} window={window} edge={edge} device />}
      </QueryView>
    </div>
  );
}

export function ProfileDevicesPage() {
  const { profileId } = useParams({ strict: false }) as { profileId: string };
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("dashboard");
  const q = useQuerySummary({ profile: profileId }, window, edge);
  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span>
            Devices of profile <Mono>{escapeControl(profileId)}</Mono>
          </span>
        }
        description={<Link to="/clients" className="text-primary hover:underline">← Clients</Link>}
        actions={
          <>
            <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
            <EdgeSelector value={edge} onChange={setEdge} />
          </>
        }
      />
      <QueryView query={q} what="The profile's device view" rows={6}>
        {(s) => (
          <div className="space-y-4">
            <SummaryView summary={s} window={window} edge={edge} />
            {(
              <Section title="Devices" description="The profile's devices in this window (the busiest 100).">
                {s.devices.length === 0 && <p className="text-sm text-muted-foreground">None in this window.</p>}
                <ul className="space-y-1 text-sm">
                  {s.devices.map((d) => (
                    <li key={d.key} className="flex justify-between gap-2">
                      <Link to="/clients/device" search={{ key: d.key, window, edge }} className="font-mono text-xs hover:underline">
                        <SafeText>{d.key}</SafeText>
                      </Link>
                      <span className="text-xs text-muted-foreground">
                        {formatCompact(d.queries)} queries, {formatCompact(d.blocked)} blocked
                      </span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
          </div>
        )}
      </QueryView>
    </div>
  );
}
