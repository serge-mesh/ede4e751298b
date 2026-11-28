import * as React from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { DownloadIcon, KeyRoundIcon, Loader2Icon, SaveIcon, Trash2Icon, TriangleAlertIcon, UploadIcon, XIcon } from "lucide-react";
import { KeyValue, PageHeader, Section } from "@/components/common/page";
import { useDraft, useHeldText } from "@/components/common/drafts";
import { ErrorState, LoadingState, PagedListError, QueryView, RefetchError } from "@/components/common/states";
import { JsonBlock, Mono, SafeText } from "@/components/common/text";
import { CopyField } from "@/components/common/copy-button";
import { Confirm } from "@/components/common/confirm";
import { IssueList } from "@/components/common/entity-editor";
import { ImportSource } from "./feeds";
import { SchemaForm, type FieldOverride } from "@/components/schema-form/schema-form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StaleSettings, qk, useEntities, useIdentity, useSaveSettings, useSecrets, useSettings } from "@/api/queries";
import { client, download, request, unwrap } from "@/api/http";
import { restoreSent, resync, resyncForRestore } from "@/api/events";
import { ApiError, errorMessage } from "@/api/errors";
import type { Issue, RestoreResult, Settings } from "@/api/types";
import { componentSchema, openapiRoot } from "@/lib/openapi";
import { clone, type FieldErrors, type SchemaObject } from "@/lib/schema";
import { COUPLED_FIELDS, deepEqual, mergeKeepingMine } from "@/lib/merge";
import { EMPTY_SOURCE, hasSource, textWithoutBom, withoutBom, type ImportSourceValue } from "@/lib/import-file";
import { formatBytes, formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { IdSelect } from "@/components/common/ordered-picker";
import { LancaTab } from "./lanca";

/**
 * lanca.zones (core.md §11, security.md §2): the names the LAN CA may sign. A change is a new
 * root, made under Settings → LAN CA (pages/lanca.tsx), never from another settings form.
 */
export const LANCA_ZONES_TEXT = "Changing the zones makes a new CA root, trusted again on every device:";

const TABS: [string, string][] = [
  ["identity", "Identity"],
  ["password", "Admin password"],
  ["web", "Web and access"],
  ["lanca", "LAN CA"],
  ["retention", "Retention"],
  ["resolver", "Resolver"],
  ["crosscheck", "Cross-check"],
  ["dnssec", "DNSSEC"],
  ["feeds", "Feeds and lookups"],
  ["alerts", "Alerts"],
  ["edges", "Edges"],
  ["secrets", "Secrets"],
  ["export", "Export and restore"],
  ["changes", "Change journal"],
];

/** Settings → Alerts: `alerts.temporary_allow` (core.md §9: off by default) says what it does. */
const ALERTS_LABELS = { "alerts.temporary_allow": "Alert on temporary allows" };
const ALERTS_OVERRIDES: Record<string, FieldOverride> = {
  "alerts.temporary_allow": ({ renderDefault }) => (
    <div className="space-y-1">
      {renderDefault()}
      <p className="text-xs text-muted-foreground">Raises an info alert whenever an edge creates a temporary allow.</p>
    </div>
  ),
};

export function SettingsPage() {
  const search = useSearch({ strict: false }) as { tab?: string };
  const navigate = useNavigate();
  const tab = search.tab ?? "identity";
  return (
    <div>
      <PageHeader title="Settings" />
      <Tabs value={tab} onValueChange={(t) => void navigate({ to: ".", search: { tab: t }, replace: true })} orientation="vertical" className="lg:flex-row lg:items-start lg:gap-6">
        <TabsList className="h-auto w-full flex-wrap lg:w-52 lg:flex-col lg:items-stretch">
          {TABS.map(([v, l]) => (
            <TabsTrigger key={v} value={v} className="lg:justify-start">
              {l}
            </TabsTrigger>
          ))}
        </TabsList>
        <div className="min-w-0 flex-1">
          <TabsContent value="identity">
            <IdentityTab />
          </TabsContent>
          <TabsContent value="password">
            <PasswordTab />
          </TabsContent>
          <TabsContent value="web">
            <SettingsSection
              keys={["web", "lists", "metrics"]}
              title="Web and access"
              description="The web port, its TLS, core's names (its certificate and the Host allowlist, under the LAN CA's zones), the extra IP addresses clients reach core at through NAT or a port forward, and the IP allowlists. Managed TLS covers RFC 1918 and ULA addresses only: for any other address, verified HTTPS needs a file certificate or one of core's names. Port and TLS changes apply at restart."
              banner={(s) =>
                s.web?.tls === "off" ? (
                  <Alert variant="warning">
                    <TriangleAlertIcon />
                    <AlertTitle>web.tls is off</AlertTitle>
                    <AlertDescription>Credentials cross the network in clear.</AlertDescription>
                  </Alert>
                ) : null
              }
            />
          </TabsContent>
          <TabsContent value="lanca">
            <LancaTab />
          </TabsContent>
          <TabsContent value="retention">
            <SettingsSection keys={["retention"]} title="Retention" description="Windows per data class (default 72 h; feed checks 60 days). Alerts with their evidence stay until deleted." />
          </TabsContent>
          <TabsContent value="resolver">
            <ResolverTab />
          </TabsContent>
          <TabsContent value="crosscheck">
            <CrosscheckTab />
          </TabsContent>
          <TabsContent value="dnssec">
            <SettingsSection keys={["dnssec"]} title="DNSSEC validation" description="With address translation between core and the edges, set source_ips to the translated address, or validation fails quietly until dnssec_unavailable fires." />
          </TabsContent>
          <TabsContent value="feeds">
            <SettingsSection keys={["feeds", "lookups"]} title="Feeds and lookups" />
          </TabsContent>
          <TabsContent value="alerts">
            <SettingsSection
              keys={["alerts"]}
              title="Alerts"
              description="Thresholds per alert kind (how long a condition must hold), the evidence limits, and alerts that are off by default."
              labels={ALERTS_LABELS}
              overrides={ALERTS_OVERRIDES}
            />
          </TabsContent>
          <TabsContent value="edges">
            <SettingsSection keys={["edges", "edge_api", "default_profile"]} title="Edges" description="The edge API port, the minimum UniFi OS version per target, and the default profile." />
          </TabsContent>
          <TabsContent value="secrets">
            <SecretsTab />
          </TabsContent>
          <TabsContent value="export">
            <ExportTab />
          </TabsContent>
          <TabsContent value="changes">
            <ChangesTab />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}

function IdentityTab() {
  const identity = useIdentity();
  const settings = useSettings();
  return (
    <QueryView query={identity} rows={5}>
      {(id) => (
        <div className="space-y-4">
          <Section title="Core's identity" description="Edges pin this key. Compare it with what picket-edge setup shows, and with picket-core identity on the host.">
            <KeyValue
              items={[
                ["Fingerprint", <CopyField value={id.fingerprint} label="Copy fingerprint" />],
                ["Instance", <Mono>{id.instance_id}</Mono>],
                ["Version", <Mono>{id.version}</Mono>],
                ["UI", id.ui_embedded ? "embedded" : "not embedded in this build"],
              ]}
            />
          </Section>
          <Section title="LAN CA" description="Signs edge listener certificates and the web certificate, limited to its zones. Install its root on devices that use DoT or DoH listeners.">
            <KeyValue
              items={[
                ["Root fingerprint", <CopyField value={id.lanca_fingerprint} label="Copy root fingerprint" />],
                ["Zones", <Mono>{id.lanca_zones.join(", ")}</Mono>],
                [
                  "Download",
                  <span className="flex flex-wrap gap-2">
                    <Button asChild size="sm" variant="outline">
                      <a href="/lanca/ca.crt" download>
                        <DownloadIcon /> DER (.crt)
                      </a>
                    </Button>
                    <Button asChild size="sm" variant="outline">
                      <a href="/lanca/ca.pem" download>
                        <DownloadIcon /> PEM
                      </a>
                    </Button>
                  </span>,
                ],
              ]}
            />
            <p className="mt-2 text-xs text-muted-foreground">
              {LANCA_ZONES_TEXT}{" "}
              <Link to="/settings" search={{ tab: "lanca" }} className="text-primary hover:underline">
                LAN CA
              </Link>
              .
            </p>
          </Section>
          <Section title="Release keys" description="Compiled in: the edge release bundled with core must carry a signature from one of them.">
            {settings.data ? (
              settings.data.release_keys.length > 0 ? (
                <ul className="space-y-1">
                  {settings.data.release_keys.map((k) => (
                    <li key={k}>
                      <SafeText mono className="break-all">
                        {k}
                      </SafeText>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">None compiled in (development build).</p>
              )
            ) : (
              <LoadingState rows={1} />
            )}
          </Section>
        </div>
      )}
    </QueryView>
  );
}

function PasswordTab() {
  const [current, setCurrent] = React.useState("");
  const [next, setNext] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const m = useMutation({
    mutationFn: () => unwrap(client.POST("/api/ui/v1/account/password", { body: { current, new: next } })),
    onSuccess: () => {
      toast.success("Password changed. The browser asks for the new one on the next request.");
      setCurrent("");
      setNext("");
      setConfirm("");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const short = next.length > 0 && next.length < 12;
  const mismatch = confirm.length > 0 && confirm !== next;
  return (
    <Section title="Admin password" description="One admin account (admin), checked by basic auth. It can also be set offline with picket-core passwd.">
      <form
        className="max-w-sm space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <input type="text" name="username" autoComplete="username" value="admin" readOnly hidden />
        <div className="space-y-1.5">
          <Label htmlFor="pw-current">Current password</Label>
          <Input id="pw-current" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="pw-new">New password</Label>
          <Input id="pw-new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required aria-invalid={short || undefined} aria-describedby="pw-new-help" />
          <p id="pw-new-help" className={short ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
            At least 12 characters.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="pw-confirm">Repeat the new password</Label>
          <Input id="pw-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required aria-invalid={mismatch || undefined} />
          {mismatch && <p className="text-xs text-destructive">The passwords differ.</p>}
        </div>
        <Button type="submit" disabled={!current || next.length < 12 || next !== confirm || m.isPending}>
          <KeyRoundIcon /> Change password
        </Button>
      </form>
    </Section>
  );
}

/** Changed top-level keys only: `PUT settings` takes a partial nested object. */
export function settingsPatch(before: Settings, after: Settings, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    const a = (before as Record<string, unknown>)[k];
    const b = (after as Record<string, unknown>)[k];
    if (JSON.stringify(a) !== JSON.stringify(b)) out[k] = b === undefined ? null : b;
  }
  return out;
}

/** A form over some top-level keys of Settings, from the OpenAPI schema. */
function SettingsSection({
  keys,
  title,
  description,
  overrides,
  labels,
  banner,
  children,
}: {
  keys: string[];
  title: string;
  description?: React.ReactNode;
  overrides?: Record<string, FieldOverride>;
  /** Field labels by path, where the schema's key alone reads poorly. */
  labels?: Record<string, string>;
  banner?: (s: Settings) => React.ReactNode;
  children?: (s: Settings, set: (s: Settings) => void) => React.ReactNode;
}) {
  const q = useSettings();
  if (q.data === undefined) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={6} />;
  // A failed refetch keeps the form and its draft (core.md §12).
  return (
    <SettingsForm
      refetchError={q.error ? <RefetchError error={q.error} onRetry={() => void q.refetch()} /> : null} latest={q.data.settings} readOnly={q.data.read_only} keys={keys} title={title} description={description} overrides={overrides} labels={labels} banner={banner}>
      {children}
    </SettingsForm>
  );
}

/**
 * A settings section's form. Settings have no server-side version check (api.md §7), so the form
 * keeps the settings its draft was edited from (`base`): when live data changes this section, a
 * clean form follows it and a dirty one keeps the draft and offers to reload or to keep its
 * changes on top of the new values.
 */
function SettingsForm({
  refetchError,
  latest,
  readOnly,
  keys,
  title,
  description,
  overrides,
  labels,
  banner,
  children,
}: {
  /** A failed refetch, shown above the form (which keeps its draft). */
  refetchError?: React.ReactNode;
  latest: Settings;
  readOnly: string[];
  keys: string[];
  title: string;
  description?: React.ReactNode;
  overrides?: Record<string, FieldOverride>;
  labels?: Record<string, string>;
  banner?: (s: Settings) => React.ReactNode;
  children?: (s: Settings, set: (s: Settings) => void) => React.ReactNode;
}) {
  const [base, setBase] = React.useState<Settings>(latest);
  const [value, setValue] = React.useState<Settings>(() => clone(latest));
  const [incoming, setIncoming] = React.useState<Settings | null>(null);
  const [seen, setSeen] = React.useState(latest);
  // Text a control holds that isn't in `value` yet (a threshold key typed but not added) is a draft too.
  const text = useHeldText();
  const mine = (x: Settings) => Object.fromEntries(keys.map((k) => [k, (x as Record<string, unknown>)[k]]));
  if (latest !== seen) {
    setSeen(latest);
    if (!deepEqual(mine(latest), mine(base))) {
      if (deepEqual(mine(value), mine(base)) && !text.held) {
        setBase(latest);
        setValue(clone(latest));
        setIncoming(null);
      } else setIncoming(latest);
    } else setIncoming(null);
  }
  const [errors, setErrors] = React.useState<FieldErrors>({});
  const [issues, setIssues] = React.useState<Issue[]>([]);
  const save = useSaveSettings();
  const profiles = useEntities("profiles");
  const full = componentSchema("Settings");
  const schema = React.useMemo<SchemaObject>(
    () => ({ ...full, properties: Object.fromEntries(Object.entries(full.properties ?? {}).filter(([k]) => keys.includes(k))) }),
    [full, keys],
  );
  const patch = settingsPatch(base, value, keys);
  const changed = Object.keys(patch).length > 0;
  const dirty = changed || text.held;
  useDraft(dirty);
  const allOverrides = React.useMemo<Record<string, FieldOverride>>(
    () => ({
      default_profile: ({ value: v, onChange, disabled, id }) => (
        <IdSelect id={id} value={v as string | null} onChange={onChange} nullable noneLabel="None (refuse)" disabled={disabled} options={(profiles.data ?? []).map((p) => ({ value: p.id ?? "", label: p.id }))} />
      ),
      ...overrides,
    }),
    [overrides, profiles.data],
  );
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        const sent = clone(value);
        // Sent only while the sections this form covers are still its base (api/queries.ts).
        save.mutate({ patch, check: { base, keys } }, {
          onSuccess: () => {
            toast.success("Settings saved");
            setBase(sent);
            setIncoming(null);
            setIssues([]);
            setErrors({});
          },
          onError: (err) => {
            if (err instanceof StaleSettings) {
              setIncoming(err.current);
              toast.error("These settings changed since you started editing: reload them or keep your changes, then save.");
              return;
            }
            if (err instanceof ApiError) {
              setErrors(err.fieldErrors());
              setIssues(err.issues.filter((i) => !i.field));
            }
            toast.error(errorMessage(err));
          },
        });
      }}
    >
      <Section title={title} description={description}>
        <div className="space-y-4">
          {refetchError}
          {incoming && (
            <Alert variant="warning">
              <TriangleAlertIcon />
              <AlertTitle>These settings changed elsewhere</AlertTitle>
              <AlertDescription>
                <p>They were saved since you started editing. Reload them, or keep your changes on top of the new values.</p>
                <span className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setBase(incoming);
                      setValue(clone(incoming));
                      setIncoming(null);
                      text.reset();
                    }}
                  >
                    Reload
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      // core.md §2 checks some fields together: those merge as one value.
                      const groups = COUPLED_FIELDS.settings.filter((g) => g.every((p) => keys.includes(p.split(".")[0])));
                      const { value: part, replaced } = mergeKeepingMine(mine(base), mine(value), mine(incoming), groups);
                      setValue({ ...clone(incoming), ...part } as Settings);
                      setBase(incoming);
                      setIncoming(null);
                      for (const g of replaced) toast.info(`Kept your ${g.join(", ")} as you edited them: core checks them together, so the change made elsewhere to them is replaced.`);
                    }}
                  >
                    Keep my changes
                  </Button>
                </span>
              </AlertDescription>
            </Alert>
          )}
          {banner?.(value)}
          <IssueList issues={issues} title="Core refused the change" />
          {text.scope(
            <>
              {children?.(value, setValue)}
              <SchemaForm schema={schema} root={openapiRoot} value={value} onChange={(v) => setValue(v as Settings)} errors={errors} readOnly={readOnly} overrides={allOverrides} labels={labels} disabled={save.isPending} />
            </>,
          )}
        </div>
      </Section>
      <div className="sticky bottom-0 flex gap-2 border-t bg-background/95 py-3">
        <Button type="submit" disabled={!changed || save.isPending || !!incoming} title={incoming ? "Reload or keep your changes first." : undefined}>
          {save.isPending ? <Loader2Icon className="animate-spin" /> : <SaveIcon />} Save
        </Button>
        {dirty && (
          <Button
            variant="ghost"
            onClick={() => {
              setValue(clone(base));
              text.reset();
            }}
          >
            Discard changes
          </Button>
        )}
      </div>
    </form>
  );
}

const QUAD9 = {
  dot: { protocol: "dot", ip: "9.9.9.10", port: 853, tls_host: "dns10.quad9.net", path: null, operator: "quad9" },
  doh: { protocol: "doh", ip: "9.9.9.10", port: 443, tls_host: "dns10.quad9.net", path: "/dns-query", operator: "quad9" },
};

function ResolverTab() {
  return (
    <SettingsSection
      keys={["resolver"]}
      title="Core's resolver"
      description="For feed and lookup provider hostnames. Where the port-53 redirect reaches core, set an upstream by IP over DoT or DoH, so feeds keep working while an edge is down."
    />
  );
}

function CrosscheckTab() {
  return (
    <SettingsSection
      keys={["crosscheck"]}
      title="Cross-check of unsigned answers"
      description="DNSSEC can't prove answers in unsigned zones. With the cross-check on, core asks a second resolver about answers that look like an upstream blocking a name, and alerts when it disagrees."
      overrides={{
        "crosscheck.enabled": ({ value, onChange, disabled, id }) => (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Switch id={id} checked={value === true} onCheckedChange={onChange} disabled={disabled} />
              <span className="text-sm">{value ? "On" : "Off (the default)"}</span>
            </div>
            <Alert variant="warning">
              <TriangleAlertIcon />
              <AlertTitle>The resolver sees every name checked</AlertTitle>
              <AlertDescription>
                Names that got NXDOMAIN, SERVFAIL or an empty A answer, and names answered with a sinkhole or private address, are sent to it. The negative check also needs DNSSEC
                validation on.
              </AlertDescription>
            </Alert>
          </div>
        ),
        "crosscheck.resolver": ({ renderDefault, onChange, disabled }) => (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted-foreground">Preset: Quad9 unfiltered</span>
              <Button size="sm" variant="outline" disabled={disabled} onClick={() => onChange({ ...QUAD9.dot })}>
                DoT
              </Button>
              <Button size="sm" variant="outline" disabled={disabled} onClick={() => onChange({ ...QUAD9.doh })}>
                DoH
              </Button>
              <Button size="sm" variant="ghost" disabled={disabled} onClick={() => onChange({ ...QUAD9.dot, ip: "149.112.112.10" })}>
                DoT via 149.112.112.10
              </Button>
            </div>
            {renderDefault()}
            <p className="text-xs text-muted-foreground">
              It must be run by another operator than the upstreams: core refuses a resolver whose operator or IP is an upstream's, or whose TLS name shares an upstream's registrable domain.
            </p>
          </div>
        ),
      }}
    />
  );
}

function SecretsTab() {
  const secrets = useSecrets();
  const qc = useQueryClient();
  const [name, setName] = React.useState("");
  const [value, setValue] = React.useState("");
  const setSecret = useMutation({
    mutationFn: (v: { name: string; value: string }) => unwrap(client.PUT("/api/ui/v1/secrets/{name}", { params: { path: { name: v.name } }, body: { value: v.value } })),
    onSuccess: () => {
      toast.success("Secret stored");
      setName("");
      setValue("");
      void qc.invalidateQueries({ queryKey: qk.secrets });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: (n: string) => unwrap(client.DELETE("/api/ui/v1/secrets/{name}", { params: { path: { name: n } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.secrets }),
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <div className="space-y-4">
      <Section title="Secrets" description="Referenced as ${secret:name} in provider configs and an sqs trigger's AWS keys. Values are write-only: never shown, exported or logged.">
        <QueryView query={secrets} rows={3} empty={<p className="text-sm text-muted-foreground">No secrets.</p>} isEmpty={(d) => d.length === 0}>
          {(list) => (
            <Table aria-label="Secrets">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((s) => (
                  <TableRow key={s.name}>
                    <TableCell>
                      <Mono>{escapeControl(s.name)}</Mono>
                    </TableCell>
                    <TableCell>{s.has_value ? <Badge variant="secondary">set</Badge> : <Badge variant="warning">missing</Badge>}</TableCell>
                    <TableCell className="text-right">
                      <span className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => setName(s.name)}>
                          Set value
                        </Button>
                        <Confirm title={`Delete secret ${escapeControl(s.name)}?`} description="Configs that reference it stop working until it is set again." destructive confirmLabel="Delete" onConfirm={() => del.mutate(s.name)}>
                          <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`}>
                            <Trash2Icon />
                          </Button>
                        </Confirm>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Section>
      <Section title="Set a secret">
        <form
          className="grid max-w-xl gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            setSecret.mutate({ name: name.trim(), value });
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="sec-name">Name</Label>
            <Input id="sec-name" value={name} onChange={(e) => setName(e.target.value)} className="font-mono" required autoComplete="off" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="sec-value">Value</Label>
            <Input id="sec-value" type="password" value={value} onChange={(e) => setValue(e.target.value)} required autoComplete="new-password" />
          </div>
          <Button type="submit" disabled={!name.trim() || !value || setSecret.isPending}>
            Store
          </Button>
        </form>
      </Section>
    </div>
  );
}

/** config/export.rs `MAX_DOCUMENT_BYTES`: the largest document, a bound the export and the restore both keep (413 past it). */
export const MAX_EXPORT_BYTES = 1024 * 1024 * 1024;

/**
 * A refusal of the export or the restore in words (config/export.rs): one export and one restore
 * run at a time (409), a document is at most 1 GiB (413), a restore whose upload stalls never
 * begins (408), neither runs without room on the data disk besides a margin (507); a 422 is
 * core's own message (a part the restore wouldn't read, a malformed document, other lanca.zones,
 * a bad reference with its issues, a newer format).
 */
export function exportRefusal(e: unknown, what: "export" | "restore"): string {
  if (!(e instanceof ApiError)) return errorMessage(e);
  if (e.status === 409)
    return what === "export"
      ? "Another export is being written or downloaded (from another tab or by someone else): try again when it ends."
      : "Another restore is running (from another tab or by someone else): try again when it ends. Nothing was changed.";
  if (e.status === 413) return "The document is larger than a config export can be (1 GiB). Nothing was changed.";
  // Core's body deadline (`408 timeout`): the upload stalled, so the restore never began.
  if (e.status === 408 && what === "restore") return "The upload stalled before core had the whole document. Nothing was changed: try again.";
  if (e.status === 507) return `${errorMessage(e)}. Free space on core's data disk, then try again.${what === "restore" ? " Nothing was changed." : ""}`;
  return errorMessage(e);
}

/**
 * What the top level of a document says, as far as the restore cares (config/export/stream.rs
 * reads its keys in any order): a config export with its `format_version` (and `exported_at`,
 * `core_version` when given); a feed export (`picket_feed_export` first, for Feeds → Import); not
 * a JSON object, or an object whose top level has no `format_version`, which core refuses; or
 * `unknown`: not read to its end within the budget, cut short, or a format_version that isn't a
 * number, which core checks when it restores.
 */
export type ExportScan =
  | { kind: "export"; format: number; exportedAt?: string; coreVersion?: string }
  | { kind: "feed-export" }
  | { kind: "not-object" }
  | { kind: "no-format" }
  | { kind: "unknown" };

/** How much of a document the page reads looking for its top level's format_version. */
export const HEAD_SCAN_BUDGET = 64 * 1024 * 1024;
const HEAD_SCAN_CHUNK = 1024 * 1024;
/** The longest top-level key or scalar value kept while scanning (longer ones aren't the ones read). */
const SCAN_TEXT_MAX = 256;

/**
 * A JSON object's top-level keys and scalar values, read incrementally: strings (with escapes)
 * and nested values are skipped, never parsed, so a large document costs one pass over its
 * characters and a bounded amount of memory.
 */
class RootScanner {
  private started = false;
  /** Something came before the document's first token. */
  private leading = false;
  private depth = 0;
  private inString = false;
  private escape = false;
  private expectKey = false;
  private firstKey = true;
  /** The raw text (quotes included) of the top-level key being read. */
  private keyText: string | null = null;
  /** The top-level key whose value comes next. */
  private key: string | null = null;
  /** The raw text of a top-level value being kept (a key the restore reads). */
  private valueText: string | null = null;
  private format: number | undefined;
  private formatBad = false;
  private exportedAt: string | undefined;
  private coreVersion: string | undefined;
  result: ExportScan | null = null;

  push(text: string): ExportScan | null {
    const n = text.length;
    let i = 0;
    while (i < n && this.result === null) {
      if (this.inString) {
        if (this.escape) {
          this.escape = false;
          this.keep(text[i++]);
          continue;
        }
        let j = i;
        while (j < n) {
          const c = text.charCodeAt(j);
          if (c === 34 || c === 92) break;
          j++;
        }
        if (this.keyText !== null || this.valueText !== null) this.keep(text.slice(i, Math.min(j, i + SCAN_TEXT_MAX + 1)));
        if (j === n) break;
        this.keep(text[j]);
        if (text.charCodeAt(j) === 92) this.escape = true;
        else this.closeString();
        i = j + 1;
        continue;
      }
      this.step(text[i++]);
    }
    return this.result;
  }

  /** At the end of the document (or of the budget, `complete` false). */
  end(complete: boolean): ExportScan {
    if (this.result) return this.result;
    if (!this.started) return complete ? { kind: "not-object" } : { kind: "unknown" };
    return this.found() ?? { kind: "unknown" };
  }

  private found(): ExportScan | null {
    if (this.format === undefined) return null;
    return { kind: "export", format: this.format, exportedAt: this.exportedAt, coreVersion: this.coreVersion };
  }

  /** Keeps text of the key or value being read, up to past SCAN_TEXT_MAX (then it reads as none the restore uses). */
  private keep(t: string) {
    if (this.keyText !== null && this.keyText.length <= SCAN_TEXT_MAX) this.keyText += t;
    if (this.valueText !== null && this.valueText.length <= SCAN_TEXT_MAX) this.valueText += t;
  }

  private closeString() {
    this.inString = false;
    if (this.keyText === null) return;
    let key: string;
    try {
      key = JSON.parse(this.keyText) as string;
    } catch {
      key = "";
    }
    this.keyText = null;
    this.key = key;
    if (this.firstKey && key === "picket_feed_export") this.result = { kind: "feed-export" };
    this.firstKey = false;
  }

  private step(ch: string) {
    if (!this.started) {
      // JSON's whitespace; a BOM only first (the UI sends the document without it).
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || (ch === "\uFEFF" && !this.leading)) {
        this.leading = true;
        return;
      }
      if (ch !== "{") {
        this.result = { kind: "not-object" };
        return;
      }
      this.started = true;
      this.depth = 1;
      this.expectKey = true;
      return;
    }
    if (ch === '"') {
      this.inString = true;
      if (this.depth === 1 && this.expectKey) {
        this.expectKey = false;
        this.keyText = '"';
      } else this.keep(ch);
      return;
    }
    if (this.depth > 1) {
      if (ch === "{" || ch === "[") this.depth++;
      else if (ch === "}" || ch === "]") this.depth--;
      return;
    }
    // The top level, outside strings.
    if (ch === ":") {
      if (this.key === "format_version" || this.key === "exported_at" || this.key === "core_version") this.valueText = "";
    } else if (ch === ",") {
      this.closeValue();
      this.expectKey = true;
    } else if (ch === "}") {
      this.closeValue();
      this.result = this.found() ?? (this.formatBad ? { kind: "unknown" } : { kind: "no-format" });
    } else if (ch === "{" || ch === "[") {
      this.depth++;
      // A nested value: not a format_version core reads (its kept text is dropped as not scalar).
      if (this.valueText !== null) this.valueText += ch;
    } else this.keep(ch);
  }

  private closeValue() {
    const key = this.key;
    const raw = this.valueText;
    this.valueText = null;
    this.key = null;
    if (raw === null) return;
    let v: unknown;
    try {
      v = JSON.parse(raw);
    } catch {
      v = undefined;
    }
    if (key === "format_version") {
      // stream.rs reads it as a u32; the last one given counts (serde's visitor), as here.
      if (typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffffffff) {
        this.format = v;
        this.formatBad = false;
      } else {
        this.format = undefined;
        this.formatBad = true;
      }
    } else if (typeof v === "string" && v.length <= 64) {
      if (key === "exported_at") this.exportedAt = v;
      else this.coreVersion = v;
    }
    // The three keys core writes first: nothing more to read.
    if (this.format !== undefined && this.exportedAt !== undefined && this.coreVersion !== undefined) this.result = this.found();
  }
}

/** `scanExportRoot` over text already in memory (a pasted document), up to `budget` characters. */
export function scanExportText(text: string, budget = HEAD_SCAN_BUDGET): ExportScan {
  const s = new RootScanner();
  return s.push(text.slice(0, budget)) ?? s.end(text.length <= budget);
}

/**
 * Reads a document's top level in chunks until it says what the document is (a file is never
 * read whole here): core's own exports name format_version first, so one chunk is read; a
 * reordered one is read up to `budget` bytes, past which it is `unknown`.
 */
export async function scanExportRoot(blob: Blob, { budget = HEAD_SCAN_BUDGET, chunk = HEAD_SCAN_CHUNK }: { budget?: number; chunk?: number } = {}): Promise<ExportScan> {
  const s = new RootScanner();
  const decoder = new TextDecoder();
  const end = Math.min(blob.size, budget);
  for (let at = 0; at < end; at += chunk) {
    const bytes = await blob.slice(at, Math.min(at + chunk, end)).arrayBuffer();
    const r = s.push(decoder.decode(bytes, { stream: true }));
    if (r) return r;
  }
  return s.push(decoder.decode()) ?? s.end(blob.size <= budget);
}

/** The export download of this page (one at a time, api.md §7): kept across tab switches, so its progress and Cancel stay reachable. */
interface ExportJob {
  phase: "idle" | "writing" | "downloading";
  received: number;
  total: number | null;
  error: unknown;
  cancel: (() => void) | null;
}

let exportJob: ExportJob = { phase: "idle", received: 0, total: null, error: null, cancel: null };
const exportListeners = new Set<() => void>();

function setExportJob(patch: Partial<ExportJob>) {
  exportJob = { ...exportJob, ...patch };
  for (const l of [...exportListeners]) l();
}

function useExportJob(): ExportJob {
  return React.useSyncExternalStore(
    (cb) => {
      exportListeners.add(cb);
      return () => {
        exportListeners.delete(cb);
      };
    },
    () => exportJob,
  );
}

/**
 * Downloads the export (the owner's choice: fetched into a Blob, then saved): core writes it from
 * one snapshot (`writing`), then it arrives (`downloading`, against core's Content-Length). Cancel
 * stops the request or the body, which closes the connection: core frees its one export slot when
 * the stream ends (config/export.rs `api_get`).
 */
async function startExport() {
  if (exportJob.phase !== "idle") return;
  const ctrl = new AbortController();
  setExportJob({ phase: "writing", received: 0, total: null, error: null, cancel: () => ctrl.abort() });
  try {
    await download("/config/export", undefined, `picket-config-${new Date().toISOString().slice(0, 10)}.json`, {
      signal: ctrl.signal,
      onProgress: (received, total) => setExportJob({ phase: "downloading", received, total }),
    });
  } catch (e) {
    if (ctrl.signal.aborted) toast.info("Export cancelled");
    else setExportJob({ error: e });
  } finally {
    setExportJob({ phase: "idle", cancel: null });
  }
}

function exportProgress(j: ExportJob): string {
  if (j.total === null || j.total === 0) return `${formatBytes(j.received)} so far`;
  return `${formatBytes(j.received)} of ${formatBytes(j.total)} (${Math.floor((j.received / j.total) * 100)} %)`;
}

/** Core's refusals of a restore: nothing was changed (408 the upload stalled, 409 busy, 413 too large, 422 a bad document, 507 no room; 400 a bad request). */
const RESTORE_REFUSED = new Set([400, 408, 409, 413, 422, 507]);

function ExportTab() {
  const qc = useQueryClient();
  const job = useExportJob();
  const exporting = job.phase !== "idle";
  const [src, setSrc] = React.useState<ImportSourceValue>(EMPTY_SOURCE);
  const [fileHead, setFileHead] = React.useState<{ file: File; head: ExportScan } | null>(null);
  const [result, setResult] = React.useState<RestoreResult | null>(null);
  const size = src.file ? src.file.size : new Blob([src.text]).size;
  const tooLarge = size > MAX_EXPORT_BYTES;
  // The document's top level, read once per chosen file (incrementally; never the whole file).
  React.useEffect(() => {
    const file = src.file;
    if (!file) return;
    let live = true;
    void scanExportRoot(file)
      .catch((): ExportScan => ({ kind: "unknown" }))
      .then((head) => live && setFileHead({ file, head }));
    return () => {
      live = false;
    };
  }, [src.file]);
  const pasted = React.useMemo(() => (src.text ? scanExportText(src.text) : null), [src.text]);
  const head = src.file ? (fileHead?.file === src.file ? fileHead.head : null) : pasted;
  const refused = head?.kind === "feed-export" || head?.kind === "not-object" || head?.kind === "no-format";
  const restore = useMutation({
    // Restore is offered only for a document whose top level doesn't rule it out and that fits
    // core's bound (the button is disabled otherwise, and the source can't change while the
    // confirmation is open).
    mutationFn: async () => {
      // The document goes as it is, read once when sent, without a BOM (core reads the body as JSON).
      const body = src.file ? await withoutBom(src.file) : new Blob([textWithoutBom(src.text)], { type: "application/json" });
      return request<RestoreResult>("PUT", "/config/export", { body });
    },
    onMutate: () => {
      setResult(null);
      // Where the event socket stands as the restore goes (its answer's resyncForRestore).
      return restoreSent();
    },
    onSuccess: (r, _vars, sent) => {
      setResult(r);
      // A committed restore is always a 200 (core c58ba80), its problems after the commit among the
      // warnings, e.g. the edges' configs that couldn't be rendered yet: say there are some.
      if (r.warnings.length > 0) toast.warning(`Restored, with ${r.warnings.length === 1 ? "a warning" : `${r.warnings.length} warnings`}: see below`);
      else toast.success("Restored");
      // Core now has only the document's data (core.md §2 Export and restore): everything cached
      // is read again, with a manual feed editor's rules (resync). Core's `restore` event does the
      // same in every tab, but this tab's socket may be down, so it resyncs on the answer too, once
      // for both: the answer carries the restore's generation, as its event does (core 07acc1c).
      resyncForRestore(qc, r.generation, sent);
    },
    onError: (e) => {
      toast.error(exportRefusal(e, "restore"));
      // Anything but core's refusals (a lost connection, a 500 or 502): the restore may have run,
      // so the page re-reads as after one (resync).
      if (!(e instanceof ApiError && RESTORE_REFUSED.has(e.status))) resync(qc, true);
    },
  });
  const restoreIssues = restore.error instanceof ApiError ? restore.error.issues : [];
  return (
    <div className="space-y-4">
      <Section title="What an export leaves out" description="The export is not a full backup.">
        <ul className="list-disc space-y-0.5 pl-5 text-sm">
          <li>secret values (secrets appear by name only)</li>
          <li>core's identity and the LAN CA keys</li>
          <li>the admin password</li>
          <li>logs and metrics</li>
        </ul>
      </Section>
      <Section
        title="Export"
        description="One JSON document: the configuration, manual feeds' files (in base64 chunks), alerts with their evidence, feed check history, learned schedules and the redacted change journal. At most 1 GiB; core writes it from one snapshot before the download starts."
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" disabled={exporting} onClick={() => void startExport()}>
            {exporting ? <Loader2Icon className="animate-spin" /> : <DownloadIcon />}{" "}
            {job.phase === "writing" ? "Writing the export…" : job.phase === "downloading" ? "Downloading the export…" : "Download export"}
          </Button>
          {exporting && (
            <Button variant="ghost" aria-label="Cancel the export" onClick={() => job.cancel?.()}>
              <XIcon /> Cancel
            </Button>
          )}
          {job.phase === "downloading" && (
            <span className="text-xs tabular-nums text-muted-foreground" data-testid="export-progress">
              {exportProgress(job)}
            </span>
          )}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">The page holds the whole document in memory until it saves it: very large exports are best downloaded on a desktop browser.</p>
        {job.error !== null && (
          <Alert variant="destructive" className="mt-3" data-testid="export-error">
            <TriangleAlertIcon />
            <AlertTitle>Core didn't export</AlertTitle>
            <AlertDescription>
              <SafeText>{exportRefusal(job.error, "export")}</SafeText>
            </AlertDescription>
          </Alert>
        )}
      </Section>
      <Section
        title="Restore"
        description="Replaces all current data with the document's: nothing is merged, and one bad reference rejects the whole document. A document whose lanca.zones differ from this instance's is refused before anything changes: change the zones under LAN CA first (a new root), then restore. One restore runs at a time, and core needs room on its data disk for the document and what the restore writes."
      >
        <div className="space-y-3">
          <ImportSource value={src} onChange={setSrc} accept=".json,application/json" pastePlaceholder="A config export (JSON)" showKind={false} />
          {src.file && head === null && <p className="text-xs text-muted-foreground">Reading the document's top level…</p>}
          {head?.kind === "export" && (
            <p className="text-xs text-muted-foreground" data-testid="export-head">
              A config export{head.coreVersion ? ` from picket-core ${escapeControl(head.coreVersion)}` : ""}
              {head.exportedAt ? `, written ${formatTime(head.exportedAt)}` : ""} (format {head.format}).
            </p>
          )}
          {head?.kind === "feed-export" && <p className="text-xs text-destructive">This is a feed export: import it under Feeds (Import…), not here.</p>}
          {head?.kind === "not-object" && hasSource(src) && <p className="text-xs text-destructive">This isn't a config export: it's not a JSON object.</p>}
          {head?.kind === "no-format" && <p className="text-xs text-destructive">This isn't a config export: there's no format_version at its top level.</p>}
          {head?.kind === "unknown" && hasSource(src) && (
            <p className="text-xs text-warning" data-testid="export-head-unknown">
              The page couldn't find format_version at the document's top level (not in its first {formatBytes(HEAD_SCAN_BUDGET)}, or the document is cut short): core checks it when you restore.
            </p>
          )}
          {tooLarge && <p className="text-xs text-destructive">The document is larger than a config export can be (1 GiB).</p>}
          <Confirm
            title="Replace everything with this export?"
            description="Logs, metrics, queues and verdicts go. Core's identity, LAN CA and admin password stay. Secrets without a value in the document keep their stored value; any other stored value is gone."
            destructive
            confirmLabel="Restore"
            onConfirm={() => restore.mutate()}
          >
            <Button variant="destructive" disabled={!hasSource(src) || restore.isPending || tooLarge || head === null || refused}>
              {restore.isPending ? <Loader2Icon className="animate-spin" /> : <UploadIcon />} {restore.isPending ? "Restoring…" : "Restore"}
            </Button>
          </Confirm>
          {restore.error !== null && (
            <Alert variant="destructive" data-testid="restore-error">
              <TriangleAlertIcon />
              <AlertTitle>Core didn't restore</AlertTitle>
              <AlertDescription>
                <SafeText>{exportRefusal(restore.error, "restore")}</SafeText>
              </AlertDescription>
            </Alert>
          )}
          {restoreIssues.length > 0 && <IssueList issues={restoreIssues} title="What the document fails" />}
          {result && (
            <div className="space-y-2" data-testid="restore-result">
              <p className="text-sm">
                Restored. Each feed provider's first check is due at once; until their feeds have runs, edges keep the bundle heads they run.
              </p>
              {result.missing_secrets.length > 0 && (
                <Alert variant="warning">
                  <TriangleAlertIcon />
                  <AlertTitle>Secrets still missing a value</AlertTitle>
                  <AlertDescription>
                    <span>
                      {result.missing_secrets.map(escapeControl).join(", ")} —{" "}
                      <Link to="/settings" search={{ tab: "secrets" }} className="underline">
                        set them under Secrets
                      </Link>
                      .
                    </span>
                  </AlertDescription>
                </Alert>
              )}
              {result.warnings.length > 0 && (
                <Alert variant="warning">
                  <TriangleAlertIcon />
                  <AlertTitle>Core's warnings</AlertTitle>
                  <AlertDescription>
                    <ul className="list-disc pl-4">
                      {result.warnings.map((w, i) => (
                        <li key={i}>
                          <SafeText>{w}</SafeText>
                        </li>
                      ))}
                    </ul>
                  </AlertDescription>
                </Alert>
              )}
            </div>
          )}
        </div>
      </Section>
    </div>
  );
}

function ChangesTab() {
  const q = useInfiniteQuery({
    queryKey: qk.changes,
    queryFn: ({ pageParam, signal }) => unwrap(client.GET("/api/ui/v1/config-changes", { params: { query: { cursor: pageParam, limit: 100 } }, signal })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (p) => p.next_cursor ?? undefined,
  });
  const [open, setOpen] = React.useState<number | null>(null);
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.data === undefined) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={6} />;
  // Once rows show, a failed refresh or "Load more" keeps them, and the open diff (PagedListError).
  return (
    <Section title="Change journal" description="Every configuration change, newest first; diffs are redacted.">
      <PagedListError query={q} placement="top" what="more changes" />
      <Table aria-label="Change journal">
        <TableHeader>
          <TableRow>
            <TableHead>When</TableHead>
            <TableHead>Entity</TableHead>
            <TableHead>Id</TableHead>
            <TableHead>From</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableRow>
              <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                No changes in the retention window.
              </TableCell>
            </TableRow>
          )}
          {items.map((c) => (
            <React.Fragment key={c.id}>
              <TableRow className="cursor-pointer" tabIndex={0} onClick={() => setOpen(open === c.id ? null : c.id)} onKeyDown={(e) => e.key === "Enter" && setOpen(open === c.id ? null : c.id)}>
                <TableCell className="whitespace-nowrap text-xs">{formatTime(c.at)}</TableCell>
                <TableCell>{c.entity}</TableCell>
                <TableCell>
                  <SafeText mono>{c.entity_id}</SafeText>
                </TableCell>
                <TableCell>
                  <SafeText mono>{c.source_ip}</SafeText>
                </TableCell>
              </TableRow>
              {open === c.id && (
                <TableRow>
                  <TableCell colSpan={4}>
                    <JsonBlock value={c.diff} />
                  </TableCell>
                </TableRow>
              )}
            </React.Fragment>
          ))}
        </TableBody>
      </Table>
      <PagedListError query={q} placement="bottom" what="more changes" />
      {q.hasNextPage && (
        <Button className="mt-3" variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
          Load more
        </Button>
      )}
    </Section>
  );
}
