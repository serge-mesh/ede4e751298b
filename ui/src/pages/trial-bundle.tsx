import { Link, useParams } from "@tanstack/react-router";
import { toast } from "sonner";
import { InfoIcon } from "lucide-react";
import { PageHeader, Section, Stat } from "@/components/common/page";
import { QueryView } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { Confirm } from "@/components/common/confirm";
import { EdgeSelector, WindowPicker } from "@/components/common/window-picker";
import { MetricPanel } from "@/components/charts/metric-panel";
import { sumSeries } from "@/components/charts/series";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useEntity, useMetrics, useModifyEntity } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { useQuery } from "@tanstack/react-query";
import { enforceTrial } from "./profiles";
import { errorMessage } from "@/api/errors";
import { formatCompact } from "@/lib/format";
import { escapeControl } from "@/lib/text";
import { useWindowState } from "./dashboard";

/**
 * What a trial check can't see, as core words it (logs/query.rs `trial_results` `limits`; core.md
 * §12 Trial bundles): shown until core's own list arrives, and when it can't be read.
 */
export const TRIAL_LIMITS = [
  "Only logged queries are checked: a profile with log: blocked or off sends core no allowed queries.",
  "Results arrive after ingest.",
  "The ladder isn't replayed with the bundle added: a name response checks would still let through counts too, and sync lookups are approximated from the logged verdicts.",
];

/** One trial bundle's would-blocks in one profile (core.md §12 Profiles → Trial bundles). */
export function TrialBundlePage() {
  const { profileId, bundleId } = useParams({ strict: false }) as { profileId: string; bundleId: string };
  const { window, edge, allowed, setWindow, setEdge } = useWindowState("dashboard");
  const profile = useEntity("profiles", profileId);
  const save = useModifyEntity("profiles");
  const series = `trial_would_block`;
  // Core counts trial_would_block per edge (edge=all sums them), so the graph follows the edge
  // selector like the rest of the page.
  const totals = useMetrics([series], window, edge);
  const results = useQuery({
    queryKey: ["trial-results", profileId, bundleId, window, edge],
    queryFn: ({ signal }) => unwrap(client.GET("/api/ui/v1/trial-results", { params: { query: { profile: profileId, bundle: bundleId, window, edge } }, signal })),
  });
  const lineOf = (l: { labels?: Record<string, string> }) => l.labels?.profile === profileId && l.labels?.bundle === bundleId;
  // trial-results counts the would-blocks in the logged records of the window; the metric is the
  // same count, binned (shown until trial-results arrives).
  const fromMetric = totals.data ? sumSeries({ ...totals.data, series: totals.data.series.filter(lineOf) }, series) : null;
  const total = results.data?.total ?? fromMetric;
  const limits = results.data?.limits ?? TRIAL_LIMITS;
  const onTrial = profile.data?.trial_bundles?.includes(bundleId);
  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span>
            Trial of <Mono>{escapeControl(bundleId)}</Mono> in <Mono>{escapeControl(profileId)}</Mono>
          </span>
        }
        description={
          <Link to="/profiles/$profileId" params={{ profileId }} className="text-primary hover:underline">
            ← Profile
          </Link>
        }
        actions={
          <>
            <WindowPicker value={window} onChange={setWindow} allowed={allowed} />
            <EdgeSelector value={edge} onChange={setEdge} />
            {profile.data && onTrial && (
              <Confirm
                title={`Enforce ${escapeControl(bundleId)}?`}
                description="Moves it from the trial list to the end of the profile's block list, as a normal config change."
                confirmLabel="Enforce"
                onConfirm={() =>
                  save.mutate(
                    { id: profileId, change: (p) => enforceTrial(p, bundleId) },
                    { onSuccess: (o) => toast.success(o ? "Enforced" : "Already enforced"), onError: (e) => toast.error(errorMessage(e)) },
                  )
                }
              >
                <Button disabled={save.isPending}>Enforce</Button>
              </Confirm>
            )}
            {profile.data && !onTrial && <Badge variant="secondary">not on trial in this profile</Badge>}
          </>
        }
      />
      <Alert>
        <InfoIcon />
        <AlertTitle>What a trial checks</AlertTitle>
        <AlertDescription>
          {/* Core's own list (trial-results `limits`), so the wording follows what the check does. */}
          <ul className="list-disc pl-4" aria-label="What the trial check can't see">
            {limits.map((l) => (
              <li key={l}>
                <SafeText>{l}</SafeText>
              </li>
            ))}
          </ul>
        </AlertDescription>
      </Alert>
      <div className="grid gap-3 sm:grid-cols-3">
        <Stat label="Would-blocks" value={formatCompact(total)} hint={`over ${window}`} />
      </div>
      <MetricPanel title="Would-blocks over time" series={[series]} window={window} edge={edge} transform={(ls) => ls.filter(lineOf)} specs={[{ match: () => true, label: "would-blocks" }]} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Top names" description="With the feeds and rules that matched each.">
          <QueryView query={results} what="Trial results" rows={5} empty={<p className="text-sm text-muted-foreground">No would-blocks in this window.</p>} isEmpty={(d) => d.names.length === 0}>
            {(d) => (
              <ul className="space-y-2 text-sm">
                {d.names.map((n) => (
                  <li key={n.name} className="rounded-md border p-2">
                    <div className="flex items-center justify-between gap-2">
                      <SafeText mono>{n.name}</SafeText>
                      <span className="text-xs text-muted-foreground">
                        {n.stage && <Badge variant="outline" className="mr-2">{escapeControl(n.stage)}</Badge>}
                        {formatCompact(n.count)}
                      </span>
                    </div>
                    {n.matches.map((m, i) => (
                      <div key={i} className="mt-1 text-xs">
                        <Link to="/feeds/$feedId" params={{ feedId: m.feed }} className="hover:underline">
                          <SafeText>{m.feed}</SafeText>
                        </Link>
                        : <SafeText mono>{m.rule}</SafeText> <span className="text-muted-foreground">({escapeControl(m.role)})</span>
                      </div>
                    ))}
                  </li>
                ))}
              </ul>
            )}
          </QueryView>
        </Section>
        <Section title="Devices affected">
          <QueryView query={results} what="Trial results" rows={5} empty={<p className="text-sm text-muted-foreground">None.</p>} isEmpty={(d) => d.devices.length === 0}>
            {(d) => (
              <ul className="space-y-1 text-sm">
                {d.devices.map((x) => (
                  <li key={x.key} className="flex justify-between gap-2">
                    <Link to="/clients/device" search={{ key: x.key, window, edge }} className="font-mono text-xs hover:underline">
                      <SafeText>{x.key}</SafeText>
                    </Link>
                    <span className="text-xs text-muted-foreground">{formatCompact(x.count)}</span>
                  </li>
                ))}
              </ul>
            )}
          </QueryView>
        </Section>
      </div>
    </div>
  );
}
