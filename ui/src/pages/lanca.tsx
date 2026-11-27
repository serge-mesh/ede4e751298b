// Settings → LAN CA (core.md §11 `lanca.zones`, §12; security.md §2): the current root, a zones
// change (a new root: core rotates it when the request names the root it replaces,
// `lanca.rotate_from`; lanca::rotation), the previous roots core still trusts with the edges whose
// listeners haven't reported a certificate from the current root, and core's refusals in words.
import * as React from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { CircleCheckIcon, ClockAlertIcon, DownloadIcon, RotateCwIcon, TriangleAlertIcon } from "lucide-react";
import { KeyValue, Section } from "@/components/common/page";
import { useDraft } from "@/components/common/drafts";
import { ErrorState, LoadingState, RefetchError } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { CopyField } from "@/components/common/copy-button";
import { Confirm } from "@/components/common/confirm";
import { TagInput } from "@/components/common/tag-input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { LANCA_ROOT_CHANGED, RotationAnswerLost, StaleRoot, isCoreUnavailable, useRotateLanca, useSettings } from "@/api/queries";
import { lancaEventOf, useUiEvent } from "@/api/events";
import { ApiError, errorMessage } from "@/api/errors";
import type { LancaEvent, LancaView, PreviousRootView, SettingsView } from "@/api/types";

export { answerLost } from "@/api/queries";
import { formatTime } from "@/lib/format";
import { escapeControl } from "@/lib/text";

/** Core's web settings as far as a rotation concerns this browser: its certificate and the plain-HTTP port. */
type WebTls = { tls?: string | null; http_port?: number | null } | undefined;

/** True when core's web certificate comes from the LAN CA (`web.tls` managed, the default): a rotation re-issues it at once. */
const managedWeb = (web: WebTls) => (web?.tls ?? "managed") === "managed";

/** The root's URL on core's plain-HTTP port (`web.http_port`, for browsers that don't trust the root yet: core.md §11), when set. */
export function plainRootUrl(web: WebTls, download: string): string | null {
  return web?.http_port ? `http://${window.location.hostname}:${web.http_port}${download}` : null;
}

/**
 * What a zones change does (core.md §11: "a new CA root, trusted again on every device";
 * lanca::rotation), said before it is made, for core's web settings: the devices fail as soon as
 * their edge re-issues its listener certificates, and with `web.tls` managed core's web
 * certificate is re-issued at once, so this browser loses the page on its next connection.
 */
export function rotationSteps(web: WebTls): string[] {
  const steps = [
    "Core makes a new CA root for the new zones. Each edge re-issues its DoT and DoH listener certificates from it by itself, an online edge within moments, an offline one when it reconnects; devices using its listeners fail as soon as it does, until they trust the new root. Install it on each device right after the change.",
  ];
  if (managedWeb(web))
    steps.push(
      `Core's web certificate is re-issued from the new root at once: this browser loses this page on its next connection to core. Install the new root on this browser right after the change (download it on this page)${web?.http_port ? `, or get it over the plain-HTTP port ${web.http_port}` : ""}.`,
    );
  steps.push("Core keeps trusting the old root for its own connections to the edges until every edge reports its DoT and DoH listeners serving certificates from the new one; the zones can't change again before that.");
  return steps;
}

/** How often the LAN CA tab reads the settings again while core's clock isn't synchronised (core sends no event when it is). */
export const CLOCK_POLL_MS = 30_000;

/** The LAN CA tab's polling: while the view read last says the clock isn't synchronised. */
export const clockPoll = (view: SettingsView | undefined) => (view?.lanca?.clock_synced === false ? CLOCK_POLL_MS : false);

/** What a rotation did (`rotationOutcome`). */
export type RotationOutcome =
  | { kind: "rotated" | "kept"; fingerprint: string; zones: string[] }
  | { kind: "unknown"; why: "unchanged" | "elsewhere" | "unreadable" };

/**
 * What a rotation from root `from` to `zones` did, by the LAN CA core has after it (`now`; null
 * when it couldn't be read). `answered`: `now` is core's own answer to the request, so a new root
 * is its rotation (or, to the same zones, one that finished meanwhile) and the same root means
 * core kept it (the zones are the ones it has). After a lost answer, a new root for these zones
 * is taken as this rotation (either way the root to trust now); one for other zones is another
 * change's; the same root (or none read) leaves the outcome unknown, since core may still commit.
 */
export function rotationOutcome(from: string, zones: string[], now: Pick<LancaView, "fingerprint" | "zones"> | null, answered: boolean): RotationOutcome {
  if (!now) return { kind: "unknown", why: "unreadable" };
  if (now.fingerprint === from) return answered ? { kind: "kept", fingerprint: now.fingerprint, zones: now.zones } : { kind: "unknown", why: "unchanged" };
  if (answered || sameZones(now.zones, zones)) return { kind: "rotated", fingerprint: now.fingerprint, zones: now.zones };
  return { kind: "unknown", why: "elsewhere" };
}

/** lanca::normalize_zones as far as the UI can: trimmed, lowercase, no trailing dot, each once (core checks the names and refuses public suffixes). */
export function normalizeZones(zones: string[]): string[] {
  const out: string[] = [];
  for (const z of zones) {
    const n = z.trim().replace(/\.$/, "").toLowerCase();
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

/** lanca::same_zones: zones compare as sets. */
export function sameZones(a: string[], b: string[]): boolean {
  const x = new Set(normalizeZones(a));
  const y = new Set(normalizeZones(b));
  return x.size === y.size && [...x].every((z) => y.has(z));
}

/** A refusal of a zones change, in words. */
export interface ZonesRefusal {
  /**
   * `in-use`: a previous root is still in use (409 `conflict`); `stale`: the root the change named
   * is no longer the current one (409 `lanca_root_changed`, another change replaced it); `clock`:
   * core's clock isn't synchronised (503); `orphans`: names the new zones wouldn't cover (422);
   * `other`: anything else.
   */
  kind: "in-use" | "stale" | "clock" | "orphans" | "other";
  title: string;
  /** Core's own message: it names the edges and listeners, the roots, or the names. */
  message: string;
}

/**
 * Core's refusals of a zones change (PUT settings, lanca::rotation), told apart by status and code
 * (core 07acc1c): `409 lanca_root_changed` when the root named in `lanca.rotate_from` was replaced
 * meanwhile (`StaleRoot`: reload and decide again), `409 conflict` while a previous root is still
 * in use (the last rotation is still reaching the edges: wait for `lanca.can_rotate`), `503
 * unavailable` while core's clock isn't synchronised (a 503 without core's code is a proxy's: the
 * answer was lost, `answerLost`), `422` for names in use the new zones wouldn't cover (managed
 * listener names, `web.names`), or zones core won't take (not a DNS name, a public suffix).
 * Nothing changes on a refusal.
 */
export function zonesRefusal(e: unknown): ZonesRefusal {
  const message = errorMessage(e);
  if (e instanceof StaleRoot || (e instanceof ApiError && e.status === 409 && e.code === LANCA_ROOT_CHANGED))
    return { kind: "stale", title: "The LAN CA root changed since you started editing", message };
  if (e instanceof ApiError && e.status === 409 && e.code === "conflict") return { kind: "in-use", title: "The previous root is still in use", message };
  if (isCoreUnavailable(e)) return { kind: "clock", title: "Core's clock isn't synchronised yet", message };
  if (e instanceof ApiError && e.status === 422 && /would orphan names in use/.test(e.message)) return { kind: "orphans", title: "Names to move first", message };
  return { kind: "other", title: "Core refused the zones", message };
}

/** Why the zones can't change now (core.md §11; the settings' LAN CA view), or null when they can. */
export function rotationBlocked(ca: Pick<LancaView, "can_rotate" | "clock_synced">): "in-use" | "clock" | null {
  if (!ca.can_rotate) return "in-use";
  if (!ca.clock_synced) return "clock";
  return null;
}

/**
 * The last `lanca` UI event since the LAN CA tab opened, naming the roots a rotation replaced or
 * dropped. Leaving the tab forgets it: its news ("the rotation finished") ends with the visit.
 */
function useLastLancaEvent(): LancaEvent | undefined {
  const [last, setLast] = React.useState<LancaEvent>();
  useUiEvent((ev) => {
    const l = ev.type === "lanca" ? lancaEventOf(ev.data) : null;
    if (l) setLast(l);
  });
  return last;
}

/**
 * The root core stopped trusting, when the last `lanca` event says a rotation finished
 * (`previous_dropped`) and the settings agree: its root is still the current one and the dropped
 * root is no longer listed. Null otherwise.
 */
export function finishedRotation(last: LancaEvent | undefined, ca: Pick<LancaView, "fingerprint" | "previous">): string | null {
  if (last?.event !== "previous_dropped" || last.current !== ca.fingerprint) return null;
  return ca.previous.some((r) => r.fingerprint === last.previous) ? null : last.previous;
}

/** The root the current one replaced, when the last `lanca` event says so (`rotated` to this root). Null otherwise. */
export function replacedRoot(last: LancaEvent | undefined, current: string): string | null {
  return last?.event === "rotated" && last.root === current ? last.previous : null;
}

/** Settings → LAN CA. */
export function LancaTab() {
  const q = useSettings({ refetchInterval: clockPoll });
  if (q.data === undefined) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={6} />;
  const ca = q.data.lanca;
  /** The settings read again; throws when they can't be (the page keeps the view it had). */
  const reload = async () => {
    const r = await q.refetch();
    if (!r.isSuccess) throw r.error ?? new Error("The settings couldn't be read.");
    return r.data;
  };
  return (
    <div className="space-y-4">
      {q.error && <RefetchError error={q.error} onRetry={() => void q.refetch()} />}
      <CurrentRoot ca={ca} />
      {ca.previous.length > 0 && <PreviousRoots previous={ca.previous} />}
      <ZonesForm view={q.data} readAt={q.dataUpdatedAt} reload={reload} />
    </div>
  );
}

function CurrentRoot({ ca }: { ca: LancaView }) {
  return (
    <Section title="Current root" description="Signs edge listener certificates and core's web certificate, for names under its zones only. Install it on the devices that use DoT or DoH listeners.">
      <KeyValue
        items={[
          ["Fingerprint", <CopyField value={ca.fingerprint} label="Copy root fingerprint" />],
          ["Zones", <SafeText mono>{ca.zones.join(", ")}</SafeText>],
          ["Made", ca.created_at ? formatTime(ca.created_at) : "—"],
          [
            "Download",
            <span className="flex flex-wrap gap-2">
              <Button asChild size="sm" variant="outline">
                <a href={ca.download} download>
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
    </Section>
  );
}

function PreviousRoots({ previous }: { previous: PreviousRootView[] }) {
  return (
    <Section
      title="Previous roots still in use"
      description="Core keeps trusting a previous root until every edge reports its DoT and DoH listeners serving certificates from the current root. An online edge asks for them within moments and reports them right after, an offline one when it reconnects; removing the listener from the edge, or the edge, also ends the use. The zones can't change again until this list is empty."
    >
      <div className="space-y-4">
        {previous.map((r) => (
          <div key={r.fingerprint} className="space-y-2 rounded-md border p-3" data-testid="previous-root">
            <KeyValue
              items={[
                ["Fingerprint", <CopyField value={r.fingerprint} label="Copy previous root fingerprint" />],
                ["Zones", <SafeText mono>{r.zones.join(", ")}</SafeText>],
                ["In use", `${formatTime(r.created_at)} to ${formatTime(r.retired_at)} (replaced)`],
              ]}
            />
            <Table aria-label={`Edges keeping root ${r.fingerprint} in use`}>
              <TableHeader>
                <TableRow>
                  <TableHead>Edge</TableHead>
                  <TableHead title="Their last report names the previous root, another one, or no certificate yet">Listeners not on the current root yet</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {r.edges.map((e) => (
                  <TableRow key={e.edge_id}>
                    <TableCell>
                      <Link to="/edges/$edgeId" params={{ edgeId: e.edge_id }} className="hover:underline">
                        <SafeText>{e.edge_name || e.edge_id}</SafeText>
                      </Link>
                    </TableCell>
                    <TableCell>
                      <SafeText mono>{e.listeners.join(", ")}</SafeText>
                    </TableCell>
                    <TableCell>
                      {e.online ? (
                        <Badge variant="success" title="It asks for certificates from the current root within moments and reports them right after">
                          online
                        </Badge>
                      ) : (
                        <Badge variant="outline" title="It asks for certificates from the current root when it reconnects">
                          offline
                        </Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ))}
      </div>
    </Section>
  );
}

/** A rotation's result shown under the zones: core's new root and the root it replaced (`from`), or the root it kept. */
type Done = { kind: "rotated" | "kept"; fingerprint: string; zones: string[]; from: string };

/**
 * A rotation whose answer was lost (`RotationAnswerLost`) without a new root for its zones to
 * show for it: `why` as `rotationOutcome` says, judged at `at`. Unless the root went to other
 * zones (`elsewhere`), core may still commit it, so the form takes a later new root for these
 * zones as this rotation's, and settings read after `at` that still name `from` make an
 * `unreadable` one `unchanged`.
 */
type Unknown = { why: "unchanged" | "elsewhere" | "unreadable"; from: string; zones: string[]; message: string; at: number };

/**
 * The zones, editable: a change is a new root (`rotationSteps`), confirmed first and sent as
 * `{lanca: {zones, rotate_from}}`, `rotate_from` the root the draft was edited against (`base`):
 * core rotates only from that root, so a draft begun before another change can't replace a root
 * nobody looked at (`409 lanca_root_changed`: Reload settings, then decide again). A clean form
 * follows a new root; a dirty one keeps its draft and says the root changed (naming the root it
 * replaced when this tab got core's `lanca` event), offering Reload or Keep my zones (then the
 * next change is from the current root). No change is offered while a previous root is in use or
 * core's clock isn't synchronised (core refuses it: `409 conflict`, shown until `can_rotate` says
 * the wait is over, and `503`). The result is judged by the root core has (`rotationOutcome`): its
 * answer's, or after a lost answer the settings read again, so a committed rotation shows as done
 * even when its answer never came; `previous_dropped` says the rotation finished.
 */
function ZonesForm({ view, readAt, reload }: { view: SettingsView; readAt: number; reload: () => Promise<SettingsView> }) {
  const ca = view.lanca;
  const web = view.settings.web;
  const [base, setBase] = React.useState({ fingerprint: ca.fingerprint, zones: ca.zones });
  const [draft, setDraft] = React.useState<string[]>(ca.zones);
  /** Core's refusal; `reloadFailed`: why Reload settings couldn't read them after it (it stands). */
  const [refusal, setRefusal] = React.useState<(ZonesRefusal & { reloadFailed?: string }) | null>(null);
  /** When core refused (ms): a previous root's use is over only by settings read after that. */
  const [refusedAt, setRefusedAt] = React.useState(0);
  const [done, setDone] = React.useState<Done | null>(null);
  const [unknown, setUnknown] = React.useState<Unknown | null>(null);
  const [reloading, setReloading] = React.useState(false);
  const rotate = useRotateLanca();
  const last = useLastLancaEvent();
  /** Shows a rotation's result; a new or kept root becomes the draft's base, its zones as core keeps them (its normal form). */
  const settle = (o: Done) => {
    setDone(o);
    setUnknown(null);
    setBase({ fingerprint: o.fingerprint, zones: o.zones });
    setDraft(o.zones);
  };
  if (unknown && unknown.why !== "elsewhere") {
    if (ca.fingerprint !== unknown.from) {
      // The root changed after a lost answer (core's `lanca` event, a refresh): this rotation if
      // the new root is for its zones, another change's if not.
      const o = rotationOutcome(unknown.from, unknown.zones, ca, false);
      if (o.kind === "rotated") settle({ ...o, from: unknown.from });
      else setUnknown({ ...unknown, why: "elsewhere" });
    } else if (unknown.why === "unreadable" && readAt > unknown.at) {
      // Read again since, still the root it changed from.
      setUnknown({ ...unknown, why: "unchanged" });
    }
  }
  // Not while this tab's rotation is out: core sends its `lanca rotated` event before its answer,
  // so the new root can show first; the answer says whose it is.
  const moved = !rotate.isPending && ca.fingerprint !== base.fingerprint;
  if (moved && sameZones(draft, base.zones)) {
    // A clean form follows the root core has now (a change from another tab, or this one's).
    setBase({ fingerprint: ca.fingerprint, zones: ca.zones });
    setDraft(ca.zones);
  }
  const zones = normalizeZones(draft);
  const changed = !sameZones(zones, ca.zones);
  useDraft(!sameZones(draft, base.zones));
  const blocked = rotationBlocked(ca);
  const managed = managedWeb(web);
  const plainUrl = plainRootUrl(web, ca.download);
  const plainLink = plainUrl && (
    <a href={plainUrl} className="text-primary underline">
      plain-HTTP port {web?.http_port}
    </a>
  );
  const rebase = (keepDraft: boolean, to: Pick<LancaView, "fingerprint" | "zones"> = ca) => {
    setBase({ fingerprint: to.fingerprint, zones: to.zones });
    if (!keepDraft) setDraft(to.zones);
    setRefusal(null);
    setUnknown(null);
  };
  /**
   * Core's `409 lanca_root_changed`: the settings read again, the draft on the root core has now,
   * to decide again. When they can't be read the refusal stays (the page may still have the
   * replaced root), saying so.
   */
  const reloadSettings = async () => {
    setReloading(true);
    try {
      rebase(false, (await reload()).lanca);
    } catch (e) {
      setRefusal((r) => r && { ...r, reloadFailed: errorMessage(e) });
    } finally {
      setReloading(false);
    }
  };
  const submit = () => {
    setRefusal(null);
    setDone(null);
    setUnknown(null);
    const from = base.fingerprint;
    const judge = (o: RotationOutcome, message: string) => {
      if (o.kind === "unknown") {
        setUnknown({ why: o.why, from, zones, message, at: Date.now() });
        return;
      }
      settle({ ...o, from });
      if (o.kind === "rotated") toast.success("A new LAN CA root is in place");
    };
    rotate.mutate(
      { zones, from },
      {
        onSuccess: (next) => judge(rotationOutcome(from, zones, next.lanca, true), ""),
        onError: (e) => {
          if (e instanceof RotationAnswerLost) judge(rotationOutcome(from, zones, e.now?.lanca ?? null, false), errorMessage(e.lost));
          else {
            setRefusal(zonesRefusal(e));
            setRefusedAt(Date.now());
          }
        },
      },
    );
  };
  const steps = rotationSteps(web);
  // A previous root in use when core refused: the wait is over once core can rotate again.
  const waited = refusal?.kind === "in-use" && ca.can_rotate && readAt > refusedAt;
  const replaced = replacedRoot(last, ca.fingerprint);
  const finished = refusal ? null : finishedRotation(last, ca);
  return (
    <Section title="Zones" description="The DNS names the LAN CA may sign: managed listener names and core's web.names must be under them.">
      <div className="space-y-4">
        {done?.kind === "rotated" && (
          <Alert data-testid="lanca-rotated">
            <RotateCwIcon />
            <AlertTitle>New root for {escapeControl(done.zones.join(", "))}</AlertTitle>
            <AlertDescription>
              <p>
                Download it above and trust it on every device again (fingerprint <Mono>{escapeControl(done.fingerprint)}</Mono>, replacing root <Mono>{escapeControl(done.from)}</Mono>):
              </p>
              <ul className="list-disc pl-4">
                {managed && (
                  <li>
                    on this browser now: core's web certificate already comes from the new root, so this page fails on the browser's next connection to core{plainLink ? <>; if it does, get the root over the {plainLink}</> : null}.
                  </li>
                )}
                <li>on each device that uses the DoT or DoH listeners: each fails as soon as its edge re-issues its listener certificates, an online edge within moments, an offline one when it reconnects.</li>
              </ul>
              <p>The old root shows under the previous roots until every edge reports certificates from the new one.</p>
            </AlertDescription>
          </Alert>
        )}
        {done?.kind === "kept" && (
          <Alert data-testid="lanca-kept">
            <RotateCwIcon />
            <AlertTitle>The root stays</AlertTitle>
            <AlertDescription>
              <p>
                Core has these zones already, as it writes them (<Mono>{escapeControl(done.zones.join(", "))}</Mono>), so root <Mono>{escapeControl(done.fingerprint)}</Mono> stays. Nothing changed.
              </p>
            </AlertDescription>
          </Alert>
        )}
        {unknown && (
          <Alert variant="warning" data-testid="lanca-unknown">
            <TriangleAlertIcon />
            <AlertTitle>Core's answer was lost</AlertTitle>
            <AlertDescription>
              <p>
                <SafeText>{unknown.message}</SafeText>
              </p>
              {unknown.why === "unchanged" && (
                <p>
                  Core still names root <Mono>{escapeControl(unknown.from)}</Mono>: it made no new root, or is still making it. This page shows the new root if core makes it; if nothing changes, try again.
                </p>
              )}
              {unknown.why === "elsewhere" && <p>The root is now one for other zones, from another change (above): check it, then decide again.</p>}
              {unknown.why === "unreadable" && (
                <p>
                  Core's settings can't be read now either, so whether it made the new root isn't known.
                  {managed && (
                    <>
                      {" "}
                      If it did, this browser can't reach core's pages until it trusts the new root (core's web certificate comes from it): {plainLink ? <>download it over the {plainLink}</> : <>copy <Mono>lanca/ca.crt</Mono> from core's data directory</>}, install it, then reload this page.
                    </>
                  )}
                </p>
              )}
            </AlertDescription>
          </Alert>
        )}
        {finished && (
          <Alert data-testid="lanca-finished">
            <CircleCheckIcon />
            <AlertTitle>The rotation finished</AlertTitle>
            <AlertDescription>
              <p>
                Core no longer trusts the previous root <Mono>{escapeControl(finished)}</Mono>: every edge reported its listeners serving certificates from the current root.
              </p>
            </AlertDescription>
          </Alert>
        )}
        {/* Core's own 409 for a replaced root says the same, with its action (below). */}
        {moved && refusal?.kind !== "stale" && (
          <Alert variant="warning" data-testid="lanca-moved">
            <TriangleAlertIcon />
            <AlertTitle>The LAN CA root changed since you started editing</AlertTitle>
            <AlertDescription>
              <p>
                It is now <Mono>{escapeControl(ca.fingerprint)}</Mono> for <Mono>{escapeControl(ca.zones.join(", "))}</Mono>
                {replaced && (
                  <>
                    , replacing root <Mono>{escapeControl(replaced)}</Mono>
                  </>
                )}
                . Reload the zones, or keep yours: a change then replaces the current root.
              </p>
              <span className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => rebase(false)}>
                  Reload
                </Button>
                <Button size="sm" variant="outline" onClick={() => rebase(true)}>
                  Keep my zones
                </Button>
              </span>
            </AlertDescription>
          </Alert>
        )}
        {refusal && (
          <Alert variant={waited ? "default" : refusal.kind === "in-use" || refusal.kind === "clock" ? "warning" : "destructive"} data-testid="lanca-refusal">
            {waited ? <CircleCheckIcon /> : <TriangleAlertIcon />}
            <AlertTitle>{waited ? "The previous root is no longer in use" : refusal.title}</AlertTitle>
            <AlertDescription>
              {/* Core's words name what was in use then. */}
              {!waited && (
                <p>
                  <SafeText>{refusal.message}</SafeText>
                </p>
              )}
              {refusal.kind === "orphans" && <p>Rename those names first, or move in two steps: add the new zone next to the old one, rename, then remove the old zone. Each change is a new root. Nothing was changed.</p>}
              {refusal.kind === "in-use" &&
                (waited ? (
                  <p>Nothing was changed then. Every edge now serves certificates from the current root: change the zones again when ready.</p>
                ) : (
                  <p>Nothing was changed. Wait until every edge listed above reports its listeners serving certificates from the current root: this page follows their reports and offers the change again then.</p>
                ))}
              {refusal.kind === "stale" && (
                <>
                  <p>
                    Another change replaced the root you edited against
                    {moved && (
                      <>
                        {" "}
                        (now <Mono>{escapeControl(ca.fingerprint)}</Mono> for <Mono>{escapeControl(ca.zones.join(", "))}</Mono>)
                      </>
                    )}
                    . Nothing was changed: reload the settings and decide again.
                  </p>
                  {refusal.reloadFailed && (
                    <p className="text-destructive">
                      Couldn't read the settings: <SafeText>{refusal.reloadFailed}</SafeText>. Try Reload settings again.
                    </p>
                  )}
                  <span className="flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" onClick={() => void reloadSettings()} disabled={reloading}>
                      Reload settings
                    </Button>
                  </span>
                </>
              )}
              {refusal.kind === "clock" && <p>Nothing was changed. Try again once core's host has synchronised its clock (NTP).</p>}
            </AlertDescription>
          </Alert>
        )}
        {blocked === "in-use" && refusal?.kind !== "in-use" && (
          <Alert variant="warning" data-testid="lanca-blocked">
            <TriangleAlertIcon />
            <AlertTitle>The last zones change is still reaching the edges</AlertTitle>
            <AlertDescription>The zones can change again once every edge reports its listeners serving certificates from the current root (see the previous roots above).</AlertDescription>
          </Alert>
        )}
        {blocked === "clock" && (
          <Alert variant="warning" data-testid="lanca-clock">
            <ClockAlertIcon />
            <AlertTitle>Core's clock isn't synchronised yet</AlertTitle>
            <AlertDescription>A new root and the certificates it signs carry dates, and a root dated wrongly would leave every certificate invalid, so core makes no new root until its clock is synchronised. Check NTP on core's host; this page checks again every {CLOCK_POLL_MS / 1000} seconds and offers the change once it is.</AlertDescription>
          </Alert>
        )}
        <div className="max-w-xl space-y-1.5">
          <Label htmlFor="lanca-zones">Zones</Label>
          <TagInput id="lanca-zones" value={draft} onChange={setDraft} disabled={rotate.isPending} placeholder="home.arpa" aria-describedby="lanca-zones-help" />
          <p id="lanca-zones-help" className="text-xs text-muted-foreground">
            home.arpa, or zones under a domain you own: core refuses public suffixes.
          </p>
        </div>
        <Alert variant="warning">
          <TriangleAlertIcon />
          <AlertTitle>Changing the zones makes a new CA root</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-4" aria-label="What a zones change does">
              {steps.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
        <div className="flex flex-wrap gap-2">
          <Confirm
            title="Make a new LAN CA root?"
            description={
              <div className="space-y-2">
                <p>
                  New zones: <Mono>{escapeControl(zones.join(", "))}</Mono> (now <Mono>{escapeControl(ca.zones.join(", "))}</Mono>), replacing root <Mono>{escapeControl(base.fingerprint)}</Mono>.
                </p>
                <ul className="list-disc pl-4">
                  {steps.map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
              </div>
            }
            confirmLabel="Make a new root"
            destructive
            onConfirm={submit}
          >
            <Button
              disabled={!changed || zones.length === 0 || blocked !== null || moved || refusal?.kind === "stale" || rotate.isPending}
              title={refusal?.kind === "stale" ? "Reload the settings first." : moved ? "Reload or keep your zones first." : undefined}
            >
              <RotateCwIcon /> Change zones…
            </Button>
          </Confirm>
          {changed && (
            <Button variant="outline" onClick={() => setDraft(ca.zones)} disabled={rotate.isPending}>
              Undo
            </Button>
          )}
        </div>
      </div>
    </Section>
  );
}
