import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PageHeader, Section } from "@/components/common/page";
import { ErrorState, LoadingState, PagedListError } from "@/components/common/states";
import { Mono, SafeText } from "@/components/common/text";
import { TimeAgo } from "@/components/common/time";
import { Confirm } from "@/components/common/confirm";
import { EdgeSelector } from "@/components/common/window-picker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { qk, useEdges, usePagedList } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { errorMessage } from "@/api/errors";
import { useConnection } from "@/api/events";
import type { AllowState, AllowView, TempAllowView } from "@/api/types";
import { formatTime } from "@/lib/format";
import { revokeAllow } from "./edge-detail";

/** `GET temp-allows?state` (lookups/api.rs): `active`, or `recent` (ended or past the reported expiry). */
type Wanted = "active" | "recent";

/**
 * How often an open list reads again while the event socket is down. While it is open, core's
 * `temp_allow` events say when allows change (allow records from an edge's log, a revoke
 * requested or acknowledged, a reported expiry passed: api/events.ts), so nothing polls; the lists
 * read once more when it first opens (api/events.ts keptByEvents).
 */
export const TEMP_ALLOWS_POLL = 60_000;

/** One state's allows, newest first, a page of 100 at a time (core filters by state before paging). */
function useTempAllows(state: Wanted, edge: string) {
  const live = useConnection() === "open";
  return usePagedList({
    queryKey: [...qk.tempAllows, state, edge],
    fetchPage: (cursor, signal) =>
      unwrap(
        client.GET("/api/ui/v1/temp-allows", {
          params: { query: { state, edge: edge === "all" ? undefined : edge, cursor, limit: 100 } },
          signal,
        }),
      ),
    rowKey: (a) => `${a.edge}/${a.allow_id}`,
    interval: live ? undefined : TEMP_ALLOWS_POLL,
  });
}

const STATE_TEXT: Record<AllowState, string> = {
  active: "In force on the edge",
  revoked: "The edge applied the revoke; core keeps the allow open until the edge's log reports its end",
  ended: "The edge logged its end",
  expired: "Past the expiry the edge reported, with no later news",
};

/**
 * An allow's state as core gives it (`AllowState`): `active`, `revoked` (the edge acknowledged the
 * revoke and the allow is no longer in force, though its end isn't logged yet), `ended` or
 * `expired`; an allow with a revoke pending says so (core sets `revoke_pending` only on an allow
 * still active: requested, not acknowledged, not ended).
 */
export function AllowStateBadge({ allow }: { allow: Pick<AllowView, "state" | "revoke_acked_at"> & { revoke_pending?: boolean; revoke_requested_at?: string | null } }) {
  if (allow.revoke_pending)
    return (
      <Badge variant="warning" title={allow.revoke_requested_at ? `Requested ${formatTime(allow.revoke_requested_at)}; the edge hasn't acknowledged it yet` : undefined}>
        revoke pending
      </Badge>
    );
  const title = allow.state === "revoked" && allow.revoke_acked_at ? `${STATE_TEXT.revoked} (acknowledged ${formatTime(allow.revoke_acked_at)})` : STATE_TEXT[allow.state];
  return (
    <Badge variant={allow.state === "active" ? "success" : allow.state === "revoked" ? "warning" : "secondary"} title={title}>
      {allow.state}
    </Badge>
  );
}

/** Who an allow is for: the device (its client name or MAC), with the address it was made from. */
export function AllowDevice({ allow }: { allow: Pick<AllowView, "device" | "client"> }) {
  return (
    <span className="flex flex-col">
      <SafeText>{allow.device ?? allow.client ?? "?"}</SafeText>
      {allow.device && allow.client && (
        <span className="text-xs text-muted-foreground">
          from <SafeText mono>{allow.client}</SafeText>
        </span>
      )}
    </span>
  );
}

/** Temporary allows across edges (core.md §12): active and recent, with revoke. */
export function TemporaryAllowsPage() {
  const [edge, setEdge] = React.useState("all");
  return (
    <div className="space-y-4">
      <PageHeader
        title="Temporary allows"
        description={
          <>
            Time-limited exceptions for one device, by block id (DNS) or by IP, made from the browser extension. A revoke stays pending until the edge acknowledges it in its{" "}
            <Mono>revoked_allows</Mono>; the allow is then <em>revoked</em> until the edge's log reports its end.
          </>
        }
        actions={<EdgeSelector value={edge} onChange={setEdge} />}
      />
      <AllowSection state="active" edge={edge} />
      <AllowSection state="recent" edge={edge} />
    </div>
  );
}

function AllowSection({ state, edge }: { state: Wanted; edge: string }) {
  const q = useTempAllows(state, edge);
  const edges = useEdges();
  const qc = useQueryClient();
  const [busy, setBusy] = React.useState<string | null>(null);
  const edgeName = new Map((edges.data ?? []).map((e) => [e.id ?? "", e.name || e.id || ""]));
  const active = state === "active";
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  const title = active ? "Active" : "Recent";
  const description = active
    ? "Not ended, not revoked, and not past the expiry the edge reported (the extension can extend an allow core can't see). A revoke pending shows here until the edge acknowledges it."
    : "Revoked (the edge acknowledged the revoke; its end isn't logged yet), ended (the edge logged a revoke or the expiry), or past the reported expiry with no later news. Kept for the temp_allows retention.";
  let body: React.ReactNode;
  if (q.data === undefined) body = q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <LoadingState rows={3} />;
  else
    body = (
      <div className="space-y-3">
        <PagedListError query={q} placement="top" what="more allows" />
        <Table aria-label={active ? "Active temporary allows" : "Recent temporary allows"}>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Edge</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>{active ? "Expires" : "Ended or revoked"}</TableHead>
              <TableHead className="text-right">{active ? "Revoke" : "State"}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                  None.
                </TableCell>
              </TableRow>
            )}
            {items.map((a: TempAllowView) => {
              const key = `${a.edge}/${a.allow_id}`;
              return (
                <TableRow key={key}>
                  <TableCell>
                    <span className="flex flex-col">
                      <SafeText mono>{a.target}</SafeText>
                      <span className="text-xs text-muted-foreground" title="The allow's id on its edge">
                        <SafeText mono>{a.allow_id}</SafeText>
                      </span>
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{a.kind ?? "?"}</Badge>
                  </TableCell>
                  <TableCell>
                    <AllowDevice allow={a} />
                  </TableCell>
                  <TableCell>
                    <SafeText>{edgeName.get(a.edge) ?? a.edge}</SafeText>
                  </TableCell>
                  <TableCell>
                    <TimeAgo value={a.created_at} />
                  </TableCell>
                  <TableCell>
                    {/* A revoked allow has no end yet: when the edge acknowledged the revoke. */}
                    <TimeAgo value={active ? a.expires_at : (a.ended_at ?? (a.state === "revoked" ? a.revoke_acked_at : null))} />
                  </TableCell>
                  <TableCell className="text-right">
                    {/* Only an active allow without a revoke pending can be revoked. */}
                    {a.state !== "active" || a.revoke_pending ? (
                      <AllowStateBadge allow={a} />
                    ) : (
                      <Confirm
                        title="Revoke this allow?"
                        description="The edge removes it when it applies the request; an offline edge applies it on reconnect."
                        confirmLabel="Revoke"
                        destructive
                        onConfirm={async () => {
                          setBusy(key);
                          try {
                            await revokeAllow(a.edge, a.allow_id);
                            toast.success("Revoke requested");
                            void qc.invalidateQueries({ queryKey: qk.tempAllows });
                            void qc.invalidateQueries({ queryKey: ["edges"] });
                          } catch (e) {
                            toast.error(errorMessage(e));
                          } finally {
                            setBusy(null);
                          }
                        }}
                      >
                        <Button size="sm" variant="outline" disabled={busy === key}>
                          Revoke
                        </Button>
                      </Confirm>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
        <PagedListError query={q} placement="bottom" what="more allows" />
        {q.hasNextPage && (
          <Button variant="outline" onClick={() => void q.fetchNextPage()} disabled={q.isFetching}>
            Load more
          </Button>
        )}
      </div>
    );
  return (
    <Section title={title} description={description}>
      {body}
    </Section>
  );
}
