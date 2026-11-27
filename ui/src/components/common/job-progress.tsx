// A heavy job's progress as `job` events report it (api.md §7, JobEvent): running, or how it ended.
import { Loader2Icon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { JobEvent } from "@/api/types";
import { formatSeconds } from "@/lib/format";

/** What a job report says, in words. */
export function jobState(j: Pick<JobEvent, "phase" | "outcome" | "ms">): string {
  if (j.phase === "start") return "running";
  const took = j.ms === null || j.ms === undefined ? "" : ` ${j.outcome === "failed" ? "after" : "in"} ${formatSeconds(j.ms / 1000)}`;
  switch (j.outcome) {
    case "ok":
      return `done${took}`;
    case "failed":
      return `failed${took}`;
    case "superseded":
      return "superseded by a newer one before it finished";
    default:
      return "ended";
  }
}

/** A job report as a badge: running, done, failed or superseded. */
export function JobBadge({ j }: { j: Pick<JobEvent, "phase" | "outcome" | "ms"> }) {
  if (j.phase === "start")
    return (
      <Badge variant="secondary">
        <Loader2Icon className="size-3 animate-spin" aria-hidden /> running
      </Badge>
    );
  const v = j.outcome === "ok" ? "success" : j.outcome === "failed" ? "destructive" : "outline";
  return <Badge variant={v}>{jobState(j)}</Badge>;
}
