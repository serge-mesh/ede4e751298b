import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { WINDOWS, WINDOW_SECONDS, type Window } from "@/api/types";
import { useEdges, useSettings } from "@/api/queries";
import { parseDuration } from "@/lib/format";
import { escapeControl } from "@/lib/text";

/** The windows a retention allows: none longer than it (core.md §12). */
export function allowedWindows(retentionS: number | null): Window[] {
  if (retentionS === null) return WINDOWS;
  const w = WINDOWS.filter((x) => WINDOW_SECONDS[x] <= retentionS);
  return w.length ? w : ["1h"];
}

/**
 * The retention that bounds a page's window picker: the dashboard's is the shorter of the
 * metrics and query-log retention; the System page's is metrics retention alone.
 */
export function useWindowBound(kind: "dashboard" | "metrics"): number | null {
  const s = useSettings();
  const r = s.data?.settings.retention;
  if (!r) return null;
  const metrics = parseDuration(r.metrics) ?? null;
  if (kind === "metrics") return metrics;
  const logs = parseDuration(r.query_logs) ?? null;
  if (metrics === null) return logs;
  if (logs === null) return metrics;
  return Math.min(metrics, logs);
}

export function clampWindow(w: Window, allowed: Window[]): Window {
  return allowed.includes(w) ? w : allowed[allowed.length - 1];
}

const LABEL: Record<Window, string> = { "1h": "1 hour", "6h": "6 hours", "24h": "24 hours", "72h": "72 hours" };

export function WindowPicker({ value, onChange, allowed }: { value: Window; onChange: (w: Window) => void; allowed: Window[] }) {
  return (
    <div className="inline-flex rounded-md border p-0.5" role="radiogroup" aria-label="Time window">
      {WINDOWS.map((w) => {
        const ok = allowed.includes(w);
        return (
          <button
            key={w}
            type="button"
            role="radio"
            aria-checked={value === w}
            aria-label={LABEL[w]}
            disabled={!ok}
            title={ok ? LABEL[w] : "Longer than the retention window"}
            onClick={() => onChange(w)}
            className="rounded px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground disabled:cursor-not-allowed disabled:opacity-40 aria-checked:bg-primary aria-checked:text-primary-foreground"
          >
            {w}
          </button>
        );
      })}
    </div>
  );
}

export function EdgeSelector({ value, onChange, allowEach }: { value: string; onChange: (e: string) => void; allowEach?: boolean }) {
  const edges = useEdges();
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger size="sm" aria-label="Edge" className="min-w-40">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All edges</SelectItem>
        {allowEach && <SelectItem value="each">Each edge (one line each)</SelectItem>}
        {(edges.data ?? []).map((e) => (
          <SelectItem key={e.id} value={e.id ?? ""}>
            {escapeControl(e.name || e.id || "")}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
