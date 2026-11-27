// Formatting helpers for times, durations, sizes and counts.

const UNITS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };

/** Parses a duration such as `30s`, `2m`, `24h`, `7d`, `1w` or `1h30m` into seconds. */
export function parseDuration(d: string | null | undefined): number | null {
  if (!d) return null;
  const re = /(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)/g;
  let total = 0;
  let matched = "";
  for (const m of d.trim().matchAll(re)) {
    matched += m[0];
    total += m[2] === "ms" ? Number(m[1]) / 1000 : Number(m[1]) * UNITS[m[2]];
  }
  return matched.replace(/\s/g, "") === d.trim().replace(/\s/g, "") && matched ? total : null;
}

export function formatSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return "—";
  const abs = Math.abs(s);
  if (abs < 1) return `${Math.round(s * 1000)} ms`;
  if (abs < 90) return `${Math.round(s)} s`;
  if (abs < 90 * 60) return `${Math.round(s / 60)} min`;
  if (abs < 48 * 3600) return `${(s / 3600).toFixed(abs < 10 * 3600 ? 1 : 0)} h`;
  return `${(s / 86400).toFixed(abs < 10 * 86400 ? 1 : 0)} d`;
}

export function parseTime(t: string | number | null | undefined): Date | null {
  if (t === null || t === undefined || t === "") return null;
  const d = typeof t === "number" ? new Date(t < 1e12 ? t * 1000 : t) : new Date(t);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Orders core's timestamps (RFC 3339, microseconds, e.g. save times); null (none, unknown) first. */
export function timeOrder(a: string | null | undefined, b: string | null | undefined): number {
  const x = a ?? null;
  const y = b ?? null;
  if (x === y) return 0;
  if (x === null) return -1;
  if (y === null) return 1;
  const ms = Date.parse(x) - Date.parse(y);
  if (ms !== 0 && !Number.isNaN(ms)) return Math.sign(ms);
  const frac = (t: string) => (/\.(\d+)/.exec(t)?.[1] ?? "").padEnd(9, "0");
  return frac(x) < frac(y) ? -1 : frac(x) > frac(y) ? 1 : 0;
}

export function formatTime(t: string | number | null | undefined): string {
  const d = parseTime(t);
  if (!d) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelative(t: string | number | null | undefined, now = Date.now()): string {
  const d = parseTime(t);
  if (!d) return "—";
  const diff = (d.getTime() - now) / 1000;
  const abs = Math.abs(diff);
  const text = formatSeconds(abs);
  if (abs < 5) return "just now";
  return diff < 0 ? `${text} ago` : `in ${text}`;
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (Math.abs(v) >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 || v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function formatNumber(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
}

export function formatCompact(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function formatPercent(ratio: number | null | undefined, digits = 1): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) return "—";
  return `${(ratio * 100).toFixed(digits)} %`;
}

/** `snake_case` → "Snake case". */
export function humanize(key: string): string {
  const s = key.replace(/[_-]+/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}
