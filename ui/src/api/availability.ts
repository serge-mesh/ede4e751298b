// The one place that lists what this core doesn't serve yet. A screen shows "not available yet"
// only for these (core answers `404 no such UI API endpoint`, or `422 unknown series` for a
// chart series); the same answer for any other path or series is an error, so a typo in the UI's
// own paths or series names shows up instead of hiding as "not available". Core's explicit
// `501 not implemented` is always "not available yet".
//
// When core builds one of these, remove it here.

/**
 * Endpoints (paths after /api/ui/v1, `{x}` = one segment), with the spec name where api.md §7 gives
 * one. Core 826b4d6 serves every endpoint the UI's screens use (wave 5 added logs, logs/{id}, top,
 * devices, query-summary, trial-results, alerts/{id}/evidence, lookup-modules and their presets,
 * lookup-providers/{id}/flush|test|status, temp-allows, dnssec/queue|results, extension and
 * config/export), so none is listed.
 */
export const NOT_BUILT_ENDPOINTS: { path: string; spec: string }[] = [];

/**
 * Chart series core.md §10 names that this core doesn't record yet (base names; labels and
 * `.p50`/`.p99` allowed). Core 826b4d6 records every series the UI charts (metrics/mod.rs
 * `CORE_SERIES`), so none is listed.
 */
export const NOT_BUILT_SERIES: string[] = [];

function segments(path: string): string[] {
  return path.split("?")[0].split("/").filter(Boolean);
}

/** True when `path` (after /api/ui/v1, query allowed) is a registered endpoint core hasn't built. */
export function isNotBuiltEndpoint(path: string | undefined): boolean {
  if (!path) return false;
  const got = segments(path);
  return NOT_BUILT_ENDPOINTS.some(({ path: p }) => {
    const want = segments(p);
    return want.length === got.length && want.every((w, i) => (w.startsWith("{") ? got[i].length > 0 : w === got[i]));
  });
}

/** True when a requested series name is one core.md §10 names and this core doesn't record yet. */
export function isNotBuiltSeries(name: string): boolean {
  const base = name.replace(/\.(p50|p99)$/, "");
  return NOT_BUILT_SERIES.some((s) => base === s || base.startsWith(`${s}.`));
}

/** The series a `422 unknown series "x"` names, if the message is that. */
export function unknownSeriesOf(message: string): string | null {
  const m = /^unknown series "(.*)"$/.exec(message);
  if (!m) return null;
  try {
    return JSON.parse(`"${m[1]}"`) as string;
  } catch {
    return m[1];
  }
}
