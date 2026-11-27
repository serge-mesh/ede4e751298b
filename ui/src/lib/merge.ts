// Edit forms against live data. Entities and settings have no server-side version check
// (api.md §7), so a form keeps the value it was edited from (its base) and compares new data
// with it: a clean form follows the new data, a dirty one keeps its draft and offers to reload
// or to keep its changes on top of the new data.

/** Structural equality of JSON values (object key order ignored). */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") {
    // A missing key, undefined and null all mean "not set" to core.
    return (a ?? null) === (b ?? null);
  }
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    const bb = b as unknown[];
    return a.length === bb.length && a.every((x, i) => deepEqual(x, bb[i]));
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const keys = new Set([...Object.keys(ao), ...Object.keys(bo)]);
  for (const k of keys) {
    if (!deepEqual(ao[k], bo[k])) return false;
  }
  return true;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * A three-way merge: the changes from `base` to `mine`, applied to `theirs`. Objects merge
 * key by key; anything else (arrays included, so an ordered list stays one choice) is a leaf.
 * Where both sides changed the same leaf, `mine` wins.
 */
export function merge3<T>(base: T, mine: T, theirs: T): T {
  if (deepEqual(mine, base)) return theirs;
  if (deepEqual(theirs, base)) return mine;
  if (isPlainObject(base) && isPlainObject(mine) && isPlainObject(theirs)) {
    const out: Record<string, unknown> = {};
    const keys = new Set([...Object.keys(base), ...Object.keys(mine), ...Object.keys(theirs)]);
    for (const k of keys) {
      const v = merge3(base[k], mine[k], theirs[k]);
      if (v !== undefined) out[k] = v;
    }
    return out as T;
  }
  return mine;
}

/**
 * Fields of one form that core checks together (core.md §2), so "Keep my changes" merges each
 * group as one value: a field-by-field merge could keep half of a change made elsewhere, e.g.
 * Enforce moving a bundle from `trial_bundles` to `block` while the draft edited `block` would
 * leave that bundle in neither list. Paths are dot-separated.
 * - profiles: a trial bundle may be neither in `block` nor in the scope of one of the profile's
 *   `sync` attachments (`lookups`);
 * - settings: none. `web.names` must be under `lanca.zones`, but no settings form edits or sends
 *   the zones: a zones change is a LAN CA rotation, made under Settings → LAN CA with the root it
 *   replaces (`lanca.rotate_from`, core.md §11), so a merged form never carries a stale value of
 *   them (core c58ba80 checks a form's `web.names` against the zones it has).
 */
export const COUPLED_FIELDS: Record<string, string[][]> = {
  profiles: [["block", "trial_bundles", "lookups"]],
  settings: [],
};

/** A deep copy of a JSON value (merge3 returns parts of its inputs as they are). */
function copy<T>(v: T): T {
  return v === undefined ? v : (JSON.parse(JSON.stringify(v)) as T);
}

function at(v: unknown, path: string[]): unknown {
  let cur = v;
  for (const k of path) cur = isPlainObject(cur) ? cur[k] : undefined;
  return cur;
}

function setAt(v: Record<string, unknown>, path: string[], x: unknown): void {
  let cur = v;
  for (const k of path.slice(0, -1)) {
    if (!isPlainObject(cur[k])) cur[k] = {};
    cur = cur[k] as Record<string, unknown>;
  }
  const last = path[path.length - 1];
  if (x === undefined) delete cur[last];
  else cur[last] = x;
}

/**
 * `merge3` with coupled field groups merged as one value each: where both sides changed some
 * field of a group, the whole group comes from `mine` (mine wins, as on one field). Returns the
 * merged value and the groups where `mine` replaced a change made elsewhere.
 */
export function mergeKeepingMine<T>(base: T, mine: T, theirs: T, groups: string[][] = []): { value: T; replaced: string[][] } {
  const value = copy(merge3(base, mine, theirs));
  const replaced: string[][] = [];
  if (!isPlainObject(value)) return { value, replaced };
  for (const group of groups) {
    const paths = group.map((p) => p.split("."));
    const changed = (side: T) => paths.some((p) => !deepEqual(at(side, p), at(base, p)));
    if (changed(mine) && changed(theirs)) {
      for (const p of paths) setAt(value, p, copy(at(mine, p)));
      if (paths.some((p) => !deepEqual(at(mine, p), at(theirs, p)))) replaced.push(group);
    }
  }
  return { value, replaced };
}
