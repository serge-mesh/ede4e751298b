import { WINDOWS, type Window } from "@/api/types";

export interface WindowSearch {
  window?: Window;
  edge?: string;
}

function str(v: unknown, max = 512): string | undefined {
  return typeof v === "string" && v.length > 0 && v.length <= max ? v : undefined;
}

/** The dashboard's window and edge, kept in the URL so links can keep them (core.md §12). */
export function parseWindowSearch(s: Record<string, unknown>): WindowSearch {
  const w = str(s.window);
  return {
    window: w && (WINDOWS as string[]).includes(w) ? (w as Window) : undefined,
    edge: str(s.edge, 128),
  };
}

export interface QueryLogSearch extends WindowSearch {
  from?: string;
  to?: string;
  client?: string;
  device?: string;
  qname?: string;
  match?: "exact" | "suffix" | "substring";
  decision?: string;
  profile?: string;
  bundle?: string;
}

export function parseQueryLogSearch(s: Record<string, unknown>): QueryLogSearch {
  const m = str(s.match);
  return {
    ...parseWindowSearch(s),
    from: str(s.from, 64),
    to: str(s.to, 64),
    client: str(s.client, 256),
    device: str(s.device, 256),
    qname: str(s.qname, 1024),
    match: m === "exact" || m === "suffix" || m === "substring" ? m : undefined,
    decision: str(s.decision, 32),
    profile: str(s.profile, 128),
    bundle: str(s.bundle, 128),
  };
}

export function parseTabSearch(s: Record<string, unknown>): { tab?: string } {
  return { tab: str(s.tab, 64) };
}

/**
 * A feed provider's page: its tab, and the Files tab's folder (`prefix`) and search (`q`), so Back
 * walks up a folder or out of a search, and either can be linked.
 */
export interface ProviderSearch {
  tab?: string;
  prefix?: string;
  q?: string;
}

/**
 * A search parameter read as text: the router's default parsing reads a hand-typed `?q=123` as
 * the number 123 (and `true` as a boolean); both are text here. (A link the UI makes quotes such
 * values, so they come back as typed.)
 */
function text(v: unknown): unknown {
  return typeof v === "number" || typeof v === "boolean" ? String(v) : v;
}

/**
 * core's bounds (feeds/api.rs `MAX_LISTING_PREFIX`, `MAX_LISTING_Q`): `prefix` at most 4,096 bytes
 * and `q` 256 characters; past them, dropped. A prefix is a folder: one typed without its last
 * `/` gets it, so names are never cut mid-segment.
 */
export function parseProviderSearch(s: Record<string, unknown>): ProviderSearch {
  const raw = str(text(s.prefix), 4096);
  const prefix = raw && !raw.endsWith("/") ? `${raw}/` : raw;
  const q = str(text(s.q), 1024);
  return {
    ...parseTabSearch(s),
    prefix: prefix && new TextEncoder().encode(prefix).length <= 4096 ? prefix : undefined,
    q: q && [...q].length <= 256 ? q : undefined,
  };
}

export interface DeviceSearch extends WindowSearch {
  key?: string;
}

/**
 * A device view's device (a MAC or an address) as the `key` parameter. The UI's links use it, and
 * the route stays for the bookmarks made with it; it is no longer required: core now serves the UI
 * document for any GET path outside `assets/` that isn't a top-level file name, so a reload of
 * `/clients/device/192.168.1.20` works too.
 */
export function parseDeviceSearch(s: Record<string, unknown>): DeviceSearch {
  return { ...parseWindowSearch(s), key: str(s.key, 256) };
}
