// The bypass API's wire types (api.md §6) and the errors the extension shows.

/** Path of the bypass API on the edge's API listener. */
export const ALLOWS_PATH = '/v1/temporary-allows';
/** Path of DoH on the same origin (edge.md §5). */
export const DOH_PATH = '/dns-query';
/** Header every bypass request and every probe carries (api.md §6). */
export const CLIENT_HEADER = 'X-Picket-Client';
export const CLIENT_HEADER_VALUE = 'extension';

/** The edge's limits on a request (apps/picket-edge bypass: MAX_ENTRIES, MAX_BODY, id length). */
export const MAX_ENTRIES = 256;
export const MAX_BODY = 64 * 1024;
export const MAX_ID_LENGTH = 64;
/** The longest allow a firewall entry can hold (~24.8 days); the edge clamps to it too. */
export const MAX_DURATION_S = 2_147_483;

/** The block page's choices (browser-extension.md §3 step 3). */
export const DURATIONS: readonly { label: string; seconds: number }[] = [
  { label: '15 min', seconds: 15 * 60 },
  { label: '1 hour', seconds: 60 * 60 },
  { label: '8 hours', seconds: 8 * 60 * 60 },
  { label: '24 hours', seconds: 24 * 60 * 60 },
];

/** One `PATCH`/`PUT` entry: `{block_id, expires_at, subdomains?}`, `{ip, expires_at}` or `{allow_id, expires_at}`. */
export type AllowEntry =
  | { block_id: string; expires_at: number; subdomains?: boolean }
  | { ip: string; expires_at: number }
  | { allow_id: string; expires_at: number };

/** One active allow in a response: `{allow_id, kind, target, subdomains?, expires_at, retry_after_s?}`. */
export interface AllowView {
  allow_id: string;
  /** `dns` or `ip`; other values are shown as they are (newer edges may add kinds). */
  kind: string;
  /** The name (DNS) or IP. */
  target: string;
  subdomains?: boolean;
  /** Unix seconds. */
  expires_at: number;
  /** Only on allows the request created or re-timed. */
  retry_after_s?: number;
}

export type ErrorKind =
  /** No edge URL is set. */
  | 'not_configured'
  /** The edge origin's host permission isn't granted. */
  | 'permission'
  /** The request didn't reach the edge (offline, DNS, TLS: the LAN CA isn't trusted). */
  | 'network'
  | 'timeout'
  /** 403: bypass off in a governing profile, a limit hit, or the request refused. */
  | 'forbidden'
  /** 409: nothing to lift. */
  | 'conflict'
  /** 503: the firewall didn't take an IP allow, the edge's clock isn't synchronised, no config. */
  | 'unavailable'
  /** 429: over this device's request limits. */
  | 'busy'
  /** 400, 413: the edge refused the request as malformed. */
  | 'invalid'
  /** 404: no bypass API on this listener (`"api": true` not set). */
  | 'not_found'
  /** Any other HTTP status. */
  | 'http'
  /** The edge's reply wasn't what the API promises. */
  | 'bad_response'
  /**
   * A 200 whose allow list lacks an allow the request asked for: nothing was allowed for that
   * entry (an `expires_at` already past on the edge only revokes, api.md §6).
   */
  | 'not_applied'
  /** The edge's time couldn't be learned (no usable `Date`), so no `expires_at` could be set. */
  | 'no_edge_time'
  /** A request the extension refused to send (over a limit, bad input). */
  | 'request';

export interface ApiError {
  kind: ErrorKind;
  message: string;
  status?: number;
  /** The edge's error code (`forbidden`, `rate_limited`, `max_active`, `no_block`, …). */
  code?: string;
  /** The entry the error names (all or nothing: nothing was changed). */
  index?: number;
  retryAfterS?: number;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: ApiError };

export const ok = <T>(value: T): Result<T> => ({ ok: true, value });
export const fail = <T = never>(error: ApiError): Result<T> => ({ ok: false, error });

/** A one-line explanation of an error for the block page and popup. */
export function describeError(e: ApiError): string {
  switch (e.kind) {
    case 'not_configured':
      return 'Picket is not set up yet: enter the edge API URL in the options.';
    case 'permission':
      return 'The extension has no access to the edge: open the options and save the edge URL again.';
    case 'network':
      return "Couldn't reach the edge. Check the edge URL, and that this browser trusts the LAN CA root (download it from core's UI).";
    case 'timeout':
      return "The edge didn't answer in time.";
    case 'forbidden':
      switch (e.code) {
        case 'rate_limited':
          return 'This device has made too many temporary allows in the last hour.';
        case 'max_active':
          return 'This device already has as many temporary allows as its profile permits.';
        default:
          // Bypass off in a governing profile, no profile admitting the device, or a refused request.
          return `The edge refused: ${e.message}.`;
      }
    case 'conflict':
      switch (e.code) {
        case 'no_block':
          return 'The edge no longer remembers this block (it may have been too long ago). Reload the page to see whether it is still blocked.';
        case 'not_blocked':
          return 'Picket does not block this address for this device, so there is nothing to lift.';
        case 'not_found':
          return 'That allow has already ended.';
        default:
          return `Nothing to lift: ${e.message}`;
      }
    case 'unavailable':
      switch (e.code) {
        case 'firewall':
          return "The edge's firewall didn't take the allow; nothing was changed.";
        case 'clock':
          return "The edge's clock isn't synchronised yet; try again shortly.";
        default:
          return `The edge can't do this right now: ${e.message}`;
      }
    case 'busy':
      return 'The edge is busy with this device’s requests; try again in a moment.';
    case 'invalid':
      return `The edge refused the request: ${e.message}`;
    case 'not_found':
      return 'This edge URL has no bypass API: use a listener with "api": true.';
    case 'http':
      return `The edge answered HTTP ${String(e.status ?? '?')}: ${e.message}`;
    case 'bad_response':
      return `The edge sent an unexpected reply: ${e.message}`;
    case 'not_applied':
      return `${e.message} Try again; if this keeps happening, check this device's clock.`;
    case 'no_edge_time':
      return "The edge didn't say what time it is (no Date header), so the allow's end couldn't be set by its clock. Nothing was changed.";
    case 'request':
      return e.message;
  }
}
