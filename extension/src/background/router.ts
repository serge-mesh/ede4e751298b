// Messages from the extension's own pages (browser-extension.md §4: the edge is called only from
// the background script). A message from anything but one of this extension's pages, or one
// that isn't a known request, is refused.

import { fail, ok, type AllowEntry, type AllowView, type ApiError, type Result } from '../shared/api';
import { canonicalIp, hostOf } from '../shared/host';
import { DETECTION_PERMISSIONS } from '../shared/permissions';
import {
  parseRequest,
  type AllowList,
  type NewAllow,
  type Request,
  type ResponseOf,
  type State,
  type TabBlock,
} from '../shared/messages';
import { originPattern, parseCoreUrl, parseEdgeUrl, type Settings } from '../shared/settings';
import type { EdgeClient } from './edge-client';

export interface Sender {
  id?: string;
  url?: string;
  tab?: { id?: number };
}

export interface RouterDeps {
  /** This extension's id and the base URL of its pages. */
  extensionId: string;
  extensionBase: string;
  loadSettings(): Promise<Settings>;
  saveSettings(s: Settings): Promise<void>;
  hasPermissions(p: { origins?: string[]; permissions?: string[] }): Promise<boolean>;
  /** Whether detection was granted since the browser started, where it then waits for a restart. */
  detectionAfterRestart(): Promise<boolean>;
  /** The client for an edge origin (kept per origin; its clock skew is kept in `storage.session` too). */
  client(origin: string): EdgeClient;
  tabBlocks(tabId: number): Promise<TabBlock[]>;
  reloadAfterAllow(tabId: number, url: string): Promise<void>;
  /** Called after allows change (forget probe results that may no longer hold). */
  allowsChanged(): void;
}

/** An allow list for a page, with the edge's clock skew learnt from the same reply. */
function listOf(c: EdgeClient, r: Result<AllowView[]>): Result<AllowList> {
  return r.ok ? ok({ allows: r.value, skewMs: c.clock.skewMs }) : r;
}

function entryOf(a: NewAllow, expiresAt: number): AllowEntry {
  if (a.kind === 'ip') {
    return { ip: a.ip, expires_at: expiresAt };
  }
  // `subdomains` is sent only when asked for: left out, a re-timed allow keeps its own.
  return a.subdomains
    ? { block_id: a.blockId, expires_at: expiresAt, subdomains: true }
    : { block_id: a.blockId, expires_at: expiresAt };
}

const nameKey = (n: string): string => n.toLowerCase().replace(/\.$/, '');

/**
 * The allow a reply lists for a requested entry (by kind and target; one the request created or
 * re-timed first), or undefined. The edge names a DNS allow by its blocked name and an IP allow
 * by its canonical text (api.md §6).
 */
export function allowForEntry(allows: readonly AllowView[], e: NewAllow): AllowView | undefined {
  const same =
    e.kind === 'ip'
      ? (a: AllowView) => a.kind === 'ip' && canonicalIp(a.target) === (canonicalIp(e.ip) ?? e.ip)
      : (a: AllowView) => a.kind === 'dns' && nameKey(a.target) === nameKey(e.name);
  return allows.find((a) => same(a) && a.retry_after_s !== undefined) ?? allows.find(same);
}

export class Router {
  constructor(private readonly deps: RouterDeps) {}

  /** True for a message from one of this extension's pages. */
  isOwnPage(sender: Sender): boolean {
    return sender.id === this.deps.extensionId && typeof sender.url === 'string' && sender.url.startsWith(this.deps.extensionBase);
  }

  async handle(message: unknown, sender: Sender): Promise<Result<unknown>> {
    if (!this.isOwnPage(sender)) {
      return fail({ kind: 'request', message: 'refused: not from this extension' });
    }
    const req = parseRequest(message);
    if (req === null) {
      return fail({ kind: 'request', message: 'refused: not a valid request' });
    }
    try {
      return await this.dispatch(req, sender);
    } catch (e) {
      return fail({ kind: 'request', message: e instanceof Error ? e.message : String(e) });
    }
  }

  private async dispatch(req: Request, sender: Sender): Promise<ResponseOf<Request>> {
    switch (req.type) {
      case 'getState':
        return ok(await this.state());
      case 'saveSettings':
        return this.save(req.edgeUrl, req.coreUrl);
      case 'testEdge':
      case 'listAllows': {
        const c = await this.edge();
        return c.ok ? listOf(c.value, await c.value.listAllows()) : c;
      }
      case 'createAllows': {
        const c = await this.edge();
        if (!c.ok) {
          return c;
        }
        // `expires_at` = the edge's now + the duration (§3 step 4): learnt first if not known.
        const now = await c.value.edgeNowS();
        if (!now.ok) {
          return now;
        }
        const until = now.value + req.durationS;
        const r = await c.value.patch(req.entries.map((e) => entryOf(e, until)));
        if (!r.ok) {
          return r;
        }
        this.deps.allowsChanged();
        // A 200 lists the device's active allows; one missing for an entry means nothing was
        // allowed for it (a past `expires_at` only revokes), whatever the status says.
        const found = req.entries.map((e) => allowForEntry(r.value, e));
        const index = found.findIndex((a) => a === undefined);
        const e = req.entries[index];
        if (e !== undefined) {
          const missing = found.filter((a) => a === undefined).length;
          const target = e.kind === 'ip' ? e.ip : e.name;
          const rest =
            req.entries.length === 1 ? '' : missing === 1 ? ' The other entries were allowed.' : ` ${String(missing)} entries weren't allowed.`;
          return fail({ kind: 'not_applied', index, message: `The edge lists no allow for ${target}, so it is still blocked.${rest}` });
        }
        const created = found.filter((a): a is AllowView => a !== undefined);
        return ok({ allows: r.value, created, requestedUntil: until, skewMs: c.value.clock.skewMs });
      }
      case 'endAllow': {
        const c = await this.edge();
        if (!c.ok) {
          return c;
        }
        // A past `expires_at` revokes (api.md §6); 0 is past whatever either clock says.
        const r = await c.value.patch([{ allow_id: req.allowId, expires_at: 0 }]);
        if (r.ok) {
          this.deps.allowsChanged();
        }
        return listOf(c.value, r);
      }
      case 'tabBlocks':
        return ok(await this.deps.tabBlocks(req.tabId));
      case 'reloadAfterAllow': {
        const tabId = sender.tab?.id;
        if (tabId === undefined || hostOf(req.url) === null) {
          return fail({ kind: 'request', message: 'nothing to reload' });
        }
        await this.deps.reloadAfterAllow(tabId, req.url);
        return ok(null);
      }
    }
  }

  private async state(): Promise<State> {
    const s = await this.deps.loadSettings();
    const edgeAccess = s.edgeUrl !== null && (await this.deps.hasPermissions({ origins: [originPattern(s.edgeUrl)] }));
    const detection = await this.deps.hasPermissions(DETECTION_PERMISSIONS);
    const detectionAfterRestart = detection && (await this.deps.detectionAfterRestart());
    return { edgeUrl: s.edgeUrl, coreUrl: s.coreUrl, edgeAccess, detection, detectionAfterRestart };
  }

  private async save(edgeRaw: string, coreRaw: string): Promise<Result<State>> {
    const edge = parseEdgeUrl(edgeRaw);
    if (!edge.ok) {
      return fail({ kind: 'request', message: edge.reason });
    }
    const core = parseCoreUrl(coreRaw);
    if (!core.ok) {
      return fail({ kind: 'request', message: core.reason });
    }
    await this.deps.saveSettings({ edgeUrl: edge.url, coreUrl: core.url });
    return ok(await this.state());
  }

  /** The client for the configured edge, once its host permission is granted. */
  private async edge(): Promise<Result<EdgeClient>> {
    const s = await this.deps.loadSettings();
    if (s.edgeUrl === null) {
      return fail({ kind: 'not_configured', message: 'no edge URL set' } satisfies ApiError);
    }
    if (!(await this.deps.hasPermissions({ origins: [originPattern(s.edgeUrl)] }))) {
      return fail({ kind: 'permission', message: 'no host permission for the edge' });
    }
    return ok(this.deps.client(s.edgeUrl));
  }
}
