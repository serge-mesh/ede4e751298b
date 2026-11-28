// The background script (Brave: service worker; Firefox: event page). It alone calls the edge
// (browser-extension.md §4). Listeners are registered synchronously at start, so the browser
// wakes the script for the events it needs. It unloads when idle (~30 s); what a restart would
// lose (the edge's clock skew, pending retries, each tab's blocked hosts, long block page URLs)
// is kept in `storage.session` (README §2 "Restarts"), each only as long as it has a use. Right
// after a restart, events that read or change the pending retries or kept URLs wait for the one
// read of each and are then applied in arrival order (session.ts); each tab's blocked hosts are
// read again by every write (tab-store.ts).
//
// Every change to a tab is made only while the decision behind it still holds (tab-guard.ts):
// `load` checks right before each `tabs.update`.

import browser from 'webextension-polyfill';

import {
  KEPT_KEY,
  MAX_INLINE_URL,
  MAX_KEPT_URLS,
  MAX_URL,
  newRef,
  parseKeptUrls,
  serializeKeptUrls,
  toQuery,
  type BlockInfo,
  type KeptUrl,
} from '../shared/block-info';
import { isBlockCandidate } from '../shared/block-errors';
import { DETECTION_PERMISSIONS, DETECTION_RESTART_KEY } from '../shared/permissions';
import { loadSettings, originPattern, saveSettings } from '../shared/settings';
import { EdgeClient, sessionClockStore } from './edge-client';
import { NavigationFlow, type ErrorDetails, type FrameDetails } from './navigation';
import { probeUrl } from './probe';
import { Router, type Sender } from './router';
import { SessionMap } from './session';
import { SubresourceWatcher, type RequestErrorDetails } from './subresources';
import { TabGuard } from './tab-guard';
import { TabStore } from './tab-store';

/** Firefox can load a URL in place of the tab's current history entry (`tabs.update` `loadReplace`). */
const FIREFOX = browser.runtime.getURL('').startsWith('moz-extension:');

const clients = new Map<string, EdgeClient>();

function clientFor(origin: string): EdgeClient {
  let c = clients.get(origin);
  if (c === undefined) {
    clients.clear();
    c = new EdgeClient({ origin, clockStore: sessionClockStore(browser.storage.session, origin) });
    clients.set(origin, c);
  }
  return c;
}

/** The configured edge's client, once set up and granted; null otherwise. */
async function activeClient(): Promise<EdgeClient | null> {
  const s = await loadSettings();
  if (s.edgeUrl === null) {
    return null;
  }
  const granted = await browser.permissions.contains({ origins: [originPattern(s.edgeUrl)] });
  return granted ? clientFor(s.edgeUrl) : null;
}

async function probe(url: string): Promise<BlockInfo | null> {
  const c = await activeClient();
  return c === null ? null : probeUrl(c, url);
}

/** Each tab's navigation token at its last top-frame commit (see `load`). */
const commits = new Map<number, number>();
/**
 * Firefox: each tab's top-frame document when its navigation failed (`onErrorOccurred`'s
 * `documentId`, read by the browser as it fires the event, before the error page exists). The
 * first per navigation is kept: a process switch can repeat the event, the second time with the
 * error page already current.
 */
const failedFrom = new Map<number, { nav: number; documentId: string | undefined }>();
/** Checks waiting for a tab's next commit or navigation (see `errorPageCommitted`). */
const commitWaiters = new Map<number, Set<() => void>>();
/** Longest wait for a failed load's error page to commit before the block page opens. */
const ERROR_PAGE_WAIT_MS = 2_000;

function wakeCommitWaiters(tabId: number): void {
  for (const check of commitWaiters.get(tabId) ?? []) {
    check();
  }
}

/**
 * Whether the tab's top frame shows the failed load's error page, when its commit event hasn't
 * arrived: a document other than the one the failure left (a back-forward cache restore is one
 * too), showing the failed URL (so is the page before a failed same-URL POST). Without both
 * document IDs (older Firefox) or the frame, false: the plain load that follows never drops a
 * history entry, at worst it leaves the failed one behind *Go back*.
 */
async function errorPageShown(tabId: number, nav: number, failedUrl: string): Promise<boolean> {
  const frame = (await browser.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => null)) as { url?: string; documentId?: string } | null;
  const failure = failedFrom.get(tabId);
  const before = failure?.nav === nav ? failure.documentId : undefined;
  return before !== undefined && frame?.documentId !== undefined && frame.documentId !== before && frame.url === failedUrl;
}

/**
 * Resolves true once the tab's navigation `nav` has committed (Firefox: the failed load's error
 * page), false when the tab moves on or after ERROR_PAGE_WAIT_MS.
 */
function errorPageCommitted(tabId: number, nav: number): Promise<boolean> {
  if (commits.get(tabId) === nav) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    const set = commitWaiters.get(tabId) ?? new Set<() => void>();
    commitWaiters.set(tabId, set);
    const done = (ok: boolean): void => {
      clearTimeout(timer);
      set.delete(check);
      if (set.size === 0) {
        commitWaiters.delete(tabId);
      }
      resolve(ok);
    };
    const check = (): void => {
      if (commits.get(tabId) === nav) {
        done(true);
      } else if (guard.nav(tabId) !== nav) {
        done(false);
      }
    };
    const timer = setTimeout(() => {
      done(false);
    }, ERROR_PAGE_WAIT_MS);
    set.add(check);
  });
}

/**
 * Loads `url` in the tab, if `still()` (checked right before each `tabs.update`). On Firefox it
 * replaces the current history entry (the failed load's error page, or the block page once
 * allowed), so Back never returns to a load that fails again; Chromium has no such option (the
 * block page's "Go back" skips the failed entry instead).
 *
 * `failedUrl` (the block page, after a failed load of that URL): Firefox commits a failed load's
 * error page only after onErrorOccurred, and a probe can answer first (the edge is a LAN hop
 * away). Replacing before that commit replaces the page before the failed load, losing it from
 * history; pushing after it leaves the failed load's entry behind *Go back* (both seen in the
 * browser tests under load, where this script also learns of the commit after the browser made
 * it). So the block page waits for this script's own commit event, at most ERROR_PAGE_WAIT_MS,
 * and replaces the error page. Without that event, the tab's top frame says which case holds
 * (`errorPageShown`, `webNavigation.getFrame`, no extra permission): showing the error page, it
 * is replaced; otherwise a plain load ends the still-pending error page, so the failed load
 * leaves no entry either. Either way `replaced` holds.
 */
async function load(tabId: number, url: (replaced: boolean) => string, still: () => boolean, failedUrl: string | null = null): Promise<void> {
  if (!still()) {
    return;
  }
  if (FIREFOX) {
    const navToken = guard.nav(tabId);
    if (failedUrl !== null && !(await errorPageCommitted(tabId, navToken))) {
      if (!still()) {
        return;
      }
      const shown = await errorPageShown(tabId, navToken, failedUrl);
      if (!still()) {
        return;
      }
      if (!shown) {
        await browser.tabs.update(tabId, { url: url(true) });
        return;
      }
    }
    if (!still()) {
      return;
    }
    try {
      await browser.tabs.update(tabId, { url: url(true), loadReplace: true });
      return;
    } catch {
      // Not supported after all: a plain load below, if the tab hasn't moved on meanwhile.
      if (!still()) {
        return;
      }
    }
  }
  await browser.tabs.update(tabId, { url: url(false) });
}

function setBadge(tabId: number, count: number): void {
  void browser.action
    .setBadgeText({ tabId, text: count > 0 ? String(Math.min(count, 99)) : '' })
    .catch(() => undefined);
}

const BLOCK_PAGE = browser.runtime.getURL('block.html');
const guard = new TabGuard();
const tabs = new TabStore(browser.storage.session, guard, setBadge);
/** Long page URLs kept for block pages (block-info.ts), one per tab. */
const keptUrls = new SessionMap<KeptUrl>(browser.storage.session, KEPT_KEY, { parse: parseKeptUrls, serialize: serializeKeptUrls }, MAX_KEPT_URLS);

/**
 * Drops the tab's kept URL `id` (or any), which no block page needs any more. A drop of `id`
 * follows that URL's own write, so the kept URLs have been read by then.
 */
function dropKeptUrl(tabId: number, id?: string): void {
  if (id === undefined || keptUrls.get(tabId)?.id === id) {
    void keptUrls.delete(tabId).catch(() => undefined);
  }
}

const nav = new NavigationFlow({
  guard,
  probe,
  openBlockPage: async (tabId, info, still) => {
    // A URL too long for the block page's query is kept in storage.session (block-info.ts).
    let ref: string | null = null;
    if (info.url.length > MAX_INLINE_URL && info.url.length <= MAX_URL) {
      const id = newRef();
      ref = await keptUrls.set(tabId, { id, url: info.url }).then(
        () => id,
        () => {
          // Not stored: the block page couldn't read it.
          dropKeptUrl(tabId, id);
          return null;
        },
      );
    }
    if (!still()) {
      // The tab moved on while the URL was kept: no block page will read it.
      if (ref !== null) {
        dropKeptUrl(tabId, ref);
      }
      return;
    }
    await load(tabId, (replaced) => `${BLOCK_PAGE}?${toQuery(info, { ref, replaced })}`, still, info.url);
  },
  navigate: (tabId, url, still) => load(tabId, () => url, still),
  isCandidate: isBlockCandidate,
  setTimer: (fn, ms) => {
    setTimeout(fn, ms);
  },
  now: Date.now,
  session: browser.storage.session,
  log: (error, outcome) => {
    console.debug(`picket: page load failed with ${error}: ${outcome}`);
  },
});

const subresources = new SubresourceWatcher({
  probe,
  guard,
  record: (tabId, block, ticket) => tabs.record(tabId, block, ticket),
  isCandidate: isBlockCandidate,
  now: Date.now,
});

const router = new Router({
  extensionId: browser.runtime.id,
  extensionBase: browser.runtime.getURL(''),
  loadSettings,
  saveSettings,
  hasPermissions: (p) => browser.permissions.contains(p),
  detectionAfterRestart: async () => (await browser.storage.session.get(DETECTION_RESTART_KEY))[DETECTION_RESTART_KEY] === true,
  client: clientFor,
  tabBlocks: (tabId) => tabs.list(tabId),
  reloadAfterAllow: (tabId, url) => nav.reloadAfterAllow(tabId, url),
  allowsChanged: () => {
    guard.allowsChanged();
  },
});

browser.webNavigation.onBeforeNavigate.addListener((d: FrameDetails) => {
  // First: the tab's new navigation token (NavigationFlow), which every other check reads.
  void nav.onBeforeNavigate(d);
  if (d.frameId === 0) {
    wakeCommitWaiters(d.tabId);
  }
  if (d.frameId === 0 && d.tabId >= 0) {
    void tabs.clear(d.tabId).catch(() => undefined);
    // The tab leaves its block page: the URL kept for it has no further use.
    if (!d.url.startsWith(BLOCK_PAGE)) {
      dropKeptUrl(d.tabId);
    }
  }
});
browser.webNavigation.onErrorOccurred.addListener((d) => {
  if (FIREFOX && d.frameId === 0 && d.tabId >= 0) {
    const navToken = guard.nav(d.tabId);
    if (failedFrom.get(d.tabId)?.nav !== navToken) {
      failedFrom.set(d.tabId, { nav: navToken, documentId: (d as { documentId?: string }).documentId });
    }
  }
  void nav.onErrorOccurred(d as ErrorDetails).catch(() => undefined);
});
if (FIREFOX) {
  // Only `load` on Firefox reads the commits.
  browser.webNavigation.onCommitted.addListener((d: FrameDetails) => {
    // The commit belongs to the tab's current navigation (an error page has no onBeforeNavigate of its own).
    if (d.frameId === 0 && d.tabId >= 0) {
      commits.set(d.tabId, guard.nav(d.tabId));
      wakeCommitWaiters(d.tabId);
    }
  });
}
browser.webNavigation.onCompleted.addListener((d: FrameDetails) => {
  void nav.onCompleted(d);
});
browser.tabs.onRemoved.addListener((tabId) => {
  commits.delete(tabId);
  failedFrom.delete(tabId);
  void nav.onTabRemoved(tabId);
  void tabs.remove(tabId).catch(() => undefined);
  dropKeptUrl(tabId);
});
browser.runtime.onMessage.addListener((message: unknown, sender: Sender) => router.handle(message, sender));
browser.runtime.onInstalled.addListener((d) => {
  if (d.reason === 'install') {
    void browser.runtime.openOptionsPage();
  }
});

// Blocked sub-resource detection follows its optional permissions, as `permissions.contains`
// reports them: `browser.webRequest` can't tell, since webextension-polyfill keeps the
// namespace it first read after the permission is removed. The listener goes on the live
// namespace (`chrome.webRequest` where it exists) and is added synchronously at start when the
// API is there, so the browser wakes the script for its events; the check then confirms it.
type RequestEvent = typeof browser.webRequest.onErrorOccurred;
let detecting: RequestEvent | null = null;
/** Whether a webRequest event arrived since the last grant: the restart note is then moot. */
let requestSeen = false;
function onRequestError(d: RequestErrorDetails): void {
  if (!requestSeen) {
    requestSeen = true;
    void browser.storage.session.remove(DETECTION_RESTART_KEY).catch(() => undefined);
  }
  subresources.onErrorOccurred(d);
}
function liveWebRequest(): typeof browser.webRequest | undefined {
  const chromeNs = (globalThis as { chrome?: { webRequest?: typeof browser.webRequest } }).chrome;
  return chromeNs?.webRequest ?? (browser as { webRequest?: typeof browser.webRequest }).webRequest;
}
function startDetection(): void {
  const webRequest = liveWebRequest();
  if (detecting === null && webRequest !== undefined) {
    webRequest.onErrorOccurred.addListener(onRequestError, { urls: ['<all_urls>'] });
    detecting = webRequest.onErrorOccurred;
  }
}
function stopDetection(): void {
  if (detecting !== null) {
    try {
      detecting.removeListener(onRequestError);
    } catch {
      // The API is already gone with its permission.
    }
    detecting = null;
  }
}
let detectionSync: Promise<void> = Promise.resolve();
function syncDetection(): void {
  detectionSync = detectionSync.then(async () => {
    if (await browser.permissions.contains(DETECTION_PERMISSIONS).catch(() => false)) {
      startDetection();
    } else {
      stopDetection();
    }
  });
}
/**
 * Some Chromium builds pass webRequest events for access granted at run time only from the
 * browser's next start (Chrome for Testing in the browser tests; an extension reload doesn't help),
 * others at once (Brave 1.100 installed with Load unpacked, issue #61). A grant is noted in
 * `storage.session`, which that start clears, and so does the first event: until either, the
 * popup can say why it may list nothing yet. An extension reload or update clears it too; the
 * options page said so at the grant.
 */
function noteDetectionGrant(p: { permissions?: string[] } | undefined): void {
  if (!FIREFOX && (p?.permissions ?? []).includes('webRequest')) {
    requestSeen = false;
    void browser.storage.session.set({ [DETECTION_RESTART_KEY]: true }).catch(() => undefined);
  }
}
function noteDetectionRemoval(p: { permissions?: string[] } | undefined): void {
  if ((p?.permissions ?? []).includes('webRequest')) {
    void browser.storage.session.remove(DETECTION_RESTART_KEY).catch(() => undefined);
  }
}
startDetection();
syncDetection();
browser.permissions.onAdded.addListener((p?: { permissions?: string[] }) => {
  noteDetectionGrant(p);
  syncDetection();
});
browser.permissions.onRemoved.addListener((p?: { permissions?: string[] }) => {
  noteDetectionRemoval(p);
  syncDetection();
});
void browser.action.setBadgeBackgroundColor({ color: '#b42318' }).catch(() => undefined);
