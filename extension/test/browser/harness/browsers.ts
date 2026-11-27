// Launches a real browser with the built extension and gives the tests one way to drive both:
//
// - **Chromium** (Playwright's Chrome for Testing): a persistent profile with Developer mode on
//   and the unpacked extension (`--load-extension`, which installs it as Load unpacked does, and
//   again at each start); its pages are Playwright pages. Secure DNS (a custom DoH provider: the
//   fake edge) is set in the profile's `Local State`, and the test CA is trusted by its key
//   (`--ignore-certificate-errors-spki-list`). Permission prompts can't be answered in a headless
//   browser, so the tests first add the host to the extension's site access in chrome://extensions
//   (`preGrant`), as a user can; `permissions.request` then grants it at once.
// - **Firefox** (Playwright's Firefox): installed as a temporary add-on through WebDriver BiDi
//   (`webExtension.install`, what about:debugging's "Load Temporary Add-on" does). Juggler skips
//   `moz-extension:` documents, so extension pages are driven through BiDi (trusted input, so
//   `permissions.request` sees a user action; `extensions.webextOptionalPermissionPrompts` off
//   grants it without the doorhanger). The test CA is imported into Firefox's certificate store
//   and DNS goes over TRR (mode 3) to the fake edge.
//
// Web pages load in tabs as a user's would (Playwright's `goto`, BiDi `browsingContext.navigate`).
// An "observer" extension page (the block page without a query, which does nothing) records the
// webNavigation events the browser reports and runs extension API calls for the tests.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { chromium, firefox, type BrowserContext, type Page } from '@playwright/test';

import { GECKO_ID } from '../../../scripts/manifest.mjs';
import { Bidi } from './bidi';
import type { TestCerts } from './certs';
import { WAIT_MS } from './time';

export type BrowserKind = 'chromium' | 'firefox';

/** The Firefox add-on's internal UUID, fixed (`extensions.webextensions.uuids`) so its pages have known URLs. */
const FIREFOX_UUID = '5f0c6a3e-1d2b-4c8e-9a7f-0123456789ab';

/** The extension APIs the tests call inside extension pages (`chrome.*`, promise-based in MV3). */
export interface ExtApi {
  runtime: { getManifest(): { version: string }; id: string; getContexts(f: { contextTypes: string[] }): Promise<unknown[]> };
  tabs: {
    get(id: number): Promise<{ id?: number; windowId: number; index: number; url?: string; active: boolean }>;
    create(p: { url: string; active?: boolean; windowId?: number; index?: number }): Promise<{ id?: number }>;
    update(id: number, p: { active?: boolean; url?: string }): Promise<unknown>;
    remove(id: number): Promise<void>;
  };
  action: { getBadgeText(d: { tabId: number }): Promise<string> };
  permissions: {
    getAll(): Promise<{ origins?: string[]; permissions?: string[] }>;
    contains(p: { origins?: string[]; permissions?: string[] }): Promise<boolean>;
  };
  storage: { local: { get(k: null): Promise<Record<string, unknown>> } };
  webNavigation: Record<string, { addListener(fn: (d: NavEvent) => void): void }>;
  webRequest?: { onErrorOccurred: { addListener(fn: (d: RequestError) => void, filter: { urls: string[] }): void } };
}

export interface NavEvent {
  event: string;
  tabId: number;
  frameId: number;
  url: string;
  error?: string;
  at: number;
}

export interface RequestError {
  tabId: number;
  url: string;
  error: string;
  type?: string;
}

/** `globalThis` inside an extension page. */
export interface ExtGlobal {
  chrome: ExtApi;
  picketNav?: NavEvent[];
  picketRequestErrors?: RequestError[];
}

/** An extension page or web page shown in a tab, driven by the browser's own input. */
export interface Surface {
  /** Runs `fn(arg)` in the page; arguments and results go through JSON. */
  run<A, R>(fn: (arg: A) => R | Promise<R>, arg: A): Promise<R>;
  click(selector: string): Promise<void>;
  /** Sets an input's value and fires `input` and `change`. */
  fill(selector: string, value: string): Promise<void>;
  select(selector: string, value: string): Promise<void>;
  text(selector: string): Promise<string>;
  visible(selector: string): Promise<boolean>;
  /** Waits until `fn(arg)` returns a truthy value, and returns it. */
  waitFor<A, R>(fn: (arg: A) => R | Promise<R>, arg: A, timeoutMs?: number): Promise<R>;
}

export interface Tab {
  /** The extension API's tab id. */
  readonly id: number;
  /** Loads `url` as a typed URL; resolves once the load started (it may fail). */
  goto(url: string): Promise<void>;
  /** The URL the tab shows. */
  url(): Promise<string>;
  waitForUrl(match: (url: string) => boolean, timeoutMs?: number): Promise<string>;
  /** The page shown in the tab (extension or web). */
  surface(): Surface;
}

export interface Session {
  readonly kind: BrowserKind;
  readonly version: string;
  /** `chrome-extension://<id>/` or `moz-extension://<uuid>/`. */
  readonly base: string;
  /** An extension page recording webNavigation events, for API calls. */
  readonly observer: Surface;
  /** The options page the extension opened on install, as a tab. */
  installTab(): Promise<Tab>;
  /** A new tab (its own window on Firefox), loaded with a marker page so its id is known. */
  newTab(): Promise<Tab>;
  /** Opens an extension page in a new tab. */
  openExtensionTab(page: string): Promise<Tab>;
  /** Opens the popup page in a background tab next to `tab`, so it reads `tab` as the active one. */
  openPopup(tab: Tab): Promise<Surface>;
  /** Grants what a user grants ahead of a permission prompt (Chromium; Firefox grants without one). */
  preGrant(pattern: string): Promise<void>;
  /** Re-opens the observer (e.g. after a permission adds an API namespace). */
  reopenObserver(): Promise<void>;
  /** The webNavigation events the observer saw. */
  navEvents(): Promise<NavEvent[]>;
  /**
   * Updates the extension as its install steps say: Chromium presses Reload for the unpacked
   * folder (whose contents the caller replaced); Firefox installs `dir` over it.
   */
  update(dir: string): Promise<void>;
  /** Quits and starts the browser again on the same profile (Chromium; Firefox drops temporary add-ons). */
  restart(): Promise<void>;
  /**
   * Lets the background script go idle for `idleMs` (MV3 unloads it after ~30 s idle) and
   * returns once it isn't running. Firefox unloads its event page by itself. Chromium keeps the
   * worker while Playwright is attached to it, so after the idle time it is stopped as its idle
   * timeout would (CDP `ServiceWorker.stopAllWorkers`); the next event starts it again.
   */
  idleBackground(idleMs: number): Promise<void>;
  close(): Promise<void>;
}

export interface LaunchOptions {
  kind: BrowserKind;
  /** The unpacked build (dist/brave or dist/firefox). */
  extensionDir: string;
  certs: TestCerts;
  /** The fake edge's DoH URL: the browser's resolver. */
  dohUrl: string;
  /** A URL served by the web target, used to find a new tab's id (`<url>?tab=<n>`). */
  markerUrl: string;
  /** Extra Firefox prefs (set before any page loads). */
  firefoxPrefs?: Record<string, string | number | boolean>;
}

const HEADLESS = process.env.PICKET_HEADED !== '1';

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((resolve) => s.close(() => { resolve(); }));
  return port;
}

/** Polls `fn` until it returns something other than null, undefined, false or ''. */
async function poll<R>(what: string, fn: () => Promise<R>, timeoutMs: number): Promise<Exclude<R, null | undefined | false | ''>> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v !== null && v !== undefined && v !== false && v !== '') {
        return v as Exclude<R, null | undefined | false | ''>;
      }
      last = v;
    } catch (e) {
      last = e;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what} (last: ${last instanceof Error ? last.message : JSON.stringify(last)})`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

/** Installs the observer's listeners (runs in the observer page). */
function observe(): boolean {
  const g = globalThis as unknown as ExtGlobal;
  if (g.picketNav !== undefined) {
    return true;
  }
  const nav: NavEvent[] = [];
  g.picketNav = nav;
  for (const event of ['onBeforeNavigate', 'onCommitted', 'onCompleted', 'onErrorOccurred']) {
    g.chrome.webNavigation[event]?.addListener((d) => {
      nav.push({ event, tabId: d.tabId, frameId: d.frameId, url: d.url, at: Date.now(), ...(d.error === undefined ? {} : { error: d.error }) });
    });
  }
  const errors: RequestError[] = [];
  g.picketRequestErrors = errors;
  g.chrome.webRequest?.onErrorOccurred.addListener(
    (d) => {
      errors.push({ tabId: d.tabId, url: d.url, error: d.error, ...(d.type === undefined ? {} : { type: d.type }) });
    },
    { urls: ['<all_urls>'] },
  );
  return true;
}

function navLog(): NavEvent[] {
  return (globalThis as unknown as ExtGlobal).picketNav ?? [];
}

/** The tab that committed or failed `url`, from the observer's log (runs in the observer page). */
function tabWithUrl(url: string): number | null {
  const e = ((globalThis as unknown as ExtGlobal).picketNav ?? []).find((n) => n.frameId === 0 && n.url === url && n.event !== 'onBeforeNavigate');
  return e?.tabId ?? null;
}

let markerCounter = 0;

/** Whether the extension's background script runs (in the observer page). */
function backgroundRunning(): Promise<boolean> {
  return (globalThis as unknown as ExtGlobal).chrome.runtime.getContexts({ contextTypes: ['BACKGROUND'] }).then((l) => l.length > 0);
}

/** Waits `idleMs`, then until the background has stopped (after `stop`, if it's still up then). */
async function idle(observer: Surface, idleMs: number, stop: (() => Promise<void>) | null): Promise<void> {
  await new Promise((r) => setTimeout(r, idleMs));
  if (stop !== null && (await observer.run(backgroundRunning, null))) {
    await stop();
  }
  await poll('the background script to stop', async () => !(await observer.run(backgroundRunning, null)), 45_000);
}

/**
 * Removes a browser profile once the browser is gone. `closing` is its close; if that takes
 * longer than `waitMs` the removal is retried while the browser may still be writing, and a
 * profile that can't go is left with a warning rather than failing a test that passed.
 */
async function removeProfile(profile: string, closing: Promise<unknown>, waitMs = 30_000): Promise<void> {
  const closed = await Promise.race([closing.then(() => true, () => true), new Promise<boolean>((r) => setTimeout(() => { r(false); }, waitMs))]);
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: closed ? 3 : 20, retryDelay: 250 });
  } catch (e) {
    console.warn(`left browser profile ${profile}: ${String(e)}`);
  }
}

/** True once the popup has shown its setup prompt, or both lists (it has read the active tab by then). */
function popupReady(): boolean {
  const shown = (sel: string): boolean => document.querySelector<HTMLElement>(sel)?.hidden === false;
  if (shown('#setup')) {
    return true;
  }
  const blocks = document.querySelector('#blocks li') !== null || shown('#blocks-hint') || shown('#blocks-status');
  const allows = document.querySelector('#allows li') !== null || shown('#allows-status');
  return shown('#main') && blocks && allows;
}

// ---------------------------------------------------------------------------------------------
// Chromium

class PlaywrightSurface implements Surface {
  constructor(readonly page: Page) {}
  run<A, R>(fn: (arg: A) => R | Promise<R>, arg: A): Promise<R> {
    return this.page.evaluate<R, A>(fn as never, arg);
  }
  // The first match, as `querySelector` (the Firefox side) takes it.
  async click(selector: string): Promise<void> {
    await this.page.locator(selector).first().click();
  }
  async fill(selector: string, value: string): Promise<void> {
    await this.page.locator(selector).first().fill(value);
  }
  async select(selector: string, value: string): Promise<void> {
    await this.page.locator(selector).first().selectOption(value);
  }
  async text(selector: string): Promise<string> {
    return (await this.page.locator(selector).first().textContent()) ?? '';
  }
  visible(selector: string): Promise<boolean> {
    return this.page.locator(selector).first().isVisible();
  }
  async waitFor<A, R>(fn: (arg: A) => R | Promise<R>, arg: A, timeoutMs = WAIT_MS): Promise<R> {
    const h = await this.page.waitForFunction<R, A>(fn as never, arg, { timeout: timeoutMs, polling: 100 });
    return (await h.jsonValue());
  }
}

class ChromiumTab implements Tab {
  constructor(
    readonly id: number,
    readonly page: Page,
  ) {}
  async goto(url: string): Promise<void> {
    // A blocked load fails (and the extension may replace it): only its start matters here.
    await this.page.goto(url, { waitUntil: 'commit', timeout: WAIT_MS }).catch(() => undefined);
  }
  url(): Promise<string> {
    return Promise.resolve(this.page.url());
  }
  waitForUrl(match: (url: string) => boolean, timeoutMs = WAIT_MS): Promise<string> {
    return poll('the tab URL', () => Promise.resolve(match(this.page.url()) ? this.page.url() : ''), timeoutMs);
  }
  surface(): Surface {
    return new PlaywrightSurface(this.page);
  }
}

class ChromiumSession implements Session {
  readonly kind = 'chromium';
  observer!: PlaywrightSurface;
  private manager: Page | null = null;

  private constructor(
    private ctx: BrowserContext,
    readonly version: string,
    readonly base: string,
    private readonly opts: LaunchOptions,
    private readonly profile: string,
  ) {}

  /** Starts Chromium on `profile` with the unpacked extension (`--load-extension`). */
  private static async open(profile: string, opts: LaunchOptions): Promise<{ ctx: BrowserContext; id: string; version: string }> {
    const ctx = await chromium.launchPersistentContext(profile, {
      channel: 'chromium',
      headless: HEADLESS,
      args: [
        `--disable-extensions-except=${opts.extensionDir}`,
        `--load-extension=${opts.extensionDir}`,
        `--ignore-certificate-errors-spki-list=${opts.certs.caSpki}`,
      ],
    });
    try {
      const worker = ctx.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://')) ?? (await ctx.waitForEvent('serviceworker', { timeout: WAIT_MS }));
      const id = new URL(worker.url()).host;
      // The full version (the user agent string gives only the major one).
      const version = await worker.evaluate(async () => {
        const ua = (navigator as unknown as { userAgentData?: { getHighEntropyValues(h: string[]): Promise<{ uaFullVersion?: string }> } }).userAgentData;
        return (await ua?.getHighEntropyValues(['uaFullVersion']))?.uaFullVersion ?? navigator.userAgent.replace(/^.*Chrome\/(\S+).*$/, '$1');
      });
      return { ctx, id, version };
    } catch (e) {
      await ctx.close();
      throw e;
    }
  }

  static async launch(opts: LaunchOptions): Promise<ChromiumSession> {
    const profile = mkdtempSync(path.join(tmpdir(), 'picket-chromium-'));
    let opened: Awaited<ReturnType<typeof ChromiumSession.open>>;
    try {
      // "Use secure DNS" with a custom provider: the fake edge (what a profile DoH URL sets up).
      writeFileSync(path.join(profile, 'Local State'), JSON.stringify({ dns_over_https: { mode: 'secure', templates: opts.dohUrl } }));
      opened = await ChromiumSession.open(profile, opts);
    } catch (e) {
      // open() closed the browser it started, if any.
      await removeProfile(profile, Promise.resolve());
      throw e;
    }
    const { ctx, id, version } = opened;
    const s = new ChromiumSession(ctx, version, `chrome-extension://${id}/`, opts, profile);
    try {
      // The options page the install opens first: Chromium would load it into the next blank tab.
      await s.installTab();
      // Developer mode, as the install steps say (Chromium disables unpacked extensions on Reload without it).
      const manager = await s.extensionsPage();
      await manager.evaluate(() => {
        const dp = (globalThis as unknown as { chrome: { developerPrivate: { updateProfileConfiguration(c: { inDeveloperMode: boolean }): Promise<void> } } }).chrome
          .developerPrivate;
        return dp.updateProfileConfiguration({ inDeveloperMode: true });
      });
      await s.reopenObserver();
      return s;
    } catch (e) {
      await s.close();
      throw e;
    }
  }

  idleBackground(idleMs: number): Promise<void> {
    return idle(this.observer, idleMs, async () => {
      const cdp = await this.ctx.newCDPSession(this.observer.page);
      try {
        await cdp.send('ServiceWorker.enable');
        await cdp.send('ServiceWorker.stopAllWorkers');
      } finally {
        await cdp.detach();
      }
    });
  }

  async restart(): Promise<void> {
    await this.ctx.close();
    this.manager = null;
    const { ctx } = await ChromiumSession.open(this.profile, this.opts);
    this.ctx = ctx;
    // An extension loaded from the command line is installed again at each start, so it opens
    // its options page again (a Load unpacked one doesn't): wait for it, then close it.
    const options = await this.installTab().catch(() => null);
    if (options instanceof ChromiumTab) {
      await options.page.close();
    }
    await this.reopenObserver();
  }

  async reopenObserver(): Promise<void> {
    const page = await this.ctx.newPage();
    await page.goto(`${this.base}block.html`);
    this.observer = new PlaywrightSurface(page);
    await this.observer.run(observe, null);
  }

  navEvents(): Promise<NavEvent[]> {
    return this.observer.run(navLog, null);
  }

  private async tabOf(page: Page, url: string): Promise<Tab> {
    const id = await poll(`the tab of ${url}`, () => this.observer.run(tabWithUrl, url), WAIT_MS);
    return new ChromiumTab(id, page);
  }

  async installTab(): Promise<Tab> {
    const page = await poll(
      'the options page opened on install',
      () => Promise.resolve(this.ctx.pages().find((p) => p.url().startsWith(`${this.base}options.html`))),
      WAIT_MS,
    );
    // Its tab id: the observer started after it loaded, so ask the page itself.
    const id = await page.evaluate(() => {
      const c = (globalThis as unknown as { chrome: { tabs: { getCurrent(): Promise<{ id?: number } | undefined> } } }).chrome;
      return c.tabs.getCurrent().then((t) => t?.id ?? -1);
    });
    return new ChromiumTab(id, page);
  }

  async newTab(): Promise<Tab> {
    const page = await this.ctx.newPage();
    markerCounter += 1;
    const marker = `${this.opts.markerUrl}?tab=${String(markerCounter)}`;
    await page.goto(marker);
    return this.tabOf(page, marker);
  }

  async openExtensionTab(name: string): Promise<Tab> {
    const page = await this.ctx.newPage();
    await page.goto(`${this.base}${name}`);
    const id = await page.evaluate(() => {
      const c = (globalThis as unknown as { chrome: { tabs: { getCurrent(): Promise<{ id?: number } | undefined> } } }).chrome;
      return c.tabs.getCurrent().then((t) => t?.id ?? -1);
    });
    return new ChromiumTab(id, page);
  }

  async openPopup(tab: Tab): Promise<Surface> {
    const opened = this.ctx.waitForEvent('page', { predicate: (p) => p.url().startsWith(`${this.base}popup.html`), timeout: WAIT_MS });
    await this.observer.run(async (tabId) => {
      const c = (globalThis as unknown as ExtGlobal).chrome;
      const t = await c.tabs.get(tabId);
      await c.tabs.create({ url: 'popup.html', active: false, windowId: t.windowId, index: t.index + 1 });
    }, tab.id);
    const page = await opened;
    const s = new PlaywrightSurface(page);
    // Shown once it has read the active tab and rendered, as on Firefox.
    await s.waitFor(popupReady, null);
    await page.bringToFront();
    return s;
  }

  private async extensionsPage(): Promise<Page> {
    if (this.manager === null) {
      this.manager = await this.ctx.newPage();
      await this.manager.goto('chrome://extensions');
    }
    return this.manager;
  }

  async update(): Promise<void> {
    const manager = await this.extensionsPage();
    const id = new URL(this.base).host;
    await manager.evaluate((extId) => {
      const dp = (globalThis as unknown as { chrome: { developerPrivate: { reload(id: string, o: { failQuietly: boolean }): Promise<void> } } }).chrome
        .developerPrivate;
      return dp.reload(extId, { failQuietly: false });
    }, id);
    // The extension's pages closed with it; the observer comes back on the new version.
    await this.waitForExtension();
    await this.reopenObserver();
  }

  /** Waits until the extension's pages load (after a start or a reload). */
  private async waitForExtension(): Promise<void> {
    await poll(
      'the extension to load',
      async () => {
        const page = await this.ctx.newPage();
        const ok = await page.goto(`${this.base}block.html`).then(() => true, () => false);
        await page.close();
        return ok;
      },
      WAIT_MS,
    );
  }

  async preGrant(pattern: string): Promise<void> {
    const manager = await this.extensionsPage();
    const id = new URL(this.base).host;
    await manager.evaluate(
      ([extId, p]) => {
        const dp = (globalThis as unknown as { chrome: { developerPrivate: { addHostPermission(id: string, host: string): Promise<void> } } }).chrome
          .developerPrivate;
        return dp.addHostPermission(extId, p);
      },
      [id, pattern] as const,
    );
  }

  async close(): Promise<void> {
    await removeProfile(this.profile, this.ctx.close());
  }
}

// ---------------------------------------------------------------------------------------------
// Firefox

/** Wraps `fn(arg)` as an expression whose value is the result as JSON. */
function expressionOf<A, R>(fn: (arg: A) => R | Promise<R>, arg: A): string {
  return `(async () => JSON.stringify((await (${fn.toString()})(${JSON.stringify(arg)})) ?? null))()`;
}

class BidiSurface implements Surface {
  constructor(
    private readonly bidi: Bidi,
    readonly context: string,
  ) {}
  run<A, R>(fn: (arg: A) => R | Promise<R>, arg: A): Promise<R> {
    return this.bidi.evaluateJson<R>(this.context, expressionOf(fn, arg));
  }
  async click(selector: string): Promise<void> {
    // Like Playwright's click: wait until the element is there, shown and enabled.
    await this.waitFor(
      (sel) => {
        const el = document.querySelector(sel);
        return el instanceof HTMLElement && el.offsetParent !== null && !(el as HTMLButtonElement).disabled;
      },
      selector,
    );
    await this.run((sel) => {
      document.querySelector(sel)?.scrollIntoView({ block: 'center' });
    }, selector);
    const ref = await this.bidi.element(this.context, selector);
    if (ref === null) {
      throw new Error(`no element ${selector}`);
    }
    await this.bidi.click(this.context, ref);
  }
  async fill(selector: string, value: string): Promise<void> {
    await this.run(
      ([sel, v]) => {
        const el = document.querySelector(sel);
        if (!(el instanceof HTMLInputElement)) {
          throw new Error(`no input ${sel}`);
        }
        el.focus();
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      },
      [selector, value] as const,
    );
  }
  async select(selector: string, value: string): Promise<void> {
    await this.run(
      ([sel, v]) => {
        const el = document.querySelector(sel);
        if (!(el instanceof HTMLSelectElement)) {
          throw new Error(`no select ${sel}`);
        }
        el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      },
      [selector, value] as const,
    );
  }
  text(selector: string): Promise<string> {
    return this.run((sel) => document.querySelector(sel)?.textContent ?? '', selector);
  }
  visible(selector: string): Promise<boolean> {
    return this.run((sel) => {
      const el = document.querySelector(sel);
      return el instanceof HTMLElement && el.offsetParent !== null;
    }, selector);
  }
  waitFor<A, R>(fn: (arg: A) => R | Promise<R>, arg: A, timeoutMs = WAIT_MS): Promise<R> {
    return poll(`a condition in ${this.context}`, () => this.run(fn, arg), timeoutMs);
  }
}

class FirefoxTab implements Tab {
  constructor(
    readonly id: number,
    private readonly bidi: Bidi,
    readonly context: string,
  ) {}
  async goto(url: string): Promise<void> {
    await this.bidi.send('browsingContext.navigate', { context: this.context, url, wait: 'none' }).catch(() => undefined);
  }
  async url(): Promise<string> {
    const [c] = await this.bidi.send<{ contexts: { url: string }[] }>('browsingContext.getTree', { root: this.context, maxDepth: 0 }).then((r) => r.contexts);
    return c?.url ?? '';
  }
  waitForUrl(match: (url: string) => boolean, timeoutMs = WAIT_MS): Promise<string> {
    return poll('the tab URL', async () => {
      const u = await this.url();
      return match(u) ? u : '';
    }, timeoutMs);
  }
  surface(): Surface {
    return new BidiSurface(this.bidi, this.context);
  }
}

class FirefoxSession implements Session {
  readonly kind = 'firefox';
  readonly base = `moz-extension://${FIREFOX_UUID}/`;
  observer!: BidiSurface;

  constructor(
    private readonly ctx: BrowserContext,
    private readonly bidi: Bidi,
    readonly version: string,
    private readonly opts: LaunchOptions,
    private readonly profile: string,
  ) {}

  static async launch(opts: LaunchOptions): Promise<FirefoxSession> {
    const profile = mkdtempSync(path.join(tmpdir(), 'picket-firefox-'));
    let ctx: BrowserContext;
    let port: number;
    try {
      port = await freePort();
      ctx = await FirefoxSession.start(profile, port, opts);
    } catch (e) {
      await removeProfile(profile, Promise.resolve());
      throw e;
    }
    let bidi: Bidi | null = null;
    try {
      bidi = await Bidi.connect(port);
      await bidi.send('session.new', { capabilities: {} });
      const [win] = await bidi.tree('chrome');
      if (win === undefined) {
        throw new Error('no Firefox window');
      }
      const version = await FirefoxSession.prepare(bidi, win.context, opts);
      const s = new FirefoxSession(ctx, bidi, version, opts, profile);
      await s.install(opts.extensionDir);
      await s.reopenObserver();
      return s;
    } catch (e) {
      bidi?.close();
      await removeProfile(profile, ctx.close());
      throw e;
    }
  }

  private static start(profile: string, port: number, opts: LaunchOptions): Promise<BrowserContext> {
    return firefox.launchPersistentContext(profile, {
      headless: HEADLESS,
      args: [`--remote-debugging-port=${String(port)}`],
      // BiDi may evaluate script in extension pages only with this set.
      env: { ...process.env, MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: '1' },
      firefoxUserPrefs: {
        // Keep Playwright's prefs; BiDi's recommended set would change them.
        'remote.prefs.recommended': false,
        'extensions.webextensions.uuids': JSON.stringify({ [GECKO_ID]: FIREFOX_UUID }),
        // permissions.request grants without the doorhanger (still only on a user action).
        'extensions.webextOptionalPermissionPrompts': false,
        ...opts.firefoxPrefs,
      },
    });
  }

  /**
   * Trusts the test CA as a user imports the LAN CA root, then resolves over TRR via the edge.
   * Returns Firefox's version.
   */
  private static prepare(bidi: Bidi, chromeContext: string, opts: LaunchOptions): Promise<string> {
    return bidi.evaluateJson<string>(
      chromeContext,
      `(() => {
        const db = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB);
        db.addCertFromBase64(${JSON.stringify(opts.certs.caDerBase64)}, 'C,,');
        const p = Services.prefs;
        p.setCharPref('network.trr.uri', ${JSON.stringify(opts.dohUrl)});
        p.setCharPref('network.trr.custom_uri', ${JSON.stringify(opts.dohUrl)});
        p.setBoolPref('network.trr.allow-rfc1918', true);
        p.setCharPref('network.trr.confirmationNS', 'skip');
        p.setIntPref('network.trr.mode', 3);
        return JSON.stringify(Services.appinfo.version);
      })()`,
    );
  }

  /** Installs (or, with the same id, updates) the extension as a temporary add-on. */
  async install(dir: string): Promise<void> {
    await this.bidi.send('webExtension.install', { extensionData: { type: 'path', path: dir } });
  }

  async update(dir: string): Promise<void> {
    // The update closes the extension's pages; Firefox quits when that closes its last window.
    await this.ctx.newPage();
    await this.install(dir);
    await this.reopenObserver();
  }

  /** A new tab in a new window (Playwright's Firefox opens each page in its own window). */
  private async newContext(): Promise<string> {
    const before = new Set((await this.bidi.tree()).map((c) => c.context));
    await this.ctx.newPage();
    return poll('the new tab', async () => (await this.bidi.tree()).find((c) => !before.has(c.context))?.context ?? '', WAIT_MS);
  }

  async reopenObserver(): Promise<void> {
    const context = await this.newContext();
    await this.bidi.send('browsingContext.navigate', { context, url: `${this.base}block.html`, wait: 'complete' });
    this.observer = new BidiSurface(this.bidi, context);
    await this.observer.run(observe, null);
  }

  navEvents(): Promise<NavEvent[]> {
    return this.observer.run(navLog, null);
  }

  private async tabIdIn(context: string): Promise<number> {
    const s = new BidiSurface(this.bidi, context);
    return s.run(() => {
      const c = (globalThis as unknown as { chrome: { tabs: { getCurrent(): Promise<{ id?: number } | undefined> } } }).chrome;
      return c.tabs.getCurrent().then((t) => t?.id ?? -1);
    }, null);
  }

  async installTab(): Promise<Tab> {
    const context = await poll(
      'the options page opened on install',
      async () => (await this.bidi.tree()).find((c) => c.url.startsWith(`${this.base}options.html`))?.context ?? '',
      WAIT_MS,
    );
    await new BidiSurface(this.bidi, context).waitFor(() => document.readyState === 'complete', null);
    return new FirefoxTab(await this.tabIdIn(context), this.bidi, context);
  }

  async newTab(): Promise<Tab> {
    const context = await this.newContext();
    markerCounter += 1;
    const marker = `${this.opts.markerUrl}?tab=${String(markerCounter)}`;
    await this.bidi.send('browsingContext.navigate', { context, url: marker, wait: 'complete' });
    const id = await poll(`the tab of ${marker}`, () => this.observer.run(tabWithUrl, marker), WAIT_MS);
    return new FirefoxTab(id, this.bidi, context);
  }

  async openExtensionTab(name: string): Promise<Tab> {
    const context = await this.newContext();
    await this.bidi.send('browsingContext.navigate', { context, url: `${this.base}${name}`, wait: 'complete' });
    return new FirefoxTab(await this.tabIdIn(context), this.bidi, context);
  }

  async openPopup(tab: Tab): Promise<Surface> {
    const before = new Set((await this.bidi.tree()).map((c) => c.context));
    const popupTab = await this.observer.run(async (tabId) => {
      const c = (globalThis as unknown as ExtGlobal).chrome;
      const t = await c.tabs.get(tabId);
      return (await c.tabs.create({ url: 'popup.html', active: false, windowId: t.windowId, index: t.index + 1 })).id ?? -1;
    }, tab.id);
    const context = await poll(
      'the popup tab',
      async () => (await this.bidi.tree()).find((c) => !before.has(c.context) && c.url.startsWith(`${this.base}popup.html`))?.context ?? '',
      WAIT_MS,
    );
    const s = new BidiSurface(this.bidi, context);
    // Shown once it has read the active tab, so input reaches it (BiDi can't activate an
    // extension page's context).
    await s.waitFor(popupReady, null);
    await this.observer.run((id) => (globalThis as unknown as ExtGlobal).chrome.tabs.update(id, { active: true }).then(() => true), popupTab);
    return s;
  }

  preGrant(): Promise<void> {
    return Promise.resolve();
  }

  restart(): Promise<void> {
    return Promise.reject(new Error('Firefox removes temporary add-ons when it quits'));
  }

  idleBackground(idleMs: number): Promise<void> {
    return idle(this.observer, idleMs, null);
  }

  async close(): Promise<void> {
    await this.bidi.send('session.end').catch(() => undefined);
    this.bidi.close();
    // Firefox writes its profile until it has quit: removed after the close, or retried.
    await removeProfile(this.profile, this.ctx.close());
  }
}

export async function launch(opts: LaunchOptions): Promise<Session> {
  return opts.kind === 'chromium' ? ChromiumSession.launch(opts) : FirefoxSession.launch(opts);
}
