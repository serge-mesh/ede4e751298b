// An in-memory stand-in for the WebExtension APIs the extension uses, aliased in place of
// webextension-polyfill (vitest.config.ts). Messages are cloned as the browser does, and carry a
// sender (this extension's id, the sending page's URL and tab).

import { vi } from 'vitest';

type Fn = (...args: never[]) => unknown;

export class FakeEvent<F extends Fn = Fn> {
  readonly listeners: F[] = [];
  addListener(fn: F): void {
    this.listeners.push(fn);
  }
  removeListener(fn: F): void {
    const i = this.listeners.indexOf(fn);
    if (i >= 0) {
      this.listeners.splice(i, 1);
    }
  }
  hasListener(fn: F): boolean {
    return this.listeners.includes(fn);
  }
  emit(...args: Parameters<F>): unknown[] {
    return this.listeners.map((l) => l(...args));
  }
}

export class FakeArea {
  data = new Map<string, unknown>();
  get = vi.fn(async (keys?: string | string[] | null): Promise<Record<string, unknown>> => {
    const list = keys === undefined || keys === null ? [...this.data.keys()] : typeof keys === 'string' ? [keys] : keys;
    const out: Record<string, unknown> = {};
    for (const k of list) {
      if (this.data.has(k)) {
        out[k] = structuredClone(this.data.get(k));
      }
    }
    return out;
  });
  set = vi.fn(async (items: Record<string, unknown>): Promise<void> => {
    for (const [k, v] of Object.entries(items)) {
      this.data.set(k, structuredClone(v));
    }
  });
  remove = vi.fn(async (keys: string | string[]): Promise<void> => {
    for (const k of typeof keys === 'string' ? [keys] : keys) {
      this.data.delete(k);
    }
  });
}

export const EXTENSION_ID = 'test-extension-id';
export const BASE = `chrome-extension://${EXTENSION_ID}/`;

interface Perms {
  origins?: string[];
  permissions?: string[];
}

function covers(granted: Set<string>, origin: string): boolean {
  return granted.has(origin) || (granted.has('<all_urls>') && /^(https?|wss?):\/\//.test(origin));
}

function makeFake() {
  const granted = { origins: new Set<string>(), permissions: new Set<string>() };
  // Closures read the exported object, whose fields tests change.
  const self = (): FakeBrowser => exported;
  const fake = {
    /** The page messages come from, and its tab. */
    sender: { url: `${BASE}popup.html`, tabId: undefined as number | undefined },
    /** What a permission request answers. */
    grant: true,
    granted,
    runtime: {
      id: EXTENSION_ID,
      getURL: (p: string) => `${BASE}${p.replace(/^\//, '')}`,
      onMessage: new FakeEvent<(m: unknown, s: { id: string; url: string; tab?: { id: number } }) => unknown>(),
      onInstalled: new FakeEvent<(d: { reason: string }) => void>(),
      openOptionsPage: vi.fn(async () => undefined),
      sendMessage: vi.fn(async (message: unknown): Promise<unknown> => {
        const { url, tabId } = self().sender;
        const sender = { id: EXTENSION_ID, url, ...(tabId === undefined ? {} : { tab: { id: tabId } }) };
        const replies = self().runtime.onMessage.emit(structuredClone(message), sender);
        const first = replies.find((r) => r !== undefined);
        if (first === undefined) {
          throw new Error('Could not establish connection. Receiving end does not exist.');
        }
        return structuredClone(await Promise.resolve(first));
      }),
    },
    storage: { local: new FakeArea(), session: new FakeArea() },
    permissions: {
      contains: vi.fn(async (p: Perms) =>
        (p.origins ?? []).every((o) => covers(granted.origins, o)) &&
        (p.permissions ?? []).every((x) => granted.permissions.has(x)),
      ),
      request: vi.fn(async (p: Perms) => {
        if (!self().grant) {
          return false;
        }
        for (const o of p.origins ?? []) {
          granted.origins.add(o);
        }
        for (const x of p.permissions ?? []) {
          granted.permissions.add(x);
        }
        return true;
      }),
      remove: vi.fn(async (p: Perms) => {
        for (const o of p.origins ?? []) {
          granted.origins.delete(o);
        }
        for (const x of p.permissions ?? []) {
          granted.permissions.delete(x);
        }
        return true;
      }),
      onAdded: new FakeEvent(),
      onRemoved: new FakeEvent(),
    },
    tabs: {
      update: vi.fn(async (tabId: number, props: { url?: string }) => ({ id: tabId, ...props })),
      create: vi.fn(async (props: { url?: string }) => ({ id: 99, ...props })),
      query: vi.fn(async () => [{ id: 7 }]),
      reload: vi.fn(async () => undefined),
      onRemoved: new FakeEvent<(tabId: number) => void>(),
    },
    webNavigation: {
      onBeforeNavigate: new FakeEvent(),
      onErrorOccurred: new FakeEvent(),
      onCommitted: new FakeEvent(),
      onCompleted: new FakeEvent(),
      /** The tab's top frame: by default still the page before any failed load. */
      getFrame: vi.fn<(details: { tabId: number; frameId: number }) => Promise<{ url: string; documentId?: string; errorOccurred: boolean; parentFrameId: number } | null>>(async () => ({
        url: 'https://before.example/',
        errorOccurred: false,
        parentFrameId: -1,
      })),
    },
    action: {
      setBadgeText: vi.fn(async () => undefined),
      setBadgeBackgroundColor: vi.fn(async () => undefined),
    },
  };
  return fake;
}

export type FakeBrowser = ReturnType<typeof makeFake>;

const exported: FakeBrowser = makeFake();

/** Puts the fake back as new (call in `beforeEach`). */
export function resetFakeBrowser(): void {
  Object.assign(exported, makeFake());
}

export default exported;
