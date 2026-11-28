// Loads an extension page's HTML into jsdom and stands in for the background script.

import blockHtml from '../src/pages/block.html?raw';
import optionsHtml from '../src/pages/options.html?raw';
import popupHtml from '../src/pages/popup.html?raw';
import type { Request } from '../src/shared/messages';
import fake from './fake-browser';

const PAGES = { block: blockHtml, popup: popupHtml, options: optionsHtml };

/** Puts a page's HTML (without its script) into the document. */
export function loadPage(name: keyof typeof PAGES): void {
  const doc = new DOMParser().parseFromString(PAGES[name], 'text/html');
  for (const s of doc.querySelectorAll('script')) {
    s.remove();
  }
  document.head.replaceWith(document.importNode(doc.head, true));
  document.body.replaceWith(document.importNode(doc.body, true));
}

type Handler = (req: never) => unknown;

/** A background script answering requests by type; returns the requests it got. */
export function background(handlers: Partial<Record<Request['type'], Handler>>): Request[] {
  const got: Request[] = [];
  fake.runtime.onMessage.addListener((m) => {
    const req = m as Request;
    got.push(req);
    const h = handlers[req.type];
    return Promise.resolve(h === undefined ? { ok: false, error: { kind: 'request', message: `unhandled ${req.type}` } } : h(req as never));
  });
  return got;
}

/** An element by id (cast to the type the test expects). */
export function $<T extends HTMLElement = HTMLElement>(id: string, type?: { prototype: T; new (): T }): T {
  const el = document.getElementById(id);
  if (el === null || (type !== undefined && !(el instanceof type))) {
    throw new Error(`no #${id}`);
  }
  return el as T;
}

/** Buttons by their text. */
export function button(text: string): HTMLButtonElement {
  const b = [...document.querySelectorAll('button')].find((x) => x.textContent === text);
  if (b === undefined) {
    throw new Error(`no button "${text}"`);
  }
  return b;
}

export const state = (over: Record<string, unknown> = {}) => ({
  ok: true,
  value: { edgeUrl: 'https://dns.home.arpa:9853', coreUrl: 'https://core.home.arpa:8443/', edgeAccess: true, detection: false, detectionAfterRestart: false, ...over },
});
