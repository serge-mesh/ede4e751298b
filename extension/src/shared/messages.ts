// Messages between the extension's pages (block page, popup, options) and its background
// script, which alone calls the edge (browser-extension.md §4). Every request is checked in the
// background before use; every reply is a `Result`.

import browser from 'webextension-polyfill';

import { fail, MAX_DURATION_S, MAX_ENTRIES, MAX_ID_LENGTH, type AllowView, type Result } from './api';
import { MAX_URL } from './block-info';

/** A blocked host the sub-resource detection found on a tab. */
export interface TabBlock {
  host: string;
  kind: 'dns' | 'ip';
  /** DNS blocks: the block id and its EDE details. */
  blockId?: string;
  bundle?: string;
  head?: string;
  lookup?: string;
  verdict?: string;
  /** When it was seen (ms since the epoch). */
  at: number;
}

export interface State {
  edgeUrl: string | null;
  coreUrl: string | null;
  /** The edge origin's host permission is granted. */
  edgeAccess: boolean;
  /** Blocked sub-resource detection is on (its optional permissions are granted). */
  detection: boolean;
  /** Granted on Brave since its last start: detection starts with the next one. */
  detectionAfterRestart: boolean;
}

/** An allow to create: a DNS block by its id, or an IP. */
export type NewAllow =
  | { kind: 'dns'; blockId: string; name: string; subdomains: boolean }
  | { kind: 'ip'; ip: string };

/**
 * The device's active allows as the edge lists them (only active ones), with the edge's clock
 * minus this device's (ms), so pages count down and show times by the edge's clock.
 */
export interface AllowList {
  allows: AllowView[];
  skewMs: number;
}

export interface CreateResult extends AllowList {
  /** The allow the edge lists for each requested entry, in order. */
  created: AllowView[];
  /** The `expires_at` asked for (the edge may shorten it to its `max_duration`). */
  requestedUntil: number;
}

export type Request =
  | { type: 'getState' }
  | { type: 'saveSettings'; edgeUrl: string; coreUrl: string }
  | { type: 'testEdge' }
  | { type: 'listAllows' }
  | { type: 'createAllows'; durationS: number; entries: NewAllow[] }
  | { type: 'endAllow'; allowId: string }
  | { type: 'tabBlocks'; tabId: number }
  | { type: 'reloadAfterAllow'; url: string };

export interface ResponseMap {
  getState: Result<State>;
  saveSettings: Result<State>;
  testEdge: Result<AllowList>;
  listAllows: Result<AllowList>;
  createAllows: Result<CreateResult>;
  endAllow: Result<AllowList>;
  tabBlocks: Result<TabBlock[]>;
  reloadAfterAllow: Result<null>;
}

export type ResponseOf<R extends Request> = ResponseMap[R['type']];

const MAX_INPUT = 4096;

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isStr = (x: unknown, max = MAX_INPUT): x is string => typeof x === 'string' && x.length <= max;
const isId = (x: unknown): x is string => isStr(x, MAX_ID_LENGTH) && x.length > 0;

function parseNewAllow(x: unknown): NewAllow | null {
  if (!isObj(x)) {
    return null;
  }
  if (x.kind === 'dns' && isId(x.blockId) && isStr(x.name, 255) && typeof x.subdomains === 'boolean') {
    return { kind: 'dns', blockId: x.blockId, name: x.name, subdomains: x.subdomains };
  }
  if (x.kind === 'ip' && isId(x.ip)) {
    return { kind: 'ip', ip: x.ip };
  }
  return null;
}

/** The request a message holds, or null when it isn't one. */
export function parseRequest(x: unknown): Request | null {
  if (!isObj(x)) {
    return null;
  }
  switch (x.type) {
    case 'getState':
    case 'testEdge':
    case 'listAllows':
      return { type: x.type };
    case 'saveSettings':
      return isStr(x.edgeUrl) && isStr(x.coreUrl)
        ? { type: 'saveSettings', edgeUrl: x.edgeUrl, coreUrl: x.coreUrl }
        : null;
    case 'createAllows': {
      const d = x.durationS;
      const list = x.entries;
      if (typeof d !== 'number' || !Number.isInteger(d) || d < 1 || d > MAX_DURATION_S) {
        return null;
      }
      if (!Array.isArray(list) || list.length === 0 || list.length > MAX_ENTRIES) {
        return null;
      }
      const entries: NewAllow[] = [];
      for (const e of list) {
        const n = parseNewAllow(e);
        if (n === null) {
          return null;
        }
        entries.push(n);
      }
      return { type: 'createAllows', durationS: d, entries };
    }
    case 'endAllow':
      return isId(x.allowId) ? { type: 'endAllow', allowId: x.allowId } : null;
    case 'tabBlocks': {
      const t = x.tabId;
      return typeof t === 'number' && Number.isInteger(t) && t >= 0 ? { type: 'tabBlocks', tabId: t } : null;
    }
    case 'reloadAfterAllow':
      return isStr(x.url, MAX_URL) ? { type: 'reloadAfterAllow', url: x.url } : null;
    default:
      return null;
  }
}

function isResult(x: unknown): x is Result<unknown> {
  return isObj(x) && (x.ok === true || (x.ok === false && isObj(x.error)));
}

/** Sends a request to the background script. */
export async function send<R extends Request>(req: R): Promise<ResponseOf<R>> {
  try {
    const reply: unknown = await browser.runtime.sendMessage(req);
    if (isResult(reply)) {
      return reply as ResponseOf<R>;
    }
    return fail({ kind: 'bad_response', message: 'no reply from the background script' }) as ResponseOf<R>;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return fail({ kind: 'request', message: `The extension's background script failed: ${message}` }) as ResponseOf<R>;
  }
}
