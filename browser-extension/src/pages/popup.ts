// The popup (browser-extension.md §3 step 5): this tab's blocked hosts (once blocked
// sub-resource detection is on), which can be allowed together, and the device's active allows,
// each with "End now" (a PATCH with a past `expires_at`). Errors show at the entry they name.
//
// The allows are shown as the edge lists them (it lists only active ones), counted down by the
// edge's clock (this device's plus the skew the background learnt), and listed again once one
// runs out: this device's own clock may be off by any amount.

import browser from 'webextension-polyfill';

import { describeError, DURATIONS, type ApiError } from '../shared/api';
import { send, type AllowList, type NewAllow, type State, type TabBlock } from '../shared/messages';
import { DETECTION_ON_AFTER_RESTART } from '../shared/permissions';
import { byId, clockTime, h, setText, span } from './dom';

export interface PopupEnv {
  activeTabId(): Promise<number | null>;
  openOptions(): Promise<void>;
  openTab(url: string): Promise<void>;
  reloadTab(tabId: number): Promise<void>;
  nowMs(): number;
  close(): void;
}

const defaultEnv = (): PopupEnv => ({
  activeTabId: async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    return tab?.id ?? null;
  },
  openOptions: () => browser.runtime.openOptionsPage(),
  openTab: async (url) => {
    await browser.tabs.create({ url });
  },
  reloadTab: (tabId) => browser.tabs.reload(tabId),
  nowMs: () => Date.now(),
  close: () => {
    window.close();
  },
});

/** What a blocked host's row says about its block. */
export function blockSummary(b: TabBlock): string {
  if (b.kind === 'ip') {
    return 'firewall';
  }
  if (b.lookup !== undefined) {
    return `lookup ${b.lookup}${b.verdict === undefined ? '' : ` (${b.verdict})`}`;
  }
  return b.bundle === undefined ? 'blocked' : `bundle ${b.bundle}`;
}

function showStatus(el: HTMLElement, text: string, kind: 'info' | 'error' | 'ok' = 'info'): void {
  el.hidden = text.length === 0;
  el.className = `status ${kind}`;
  setText(el, text);
}

export async function startPopup(env: PopupEnv = defaultEnv()): Promise<void> {
  const setup = byId('setup', HTMLElement);
  const main = byId('main', HTMLElement);
  const blocksList = byId('blocks', HTMLElement);
  const blocksHint = byId('blocks-hint', HTMLElement);
  const blocksActions = byId('blocks-actions', HTMLElement);
  const blocksStatus = byId('blocks-status', HTMLElement);
  const duration = byId('duration', HTMLSelectElement);
  const allowSelected = byId('allow-selected', HTMLButtonElement);
  const allowsList = byId('allows', HTMLElement);
  const allowsStatus = byId('allows-status', HTMLElement);
  const coreButton = byId('core', HTMLButtonElement);

  const openOptions = (): void => {
    void env.openOptions().then(() => {
      env.close();
    });
  };
  byId('open-options', HTMLElement).addEventListener('click', openOptions);
  byId('options', HTMLElement).addEventListener('click', openOptions);

  for (const d of DURATIONS) {
    duration.append(h('option', { text: d.label, attrs: { value: String(d.seconds) } }));
  }

  const stateR = await send({ type: 'getState' });
  const state: State | null = stateR.ok ? stateR.value : null;
  const coreUrl = state?.coreUrl ?? null;
  if (coreUrl !== null) {
    coreButton.hidden = false;
    coreButton.addEventListener('click', () => {
      void env.openTab(coreUrl);
    });
  }
  if (state?.edgeUrl === null || state === null) {
    setup.hidden = false;
    return;
  }
  main.hidden = false;
  const tabId = await env.activeTabId();

  // Active allows, and the edge's clock minus this device's (ms).
  let skewMs = 0;
  const edgeNowMs = (): number => env.nowMs() + skewMs;
  const renderAllows = (list: AllowList): void => {
    allowsList.replaceChildren();
    showStatus(allowsStatus, '');
    skewMs = list.skewMs;
    const live = [...list.allows].sort((a, b) => a.expires_at - b.expires_at);
    if (live.length === 0) {
      allowsList.append(h('li', { class: 'empty', text: 'No active allows.' }));
      return;
    }
    for (const a of live) {
      const err = h('div', { class: 'row-error', hidden: true });
      const left = h('span', { class: 'muted', attrs: { 'data-expires': String(a.expires_at) } });
      const end = h('button', { text: 'End now', class: 'small', attrs: { type: 'button' } });
      end.addEventListener('click', () => {
        void (async () => {
          end.disabled = true;
          const r = await send({ type: 'endAllow', allowId: a.allow_id });
          if (r.ok) {
            renderAllows(r.value);
          } else {
            end.disabled = false;
            err.hidden = false;
            setText(err, describeError(r.error));
          }
        })();
      });
      const label = a.kind === 'ip' ? `${a.target} (IP)` : a.subdomains === true ? `${a.target} and subdomains` : a.target;
      allowsList.append(
        h('li', {}, h('div', { class: 'row' }, h('span', { class: 'target', text: label }), end), left, err),
      );
    }
    tick();
  };

  // The allows' countdowns; when one runs out by the edge's clock, the list is asked for again
  // (then at most every 5 s while one still shows, in case the learnt skew is a second off).
  let listing = false;
  let endedAt = -Infinity;
  const tick = (): void => {
    const deviceNow = env.nowMs();
    const edgeNow = edgeNowMs() / 1000;
    let ended = false;
    for (const el of allowsList.querySelectorAll<HTMLElement>('[data-expires]')) {
      const exp = Number(el.dataset.expires);
      if (exp <= edgeNow) {
        ended = true;
        setText(el, 'ending…');
      } else {
        setText(el, `until ${clockTime(exp - skewMs / 1000, deviceNow)} · ${span(exp - edgeNow)} left`);
      }
    }
    if (ended && !listing && Math.abs(deviceNow - endedAt) >= 5_000) {
      endedAt = deviceNow;
      void loadAllows();
    }
  };

  const loadAllows = async (): Promise<void> => {
    listing = true;
    try {
      const r = await send({ type: 'listAllows' });
      if (r.ok) {
        renderAllows(r.value);
      } else {
        allowsList.replaceChildren();
        showStatus(allowsStatus, describeError(r.error), 'error');
      }
    } finally {
      listing = false;
    }
  };

  // This tab's blocked hosts.
  const rows = new Map<string, { block: TabBlock; check: HTMLInputElement; err: HTMLElement }>();
  const renderBlocks = (blocks: readonly TabBlock[]): void => {
    blocksList.replaceChildren();
    rows.clear();
    blocksActions.hidden = blocks.length === 0;
    if (blocks.length === 0) {
      blocksHint.hidden = false;
      setText(blocksHint, 'No blocked requests seen on this tab since it loaded.');
      return;
    }
    blocksHint.hidden = true;
    for (const b of blocks) {
      const check = h('input', { attrs: { type: 'checkbox' } });
      const err = h('div', { class: 'row-error', hidden: true });
      rows.set(b.host, { block: b, check, err });
      blocksList.append(
        h(
          'li',
          {},
          h('label', { class: 'row' }, check, h('span', { class: 'target', text: b.host }), h('span', { class: 'muted', text: blockSummary(b) })),
          err,
        ),
      );
    }
  };

  const loadBlocks = async (): Promise<void> => {
    if (!state.detection) {
      blocksHint.hidden = false;
      blocksActions.hidden = true;
      setText(blocksHint, 'Turn on blocked sub-resource detection in Options to list the blocked requests of this tab.');
      return;
    }
    // Until Brave has passed a request (or restarted), an empty list may only mean it doesn't
    // report requests yet: say so rather than list nothing. What it did report is listed.
    const waiting = (): void => {
      // No rows from an earlier load beside the hint.
      renderBlocks([]);
      setText(blocksHint, DETECTION_ON_AFTER_RESTART);
    };
    if (tabId === null) {
      if (state.detectionAfterRestart) {
        waiting();
      } else {
        renderBlocks([]);
      }
      return;
    }
    const r = await send({ type: 'tabBlocks', tabId });
    if (r.ok && r.value.length === 0 && state.detectionAfterRestart) {
      waiting();
    } else if (r.ok) {
      renderBlocks(r.value);
    } else {
      showStatus(blocksStatus, describeError(r.error), 'error');
    }
  };

  const showEntryError = (e: ApiError, chosen: readonly string[]): void => {
    for (const r of rows.values()) {
      r.err.hidden = true;
    }
    const host = e.index === undefined ? undefined : chosen[e.index];
    const row = host === undefined ? undefined : rows.get(host);
    // An error status changed nothing (all or nothing); a 200 missing an allow did change the rest.
    const outcome = e.kind === 'not_applied' ? '' : 'Nothing was changed.';
    if (row !== undefined) {
      row.err.hidden = false;
      setText(row.err, describeError(e));
      showStatus(blocksStatus, outcome === '' ? 'Not everything was allowed.' : outcome, 'error');
    } else {
      showStatus(blocksStatus, `${describeError(e)} ${outcome}`.trim(), 'error');
    }
  };

  allowSelected.addEventListener('click', () => {
    void (async () => {
      // One entry per chosen host, in order, so an error's `index` names its row.
      const chosen: TabBlock[] = [];
      const entries: NewAllow[] = [];
      for (const { block: b, check } of rows.values()) {
        if (!check.checked) {
          continue;
        }
        if (b.kind === 'ip') {
          entries.push({ kind: 'ip', ip: b.host });
          chosen.push(b);
        } else if (b.blockId !== undefined) {
          entries.push({ kind: 'dns', blockId: b.blockId, name: b.host, subdomains: false });
          chosen.push(b);
        }
      }
      if (entries.length === 0) {
        showStatus(blocksStatus, 'Select the hosts to allow first.', 'error');
        return;
      }
      allowSelected.disabled = true;
      showStatus(blocksStatus, 'Asking the edge…');
      const r = await send({ type: 'createAllows', durationS: Number(duration.value), entries });
      allowSelected.disabled = false;
      if (!r.ok) {
        showEntryError(r.error, chosen.map((b) => b.host));
        if (r.error.kind === 'not_applied') {
          void loadAllows();
        }
        return;
      }
      renderAllows(r.value);
      const wait = Math.max(0, ...r.value.created.map((a) => a.retry_after_s ?? 0));
      const reload = h('button', { text: 'Reload page', class: 'small', attrs: { type: 'button' } });
      reload.addEventListener('click', () => {
        if (tabId !== null) {
          void env.reloadTab(tabId).then(() => {
            env.close();
          });
        }
      });
      showStatus(
        blocksStatus,
        wait > 0 ? `Allowed. Reload the page in ${span(wait)}, once the browser drops the blocked answers.` : 'Allowed.',
        'ok',
      );
      blocksStatus.append(' ', reload);
    })();
  });

  byId('refresh', HTMLElement).addEventListener('click', () => {
    void loadBlocks();
    void loadAllows();
  });

  setInterval(tick, 1000);
  setInterval(() => {
    void loadAllows();
  }, 30_000);
  await Promise.all([loadBlocks(), loadAllows()]);
}
