// The block page (browser-extension.md §3 steps 3–4): what was blocked and why, 15 min, 1 h, 8 h
// or 24 h allows, and "Allow permanently…" (core's UI). After an allow it counts down the
// edge's `retry_after_s` to a fixed deadline (a hidden tab's timers are throttled), then has the
// background load the original URL again.

import browser from 'webextension-polyfill';

import { describeError, DURATIONS, type ApiError } from '../shared/api';
import { fromQuery, keptUrl, MAX_URL } from '../shared/block-info';
import { send, type NewAllow } from '../shared/messages';
import { byId, clockTime, h, setText, span } from './dom';

export interface BlockPageEnv {
  search: string;
  /** Leaves the block page for `url` (when the background can't). */
  replace(url: string): void;
  /** Goes `steps` entries back in the tab's history. */
  back(steps: number): void;
  /** This page's index in the tab's history (0: the first entry). */
  historyIndex: number;
  openTab(url: string): Promise<void>;
  /** A long page URL the background kept for this page (block-info.ts), or null. */
  keptUrl(id: string): Promise<string | null>;
  /** Monotonic ms (the countdown). */
  now(): number;
}

const defaultEnv = (): BlockPageEnv => ({
  search: location.search,
  replace: (url) => {
    location.replace(url);
  },
  back: (steps) => {
    history.go(-steps);
  },
  // The block page is opened as the tab's newest entry. (The Navigation API's index counts only
  // same-origin entries, so it can't tell.)
  historyIndex: history.length - 1,
  openTab: async (url) => {
    await browser.tabs.create({ url });
  },
  keptUrl: (id) => keptUrl(browser.storage.session, id),
  now: () => performance.now(),
});

function detailRow(dl: HTMLElement, term: string, value: string): void {
  dl.append(h('dt', { text: term }), h('dd', { text: value }));
}

export async function startBlockPage(env: BlockPageEnv = defaultEnv()): Promise<void> {
  const parsed = fromQuery(env.search);
  const title = byId('title', HTMLElement);
  const lead = byId('lead', HTMLElement);
  const details = byId('details', HTMLElement);
  const note = byId('note', HTMLElement);
  const choose = byId('choose', HTMLElement);
  const durations = byId('durations', HTMLElement);
  const status = byId('status', HTMLElement);
  const retry = byId('retry', HTMLButtonElement);
  const core = byId('core', HTMLButtonElement);
  const back = byId('back', HTMLButtonElement);

  // Firefox's block page replaced the failed load's history entry; on Chromium that entry is
  // just before this page, and going back to it would only fail (and block) again.
  const steps = parsed?.replaced === true ? 1 : 2;
  back.hidden = env.historyIndex < steps;
  back.addEventListener('click', () => {
    env.back(steps);
  });

  const showStatus = (text: string, kind: 'info' | 'error' | 'ok' = 'info'): void => {
    status.hidden = false;
    status.className = `status ${kind}`;
    setText(status, text);
  };

  if (parsed === null) {
    setText(title, 'Invalid block page');
    setText(lead, 'This block page link is incomplete. Load the page you wanted again.');
    return;
  }
  const info = parsed.info;
  if (parsed.ref !== null) {
    info.url = await env.keptUrl(parsed.ref).catch(() => null);
  }

  const state = await send({ type: 'getState' });
  const coreUrl = state.ok ? state.value.coreUrl : null;
  if (coreUrl !== null) {
    core.hidden = false;
    core.addEventListener('click', () => {
      void env.openTab(coreUrl);
    });
  }

  if (info.kind === 'dns') {
    document.title = `Blocked: ${info.name}`;
    setText(title, 'Picket blocked this site');
    setText(lead, 'The name below is blocked by Picket on this network.');
    detailRow(details, 'Name', info.name);
    if (info.lookup !== undefined) {
      detailRow(details, 'Lookup provider', info.lookup);
      detailRow(details, 'Verdict', info.verdict ?? 'unknown');
    } else if (info.bundle !== undefined) {
      detailRow(details, 'Bundle', info.head === undefined ? info.bundle : `${info.bundle} (version ${info.head})`);
    } else {
      detailRow(details, 'Blocked by', 'a Picket rule (details not available)');
    }
    detailRow(details, 'Block ID', info.blockId);
    const subsRow = byId('subdomains-row', HTMLElement);
    subsRow.hidden = false;
    setText(byId('subdomains-label', HTMLElement), `Also allow subdomains of ${info.name}`);
  } else {
    document.title = `Blocked: ${info.ip}`;
    setText(title, "Picket's firewall blocked this address");
    setText(lead, 'Picket holds no allow for this IP address, so its firewall check refuses connections to it.');
    detailRow(details, 'IP', info.ip);
    detailRow(details, 'Stage', 'firewall');
    note.hidden = false;
    setText(
      note,
      "Picket logs no IP refusals: UniFi's log shows them under the Block All policy. A UniFi policy can also decide before Picket's check does.",
    );
  }
  const pageUrl = info.url;
  if (pageUrl === null) {
    const why =
      parsed.ref === null
        ? `is longer than ${String(MAX_URL / 1024)} KiB, too long to keep`
        : 'is no longer kept (a long address is kept only while its block page is open)';
    details.after(h('p', { class: 'note', text: `The page's address ${why}, so after an allow, load the page again yourself.` }));
  }

  const subdomains = byId('subdomains', HTMLInputElement);
  const buttons: HTMLButtonElement[] = [];
  const setBusy = (busy: boolean): void => {
    for (const b of buttons) {
      b.disabled = busy;
    }
    subdomains.disabled = busy;
    retry.disabled = busy;
  };

  const refuse = (e: ApiError): void => {
    // 403: bypass off or a limit hit; only an admin can help (browser-extension.md §3).
    choose.hidden = true;
    retry.hidden = true;
    showStatus(`${describeError(e)} Ask an admin${coreUrl === null ? '.' : ', or open core’s UI.'}`, 'error');
    if (coreUrl !== null) {
      setText(core, 'Open core UI');
    }
  };

  const reload = async (): Promise<void> => {
    if (pageUrl === null) {
      showStatus('Allowed. Load the page again.', 'ok');
      return;
    }
    showStatus('Loading the page…', 'ok');
    const r = await send({ type: 'reloadAfterAllow', url: pageUrl });
    if (!r.ok) {
      env.replace(pageUrl);
    }
  };

  /**
   * Counts down to a fixed deadline on the monotonic clock: hidden tabs throttle timers (to one
   * a minute in Chromium), so ticks only refresh the text, and the page checks again as soon as
   * it is shown.
   */
  const countdown = (seconds: number, done: () => void): void => {
    const deadline = env.now() + Math.max(0, seconds) * 1000;
    let finished = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    /** Shows the time left; true once the deadline has passed (and `done` ran). */
    const check = (): boolean => {
      if (finished) {
        return true;
      }
      const leftMs = deadline - env.now();
      if (leftMs <= 0) {
        finished = true;
        clearInterval(timer);
        document.removeEventListener('visibilitychange', onShown);
        done();
        return true;
      }
      showStatus(`Allowed. The browser may still hold the blocked answer: reloading in ${span(Math.ceil(leftMs / 1000))}…`, 'ok');
      return false;
    };
    const onShown = (): void => {
      check();
    };
    if (!check()) {
      timer = setInterval(onShown, 500);
      setTimeout(onShown, Math.max(0, seconds) * 1000);
      document.addEventListener('visibilitychange', onShown);
    }
  };

  const allow = async (seconds: number): Promise<void> => {
    retry.hidden = true;
    setBusy(true);
    showStatus('Asking the edge…');
    const entry: NewAllow =
      info.kind === 'dns'
        ? { kind: 'dns', blockId: info.blockId, name: info.name, subdomains: subdomains.checked }
        : { kind: 'ip', ip: info.ip };
    const r = await send({ type: 'createAllows', durationS: seconds, entries: [entry] });
    if (!r.ok) {
      setBusy(false);
      if (r.error.kind === 'forbidden') {
        refuse(r.error);
        return;
      }
      showStatus(describeError(r.error), 'error');
      retry.hidden = false;
      retry.onclick = () => {
        void allow(seconds);
      };
      return;
    }
    // The background checked that the edge lists this allow (a 200 without it is an error).
    const a = r.value.created[0];
    choose.hidden = true;
    const until = a?.expires_at ?? r.value.requestedUntil;
    const shortened = until < r.value.requestedUntil - 60 ? ` (shortened to this profile's longest allow)` : '';
    // `expires_at` is the edge's time: shown by this device's clock.
    setText(lead, `Allowed until ${clockTime(until - r.value.skewMs / 1000)}${shortened}.`);
    countdown(a?.retry_after_s ?? 0, () => {
      void reload();
    });
  };

  for (const d of DURATIONS) {
    const b = h('button', { text: d.label, attrs: { type: 'button' } });
    b.addEventListener('click', () => {
      void allow(d.seconds);
    });
    buttons.push(b);
    durations.append(b);
  }
  choose.hidden = false;
  if (!state.ok || state.value.edgeUrl === null) {
    setBusy(true);
    showStatus(state.ok ? describeError({ kind: 'not_configured', message: '' }) : describeError(state.error), 'error');
  }
}
