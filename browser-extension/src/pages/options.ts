// The options page (browser-extension.md §2): the edge API URL and, optionally, core's UI URL;
// then the edge origin's host permission and a test `GET /v1/temporary-allows`. Also the
// optional blocked sub-resource detection, and the browser-list subscription URL (bundles.md
// §8 "Subscribe"), which is built here and not stored.

import browser from 'webextension-polyfill';

import { describeError } from '../shared/api';
import { send } from '../shared/messages';
import { DETECTION_ON, DETECTION_ON_AFTER_RESTART, DETECTION_PERMISSIONS } from '../shared/permissions';
import { originPattern, parseCoreUrl, parseEdgeUrl, type UrlCheck } from '../shared/settings';
import { byId, setText } from './dom';

interface Permissions {
  origins?: string[];
  permissions?: string[];
}

export interface OptionsEnv {
  requestPermissions(p: Permissions): Promise<boolean>;
  removePermissions(p: Permissions): Promise<boolean>;
  copy(text: string): Promise<void>;
  /**
   * Brave (Chromium) passes webRequest events to the extension for access granted at run time
   * only from the browser's next start (seen in the browser tests: none until a restart, an
   * extension reload doesn't help); Firefox at once.
   */
  detectionNeedsRestart: boolean;
}

const defaultEnv = (): OptionsEnv => ({
  requestPermissions: (p) => browser.permissions.request(p as Parameters<typeof browser.permissions.request>[0]),
  removePermissions: (p) => browser.permissions.remove(p as Parameters<typeof browser.permissions.remove>[0]),
  copy: (text) => navigator.clipboard.writeText(text),
  detectionNeedsRestart: browser.runtime.getURL('').startsWith('chrome-extension:'),
});


export type ListKind = 'pruned' | 'full' | 'bundle';

/** Core's list path segment rule (apps/picket-core lists::serve). */
const SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;

/**
 * A browser list's URL (bundles.md §8 "Serving"): `/lists/profiles/<profile>.txt` (pruned),
 * `/lists/profiles/<profile>-full.txt` (full) or `/lists/<bundle>.txt`, on core's web port or
 * its plain-HTTP port.
 */
export function listUrl(kind: ListKind, rawId: string, rawBase: string): UrlCheck {
  const id = rawId.trim();
  const what = kind === 'bundle' ? 'bundle' : 'profile';
  if (id.length === 0) {
    return { ok: false, reason: `Enter the ${what} ID.` };
  }
  if (!SEGMENT.test(id)) {
    return { ok: false, reason: `A ${what} ID holds only letters, digits, "-", "_" and ".".` };
  }
  if (kind !== 'bundle' && id.endsWith('-full')) {
    return { ok: false, reason: 'A profile ID never ends in "-full": choose the full list above instead.' };
  }
  const base = parseCoreUrl(rawBase);
  if (!base.ok) {
    return base;
  }
  if (base.url === null) {
    return { ok: false, reason: "Enter core's address." };
  }
  const origin = new URL(base.url).origin;
  const path = kind === 'bundle' ? `/lists/${id}.txt` : `/lists/profiles/${id}${kind === 'full' ? '-full' : ''}.txt`;
  return { ok: true, url: `${origin}${path}` };
}

export function startOptions(env: OptionsEnv = defaultEnv()): void {
  const form = byId('settings', HTMLFormElement);
  const edgeInput = byId('edge-url', HTMLInputElement);
  const coreInput = byId('core-url', HTMLInputElement);
  const save = byId('save', HTMLButtonElement);
  const settingsStatus = byId('settings-status', HTMLElement);
  const detection = byId('detection', HTMLInputElement);
  const detectionStatus = byId('detection-status', HTMLElement);
  const listKind = byId('list-kind', HTMLSelectElement);
  const listId = byId('list-id', HTMLInputElement);
  const listIdLabel = byId('list-id-label', HTMLElement);
  const listBase = byId('list-base', HTMLInputElement);
  const listOut = byId('list-url', HTMLInputElement);
  const listStatus = byId('list-status', HTMLElement);
  const copy = byId('copy-url', HTMLButtonElement);

  const show = (el: HTMLElement, text: string, kind: 'info' | 'error' | 'ok' = 'info'): void => {
    el.hidden = text.length === 0;
    el.className = `status ${kind}`;
    setText(el, text);
  };

  let savedEdge: string | null = null;
  /** Once the user acts, the stored settings (read at start) no longer replace what is shown. */
  const ui = { acted: false };

  const refreshList = (): void => {
    setText(listIdLabel, listKind.value === 'bundle' ? 'Bundle ID' : 'Profile ID');
    const r = listUrl(listKind.value as ListKind, listId.value, listBase.value);
    listOut.value = r.ok ? r.url : '';
    copy.disabled = !r.ok;
    show(listStatus, r.ok || listId.value.trim() === '' ? '' : r.reason, 'error');
  };
  listKind.addEventListener('change', refreshList);
  listId.addEventListener('input', refreshList);
  listBase.addEventListener('input', refreshList);
  copy.addEventListener('click', () => {
    listOut.select();
    void env.copy(listOut.value).then(
      () => {
        show(listStatus, 'Copied.', 'ok');
      },
      () => {
        show(listStatus, 'Press Ctrl+C (⌘C) to copy the selected URL.', 'info');
      },
    );
  });

  const finishSave = async (asked: Promise<boolean>, edgeUrl: string, coreUrl: string): Promise<void> => {
    save.disabled = true;
    try {
      let granted = false;
      try {
        granted = await asked;
      } catch {
        granted = false;
      }
      if (!granted) {
        show(settingsStatus, 'Access to the edge was not granted; the extension needs it to reach the edge.', 'error');
        return;
      }
      const r = await send({ type: 'saveSettings', edgeUrl, coreUrl });
      if (!r.ok) {
        show(settingsStatus, describeError(r.error), 'error');
        return;
      }
      if (savedEdge !== null && originPattern(savedEdge) !== originPattern(edgeUrl)) {
        // The previous edge's access is no longer needed.
        await env.removePermissions({ origins: [originPattern(savedEdge)] }).catch(() => false);
      }
      savedEdge = r.value.edgeUrl;
      if (listBase.value.trim() === '' && r.value.coreUrl !== null) {
        listBase.value = new URL(r.value.coreUrl).origin;
        refreshList();
      }
      show(settingsStatus, 'Saved. Testing the edge…');
      const t = await send({ type: 'testEdge' });
      if (t.ok) {
        const n = t.value.allows.length;
        show(
          settingsStatus,
          `Connected. The edge lists ${String(n)} active temporary allow${n === 1 ? '' : 's'} for this device.`,
          'ok',
        );
      } else {
        show(settingsStatus, `Saved, but the test failed. ${describeError(t.error)}`, 'error');
      }
    } finally {
      save.disabled = false;
    }
  };

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    ui.acted = true;
    const edge = parseEdgeUrl(edgeInput.value);
    if (!edge.ok) {
      show(settingsStatus, edge.reason, 'error');
      edgeInput.focus();
      return;
    }
    const core = parseCoreUrl(coreInput.value);
    if (!core.ok) {
      show(settingsStatus, core.reason, 'error');
      coreInput.focus();
      return;
    }
    edgeInput.value = edge.url;
    coreInput.value = core.url ?? '';
    // Firefox grants a permission only while handling the user's action, so the request comes
    // before anything else is awaited.
    const asked = env.requestPermissions({ origins: [originPattern(edge.url)] });
    void finishSave(asked, edge.url, core.url ?? '');
  });

  detection.addEventListener('change', () => {
    ui.acted = true;
    if (detection.checked) {
      const asked = env.requestPermissions(DETECTION_PERMISSIONS);
      void asked
        .catch(() => false)
        .then((granted) => {
          detection.checked = granted;
          const on = env.detectionNeedsRestart ? DETECTION_ON_AFTER_RESTART : DETECTION_ON;
          show(detectionStatus, granted ? on : 'Not turned on: the permission was not granted.', granted ? 'ok' : 'error');
        });
      return;
    }
    void (async () => {
      await env.removePermissions(DETECTION_PERMISSIONS).catch(() => false);
      const s = await send({ type: 'getState' });
      detection.checked = s.ok && s.value.detection;
      if (s.ok && s.value.edgeUrl !== null && !s.value.edgeAccess) {
        show(detectionStatus, 'Off. Access to the edge went with it: press "Save and test" to grant it again.', 'error');
      } else {
        show(detectionStatus, detection.checked ? 'Could not turn it off.' : 'Off.', detection.checked ? 'error' : 'ok');
      }
    })();
  });

  void (async () => {
    const s = await send({ type: 'getState' });
    if (!s.ok) {
      show(settingsStatus, describeError(s.error), 'error');
      return;
    }
    savedEdge ??= s.value.edgeUrl;
    if (ui.acted) {
      return;
    }
    edgeInput.value = s.value.edgeUrl ?? '';
    coreInput.value = s.value.coreUrl ?? '';
    detection.checked = s.value.detection;
    if (s.value.coreUrl !== null) {
      listBase.value = new URL(s.value.coreUrl).origin;
    }
    refreshList();
    if (s.value.edgeUrl === null) {
      show(settingsStatus, 'Enter the edge API URL to set up the extension.');
    } else if (!s.value.edgeAccess) {
      show(settingsStatus, 'The extension has no access to the edge: press "Save and test" to grant it.', 'error');
    }
  })();
}
