// The extension's optional permissions (browser-extension.md §1): the edge's origin, requested at
// setup, and blocked sub-resource detection, off until turned on in the options.

/** Blocked sub-resource detection: `webRequest` + `<all_urls>`. */
export const DETECTION_PERMISSIONS = { permissions: ['webRequest'], origins: ['<all_urls>'] };

/**
 * `storage.session` key set when Brave grants detection: some Brave builds pass webRequest events
 * only from the browser's next start, which clears `storage.session`; the first event clears it
 * too, as the restart then isn't needed (background/index.ts).
 */
export const DETECTION_RESTART_KEY = 'detectionAfterRestart';

/** What the options page (and the popup, while nothing is listed yet) says once detection is granted. */
export const DETECTION_ON = 'On.';
export const DETECTION_ON_AFTER_RESTART =
  'On. If Brave lists no blocked requests, restart it: some versions report requests to the extension only after a restart.';
