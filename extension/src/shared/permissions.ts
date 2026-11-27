// The extension's optional permissions (browser-extension.md §1): the edge's origin, requested at
// setup, and blocked sub-resource detection, off until turned on in the options.

/** Blocked sub-resource detection: `webRequest` + `<all_urls>`. */
export const DETECTION_PERMISSIONS = { permissions: ['webRequest'], origins: ['<all_urls>'] };

/**
 * `storage.session` key set when Brave grants detection: its webRequest events start only with the
 * browser's next start (options.ts), which clears `storage.session`.
 */
export const DETECTION_RESTART_KEY = 'detectionAfterRestart';

/** What the options page (and, until the restart, the popup) says once detection is granted. */
export const DETECTION_ON = 'On.';
export const DETECTION_ON_AFTER_RESTART = 'On from the next start: restart Brave, which reports requests to the extension only after a restart.';
