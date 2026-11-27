// The page itself, behind one object so tests can watch what the UI asks of it.
export const page = {
  /** Loads the page again (the UI core serves now). */
  reload: () => window.location.reload(),
};
