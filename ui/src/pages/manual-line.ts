// Whose save a manual feed's run, file read or status is (feeds.md §1, api.md §7), for its editor.
//
// A version is a hash of the text: it repeats when a text comes back, so it doesn't order saves.
// core's order is the save time, and core says it everywhere: `PUT feeds/{id}/file`, the appends
// and the imports return it as `saved_at`, a run carries it as `updated_at` (its `feed_run` event
// as `saved_at`), and a file read and the feed's status as `saved_at`. One save time, one save: so
// everything is placed by time alone, and the page only needs the newest save it knows of. A
// restore is the one step back: core keeps a restored file's own save time, so the page forgets
// what it knew and takes the file read after it (`restored`). A read sent before the restore says
// what the restore replaced: it is discarded (`era`), and a write sent before it is checked
// against the file read after it (`pageWrite`).
//
// A run, file read or status that arrives while a write of the page is in flight may be of that
// write, whose time the page doesn't know yet: it isn't placed then (`placeable`). A write's
// answer is taken in the same step as the line counts it done (`pageWrite`), so nothing is placed
// in between against a line without it. A write that ends without a save to wait for (it failed,
// or changed nothing) has open editors read the runs again, so another writer's save reported
// meanwhile still shows.
import { timeOrder } from "@/lib/format";

/** A save core holds: its version and save time (both null while the feed has no file). */
export interface Save {
  version: string | null;
  at: string | null;
}

/** A save of the page that changed the file (the editor's or an import's), told to every open editor of the feed. */
export interface SaveNotice {
  version: string;
  at: string | null;
  /** The saved text, when the page has it (an editor's save; an import's file is core's to build). */
  content: string | null;
}

/**
 * What a manual feed's page knows of its saves: the newest one, and the page's writes in flight.
 * Held by the feed's page, so an editor reopened on another tab (even while a save is in flight)
 * still knows it, and dropped with the page.
 */
export interface Line {
  /** The newest save the page knows of; null until the editor opens or the page saves. */
  newest: Save | null;
  /** The page's writes in flight. */
  writes: number;
  listeners: Set<(n: SaveNotice) => void>;
  /**
   * Told when a write of the page ends without a save to wait for (it failed, changed nothing, or
   * its answer couldn't be taken): what core reported while it was in flight wasn't placed, so
   * each open editor reads the runs again.
   */
  rechecks: Set<() => void>;
  /** Changed saves of the page recorded so far (`recordSave`). */
  recorded: number;
  /** Told when a restore replaced core's data (`restored`): each open editor reads the file again (`reread`: a read already out is sent again, as a save's answer told of the restore). */
  restores: Set<(reread: boolean) => void>;
  /** Restores so far (`restored`): a read that lands in a later era than it was sent in is of what a restore replaced. */
  era: number;
}

export { timeOrder };

export function createLine(): Line {
  return { newest: null, writes: 0, listeners: new Set(), rechecks: new Set(), recorded: 0, restores: new Set(), era: 0 };
}

/** True while nothing core reports can be of a write of the page whose answer hasn't arrived. */
export function placeable(l: Line): boolean {
  return l.writes === 0;
}

/**
 * Takes a save core reports (a run, an event, a file read, the status, a write's answer): it
 * becomes the newest when it is later than every save the page knew. Returns whether it did.
 */
export function learn(l: Line, s: Save): boolean {
  if (l.newest && timeOrder(s.at, l.newest.at) <= 0) return false;
  l.newest = { version: s.version, at: s.at };
  return true;
}

/** True when the newest save the page knows of is later than `base` (a text's save). */
export function movedPast(l: Line, base: string | null | undefined): boolean {
  return !!l.newest && timeOrder(l.newest.at, base) > 0;
}

/**
 * One write of the page (a save, an import): `send` makes it; `landed` takes its answer in the
 * same step as the line counts it done (learn it, tell the editors), so no run or file read is
 * placed in between against a line without it. A write that records no save (`recordSave`) starts
 * no wait whose polls would place what came meanwhile: the editors read the runs again then.
 *
 * A write that a restore overtook (sent before it, answered after) may have saved before the
 * restore, which then discarded the save; or after it, and the save stands. Once it is taken, the
 * page does as after the restore again (`restored`): each open editor reads the file, which says
 * which (and, while it waits for the save's run, ends the wait if the save is gone).
 */
export async function pageWrite<R, T>(l: Line, send: () => Promise<R>, landed: (r: R) => T): Promise<T> {
  const era = l.era;
  l.writes++;
  let r: R;
  try {
    r = await send();
  } catch (e) {
    l.writes--;
    recheck(l);
    throw e;
  }
  l.writes--;
  const recorded = l.recorded;
  try {
    return landed(r);
  } finally {
    if (l.era !== era) restored(l, true);
    else if (l.recorded === recorded) recheck(l);
  }
}

function recheck(l: Line): void {
  for (const f of [...l.rechecks]) f();
}

/** A changed save of the page landed: the line takes it and every open editor of the feed hears of it. */
export function recordSave(l: Line, n: SaveNotice): void {
  l.recorded++;
  learn(l, { version: n.version, at: n.at });
  for (const f of [...l.listeners]) f(n);
}

/**
 * A restore replaced core's data (core.md §2): core keeps a restored file's own save time, which
 * can be older than saves the page knew, so the newest save it knew of is forgotten, and a new era
 * begins (reads sent before it are discarded as they land). Each open editor reads the file and
 * takes its save (an editor opened later reads it anyway: closed editors' cached files are
 * dropped, api/events.ts `resync`).
 */
export function restored(l: Line, reread = false): void {
  l.era++;
  l.newest = null;
  for (const f of [...l.restores]) f(reread);
}
