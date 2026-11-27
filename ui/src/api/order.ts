// The page's order of `job` reports and status reads (api.md §7 JobEvent). A report can be missed
// (a reconnect, `lagged`, an event's `dropped`), so a view that holds one checks it against the
// job's status, but only against a read sent after the report arrived: a read sent before it says
// nothing about the job it reports. Times can't tell (a read sent before a report can be answered
// after it), so each report and each status read takes the next number here when it arrives or
// is sent.

let last = 0;

/** The next point in the page's order of reports and reads: later than every earlier one. */
export function nextOrder(): number {
  return ++last;
}

const sent = new WeakMap<object, number>();

/**
 * A status query's function that remembers when each read was sent, with the answer it gave. The
 * query must set `structuralSharing: false`, so its data is that answer itself (never an equal
 * earlier one) and `readOrder(data)` says when the data shown was read.
 */
export function ordered<T extends object>(fn: (signal: AbortSignal) => Promise<T>): (ctx: { signal: AbortSignal }) => Promise<T> {
  return async ({ signal }) => {
    const at = nextOrder();
    const v = await fn(signal);
    sent.set(v, at);
    return v;
  };
}

/** When the read that answered `data` was sent (0: not an `ordered` read). */
export function readOrder(data: object | null | undefined): number {
  return data ? (sent.get(data) ?? 0) : 0;
}
