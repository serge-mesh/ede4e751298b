// Deadlines for the browser tests, scaled for slower machines: `PICKET_BROWSER_TIME_SCALE`
// (default 2 under CI, whose runner is several times slower than a workstation, else 1). Each
// wait is for a definite condition, so a longer deadline only gives a slow machine time; it
// can't turn a failure into a pass.

const raw = Number(process.env.PICKET_BROWSER_TIME_SCALE ?? (process.env.CI === undefined ? '1' : '2'));

export const TIME_SCALE = Number.isFinite(raw) && raw >= 1 ? raw : 1;

/** `ms` scaled. */
export const scaled = (ms: number): number => Math.round(ms * TIME_SCALE);

/** The default wait for a condition in a page, a tab's URL, or the harness's own steps. */
export const WAIT_MS = scaled(15_000);
