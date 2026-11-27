// A small 5-field cron reader (UTC) for the self-test form (providers.md §5): it shows the next
// run times and flags expressions it can't read. Core (croner) stays the judge on save.

interface Field {
  min: number;
  max: number;
  names?: Record<string, number>;
}

const FIELDS: Field[] = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12, names: { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 } },
  { min: 0, max: 7, names: { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 } },
];

const MACROS: Record<string, string> = {
  "@hourly": "0 * * * *",
  "@daily": "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@weekly": "0 0 * * 0",
  "@monthly": "0 0 1 * *",
  "@yearly": "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
};

function parseValue(s: string, f: Field): number | null {
  const lower = s.toLowerCase();
  if (f.names && lower in f.names) return f.names[lower];
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  return n >= f.min && n <= f.max ? n : null;
}

function parseField(text: string, f: Field): Set<number> | null {
  const out = new Set<number>();
  for (const part of text.split(",")) {
    const [range, stepText] = part.split("/");
    const step = stepText === undefined ? 1 : Number(stepText);
    if (!Number.isInteger(step) || step < 1) return null;
    let lo: number;
    let hi: number;
    if (range === "*" || range === "?") {
      lo = f.min;
      hi = f.max;
    } else if (range.includes("-")) {
      const [a, b] = range.split("-");
      const pa = parseValue(a, f);
      const pb = parseValue(b, f);
      if (pa === null || pb === null || pa > pb) return null;
      lo = pa;
      hi = pb;
    } else {
      const v = parseValue(range, f);
      if (v === null) return null;
      lo = v;
      hi = stepText === undefined ? v : f.max;
    }
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  return out;
}

export interface Cron {
  minute: Set<number>;
  hour: Set<number>;
  dom: Set<number>;
  month: Set<number>;
  dow: Set<number>;
  domAny: boolean;
  dowAny: boolean;
}

export function parseCron(expr: string): Cron | null {
  const text = MACROS[expr.trim().toLowerCase()] ?? expr.trim();
  const parts = text.split(/\s+/);
  if (parts.length !== 5) return null;
  const sets = parts.map((p, i) => parseField(p, FIELDS[i]));
  if (sets.some((s) => s === null)) return null;
  const dow = sets[4]!;
  if (dow.has(7)) {
    dow.delete(7);
    dow.add(0);
  }
  return {
    minute: sets[0]!,
    hour: sets[1]!,
    dom: sets[2]!,
    month: sets[3]!,
    dow,
    domAny: parts[2] === "*" || parts[2] === "?",
    dowAny: parts[4] === "*" || parts[4] === "?",
  };
}

function matchesDay(c: Cron, d: Date): boolean {
  const dom = c.dom.has(d.getUTCDate());
  const dow = c.dow.has(d.getUTCDay());
  // Standard cron: when both day fields are restricted, either matches.
  if (!c.domAny && !c.dowAny) return dom || dow;
  return dom && dow;
}

/** The next `count` run times after `from`, in UTC (bounded search: about two years). */
export function nextRuns(expr: string, count = 3, from = new Date()): Date[] | null {
  const c = parseCron(expr);
  if (!c) return null;
  const out: Date[] = [];
  const t = new Date(Math.floor(from.getTime() / 60000) * 60000 + 60000);
  const limit = from.getTime() + 2 * 366 * 86400_000;
  while (out.length < count && t.getTime() < limit) {
    if (!c.month.has(t.getUTCMonth() + 1) || !matchesDay(c, t)) {
      t.setUTCDate(t.getUTCDate() + 1);
      t.setUTCHours(0, 0, 0, 0);
      continue;
    }
    if (!c.hour.has(t.getUTCHours())) {
      t.setUTCHours(t.getUTCHours() + 1, 0, 0, 0);
      continue;
    }
    if (!c.minute.has(t.getUTCMinutes())) {
      t.setUTCMinutes(t.getUTCMinutes() + 1, 0, 0);
      continue;
    }
    out.push(new Date(t));
    t.setUTCMinutes(t.getUTCMinutes() + 1, 0, 0);
  }
  return out;
}
