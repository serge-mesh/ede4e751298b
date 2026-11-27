// The OpenAPI document core serves (api.md §7), bundled at build time: entity forms are
// rendered from its component schemas, and tooltips use its field descriptions (core.md §12).
import doc from "@/api/openapi.json";
import { deref, type SchemaObject, type SchemaRoot } from "./schema";

export const openapiRoot: SchemaRoot = doc as unknown as SchemaRoot;

export function componentSchema(name: string): SchemaObject {
  return deref({ $ref: `#/components/schemas/${name}` }, openapiRoot);
}

/** A field's description in a component (`RulePolicy`, `redirects`), for tooltips. */
export function fieldDescription(component: string, field: string): string | undefined {
  const s = componentSchema(component);
  const p = s.properties?.[field];
  if (!p || typeof p !== "object") return undefined;
  return (p as SchemaObject).description ?? deref(p, openapiRoot).description;
}

/** The values a GET's query parameter takes, as core's document lists them (an enum), or [] when it lists none. */
export function queryEnum(path: string, param: string): string[] {
  const op = (doc as unknown as { paths: Record<string, { get?: { parameters?: { in: string; name: string; schema?: { enum?: unknown[] } }[] } }> }).paths[path]?.get;
  const p = op?.parameters?.find((x) => x.in === "query" && x.name === param);
  return (p?.schema?.enum ?? []).filter((v): v is string => typeof v === "string");
}

/** A numeric query parameter's bounds as core's document gives them (`minimum`, `maximum`). */
export interface ParamRange {
  min: number;
  max: number;
  /** Whole numbers only (`integer`). */
  integer: boolean;
}

/**
 * The bounds of a GET's numeric query parameter (core 07acc1c: every `limit`, the backtest's
 * `days` and `k`; a value outside is refused with 400, no longer clamped). Throws when the
 * document gives none, so a renamed parameter fails the build's tests instead of going unchecked.
 */
export function queryRange(path: string, param: string): ParamRange {
  const op = (doc as unknown as { paths: Record<string, { get?: { parameters?: { in: string; name: string; schema?: { type?: string; minimum?: number; maximum?: number } }[] } }> }).paths[path]?.get;
  const s = op?.parameters?.find((x) => x.in === "query" && x.name === param)?.schema;
  if (typeof s?.minimum !== "number" || typeof s.maximum !== "number") throw new Error(`core's document gives no bounds for ${path} ${param}`);
  return { min: s.minimum, max: s.maximum, integer: s.type === "integer" };
}

/** A range in words, as core's refusals say it: "1 to 60". */
export const rangeText = (r: Pick<ParamRange, "min" | "max">) => `${r.min} to ${r.max}`;

/**
 * What's wrong with a value typed for a parameter of range `r` ("" left out is fine when
 * `optional`), in words with the range, or null when core takes it. `unreadable`: the browser
 * can't read the field as a number (its `validity.badInput`: "1e", "-"), so its value is "" while
 * the field shows text.
 */
export function rangeProblem(text: string, r: ParamRange, optional = false, unreadable = false): string | null {
  const t = text.trim();
  const wrong = `${r.integer ? "A whole number" : "A number"} from ${rangeText(r)}.`;
  if (unreadable) return wrong;
  if (t === "") return optional ? null : `Enter ${r.integer ? "a whole number" : "a number"} from ${rangeText(r)}.`;
  const n = Number(t);
  if (!Number.isFinite(n) || (r.integer && !Number.isInteger(n)) || n < r.min || n > r.max) return wrong;
  return null;
}
