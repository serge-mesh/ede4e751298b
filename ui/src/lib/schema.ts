// JSON Schema helpers for the generic form (core.md §12): module `Config` schemas (schemars,
// draft 2020-12, `$defs`) and the OpenAPI document's components (`#/components/schemas/…`).

export type JSONSchema = boolean | SchemaObject;

export interface SchemaObject {
  $ref?: string;
  type?: string | string[];
  title?: string;
  description?: string;
  default?: unknown;
  examples?: unknown[];
  enum?: unknown[];
  const?: unknown;
  properties?: Record<string, JSONSchema>;
  required?: string[];
  additionalProperties?: JSONSchema;
  items?: JSONSchema;
  oneOf?: JSONSchema[];
  anyOf?: JSONSchema[];
  allOf?: JSONSchema[];
  format?: string;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
  readOnly?: boolean;
  writeOnly?: boolean;
  nullable?: boolean;
  $defs?: Record<string, JSONSchema>;
  definitions?: Record<string, JSONSchema>;
  "x-picket-warning"?: PicketWarning;
  [key: string]: unknown;
}

/** `"x-picket-warning": {"when": [<values>], "text": "…"}` (providers.md §1). */
export interface PicketWarning {
  when?: unknown[];
  text?: string;
}

/** The document `$ref`s resolve against. */
export type SchemaRoot = Record<string, unknown>;

export interface EnumOption {
  value: unknown;
  label: string;
  description?: string;
}

export type FieldKind = "string" | "number" | "integer" | "boolean" | "enum" | "object" | "map" | "array" | "union" | "any";

export interface Classified {
  kind: FieldKind;
  /** The schema without its null branch, `$ref`s resolved. */
  schema: SchemaObject;
  nullable: boolean;
  options?: EnumOption[];
  /** Union variants (resolved), and the tag property when every variant carries a `const` one. */
  variants?: SchemaObject[];
  tag?: string;
  /** The component or `$defs` name the field came from, when it was a `$ref`. */
  refName?: string;
}

const MAX_DEPTH = 32;

function isObj(s: unknown): s is SchemaObject {
  return !!s && typeof s === "object" && !Array.isArray(s);
}

/** Resolves a local JSON pointer `$ref` (`#/$defs/X`, `#/components/schemas/X`). */
export function resolveRef(ref: string, root: SchemaRoot): JSONSchema | undefined {
  if (!ref.startsWith("#")) return undefined;
  const parts = ref
    .slice(1)
    .split("/")
    .filter(Boolean)
    .map((p) => decodeURIComponent(p.replace(/~1/g, "/").replace(/~0/g, "~")));
  let cur: unknown = root;
  for (const p of parts) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur as JSONSchema | undefined;
}

export function refName(ref: string | undefined): string | undefined {
  return ref ? ref.split("/").pop() : undefined;
}

/**
 * Resolves `$ref` (keeping sibling keywords such as `description`, `default` and
 * `x-picket-warning`, which override the target's) and single-element `allOf`.
 */
export function deref(schema: JSONSchema | undefined, root: SchemaRoot, depth = 0): SchemaObject {
  if (schema === true || schema === undefined) return {};
  if (schema === false) return { not: {} };
  if (depth > MAX_DEPTH) return {};
  let s: SchemaObject = schema;
  if (s.$ref) {
    const target = resolveRef(s.$ref, root);
    const { $ref, ...siblings } = s;
    const resolved = deref(target, root, depth + 1);
    s = { ...resolved, ...siblings, __ref: $ref };
  }
  if (s.allOf && s.allOf.length === 1) {
    const { allOf, ...rest } = s;
    s = { ...deref(allOf[0], root, depth + 1), ...rest };
  }
  return s;
}

function isNullSchema(s: JSONSchema, root: SchemaRoot): boolean {
  const d = deref(s, root);
  return d.type === "null" || (Array.isArray(d.type) && d.type.length === 1 && d.type[0] === "null") || d.const === null;
}

function shortText(s: string | undefined): string | undefined {
  if (!s) return undefined;
  const first = s.split(/\n|(?<=[.:;])\s/)[0].trim();
  return first.length > 64 ? `${first.slice(0, 61)}…` : first;
}

/** A label for a union variant. */
export function variantLabel(v: SchemaObject, i: number): string {
  if (v.title && v.title !== "Config") return v.title;
  if (v.const !== undefined) return String(v.const);
  const ref = refName(v.__ref as string | undefined);
  if (ref) return ref.replace(/([a-z])([A-Z])/g, "$1 $2");
  return shortText(v.description) ?? `Option ${i + 1}`;
}

function enumOptionsOf(variants: SchemaObject[], root: SchemaRoot): EnumOption[] | null {
  const out: EnumOption[] = [];
  for (const v0 of variants) {
    const v = deref(v0, root);
    if (v.const !== undefined) {
      out.push({ value: v.const, label: String(v.const), description: v.description });
    } else if (Array.isArray(v.enum)) {
      for (const e of v.enum) out.push({ value: e, label: String(e), description: undefined });
    } else if (v.oneOf || v.anyOf) {
      const nested = enumOptionsOf((v.oneOf ?? v.anyOf) as SchemaObject[], root);
      if (!nested) return null;
      out.push(...nested);
    } else {
      return null;
    }
  }
  return out;
}

function findTag(variants: SchemaObject[]): string | undefined {
  if (variants.length === 0 || !variants.every((v) => v.properties)) return undefined;
  const first = variants[0].properties ?? {};
  for (const key of Object.keys(first)) {
    const all = variants.every((v) => {
      const p = v.properties?.[key];
      return isObj(p) && (p.const !== undefined || (Array.isArray(p.enum) && p.enum.length === 1));
    });
    if (all) return key;
  }
  return undefined;
}

export function tagValue(v: SchemaObject, tag: string): unknown {
  const p = v.properties?.[tag];
  if (!isObj(p)) return undefined;
  return p.const !== undefined ? p.const : p.enum?.[0];
}

/** Normalises a schema into the kind of control that edits it. */
export function classify(schema0: JSONSchema | undefined, root: SchemaRoot): Classified {
  let s = deref(schema0, root);
  const ref = refName(s.__ref as string | undefined);
  let nullable = s.nullable === true;

  // `type: [T, "null"]`
  if (Array.isArray(s.type)) {
    const types = s.type.filter((t) => t !== "null");
    if (types.length < s.type.length) nullable = true;
    s = { ...s, type: types.length === 1 ? types[0] : types };
  }
  // `anyOf/oneOf: [X, {type: null}]`
  for (const key of ["anyOf", "oneOf"] as const) {
    const list = s[key];
    if (Array.isArray(list) && list.some((x) => isNullSchema(x, root))) {
      nullable = true;
      const rest = list.filter((x) => !isNullSchema(x, root));
      const { [key]: _omit, ...others } = s;
      if (rest.length === 1) {
        const inner = classify(rest[0], root);
        // Keep the outer description/default/warning over the inner ones.
        const merged: SchemaObject = { ...inner.schema, ...others };
        return { ...inner, schema: merged, nullable: true, refName: inner.refName ?? ref };
      }
      s = { ...others, [key]: rest };
    }
  }
  if (s.enum && Array.isArray(s.enum)) {
    const values = s.enum.filter((v) => v !== null);
    if (values.length < s.enum.length) nullable = true;
    return {
      kind: "enum",
      schema: s,
      nullable,
      refName: ref,
      options: values.map((v) => ({ value: v, label: String(v) })),
    };
  }
  if (s.const !== undefined) {
    return { kind: "enum", schema: s, nullable, refName: ref, options: [{ value: s.const, label: String(s.const), description: s.description }] };
  }
  const combo = (s.oneOf ?? s.anyOf) as JSONSchema[] | undefined;
  if (Array.isArray(combo) && combo.length > 0) {
    const variants = combo.map((v) => deref(v, root));
    const options = enumOptionsOf(variants, root);
    if (options) return { kind: "enum", schema: s, nullable, options, refName: ref };
    return { kind: "union", schema: s, nullable, variants, tag: findTag(variants), refName: ref };
  }
  const type = Array.isArray(s.type) ? s.type[0] : s.type;
  switch (type) {
    case "string":
      return { kind: "string", schema: s, nullable, refName: ref };
    case "integer":
      return { kind: "integer", schema: s, nullable, refName: ref };
    case "number":
      return { kind: "number", schema: s, nullable, refName: ref };
    case "boolean":
      return { kind: "boolean", schema: s, nullable, refName: ref };
    case "array":
      return { kind: "array", schema: s, nullable, refName: ref };
    case "object":
      if (s.properties && Object.keys(s.properties).length > 0) return { kind: "object", schema: s, nullable, refName: ref };
      if (isObj(s.additionalProperties) || s.additionalProperties === true) return { kind: "map", schema: s, nullable, refName: ref };
      return { kind: "any", schema: s, nullable, refName: ref };
    default:
      if (s.properties) return { kind: "object", schema: s, nullable, refName: ref };
      return { kind: "any", schema: s, nullable, refName: ref };
  }
}

export function clone<T>(v: T): T {
  return v === undefined ? v : (JSON.parse(JSON.stringify(v)) as T);
}

/** The value a new instance of the schema starts with: defaults, filled in recursively. */
export function defaultValue(schema: JSONSchema | undefined, root: SchemaRoot, depth = 0, required = true): unknown {
  if (depth > MAX_DEPTH) return undefined;
  const c = classify(schema, root);
  const s = c.schema;
  if (s.default !== undefined) return clone(s.default);
  if (c.nullable) return null;
  switch (c.kind) {
    case "enum":
      return required ? c.options?.[0]?.value : undefined;
    case "boolean":
      return false;
    case "string":
      return required ? "" : undefined;
    case "number":
    case "integer":
      return undefined;
    case "array":
      return [];
    case "map":
      return {};
    case "object": {
      const out: Record<string, unknown> = {};
      const req = new Set(s.required ?? []);
      for (const [k, p] of Object.entries(s.properties ?? {})) {
        const ps = deref(p, root);
        if (isReadOnly(ps)) continue;
        const v = defaultValue(p, root, depth + 1, req.has(k));
        if (v !== undefined && (req.has(k) || ps.default !== undefined || classify(p, root).nullable)) out[k] = v;
      }
      return out;
    }
    case "union": {
      const v = c.variants?.[0];
      if (!v) return undefined;
      return defaultValue(v, root, depth + 1);
    }
    default:
      return undefined;
  }
}

/** Fields core sets and the UI only shows (`readOnly`, or "(read-only…" in the description). */
export function isReadOnly(s: SchemaObject): boolean {
  return s.readOnly === true || /\(read-only[);]/i.test(s.description ?? "");
}

/** The x-picket-warning text that applies to a value, if any. */
export function activeWarning(s: SchemaObject, value: unknown): string | null {
  const w = s["x-picket-warning"];
  if (!w || typeof w !== "object" || !Array.isArray(w.when) || typeof w.text !== "string") return null;
  return w.when.some((x) => x === value) ? w.text : null;
}

/** Every x-picket-warning that applies anywhere in a value (for marking providers in lists). */
export function collectWarnings(schema: JSONSchema | undefined, value: unknown, root: SchemaRoot, depth = 0): string[] {
  if (depth > MAX_DEPTH) return [];
  const c = classify(schema, root);
  const out: string[] = [];
  const w = activeWarning(c.schema, value);
  if (w) out.push(w);
  if (c.kind === "object" && value && typeof value === "object") {
    for (const [k, p] of Object.entries(c.schema.properties ?? {})) {
      out.push(...collectWarnings(p, (value as Record<string, unknown>)[k], root, depth + 1));
    }
  } else if (c.kind === "array" && Array.isArray(value)) {
    for (const item of value) out.push(...collectWarnings(c.schema.items, item, root, depth + 1));
  } else if (c.kind === "union" && value && typeof value === "object" && c.variants) {
    const v = matchVariant(c, value);
    if (v >= 0) out.push(...collectWarnings(c.variants[v], value, root, depth + 1));
  }
  return [...new Set(out)];
}

/** The index of the union variant a value belongs to (−1 when none). */
export function matchVariant(c: Classified, value: unknown): number {
  const variants = c.variants ?? [];
  if (c.tag && value && typeof value === "object") {
    const t = (value as Record<string, unknown>)[c.tag];
    return variants.findIndex((v) => tagValue(v, c.tag!) === t);
  }
  for (let i = 0; i < variants.length; i++) {
    const v = variants[i];
    if (v.const !== undefined && v.const === value) return i;
    if (Array.isArray(v.enum) && v.enum.includes(value)) return i;
    const nested = (v.oneOf ?? v.anyOf) as SchemaObject[] | undefined;
    if (nested?.some((n) => isObj(n) && (n.const === value || (Array.isArray(n.enum) && n.enum.includes(value))))) return i;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value as object);
    let best = -1;
    let bestScore = -1;
    variants.forEach((v, i) => {
      if (!v.properties) return;
      const req = v.required ?? [];
      if (!req.every((r) => keys.includes(r))) return;
      const score = keys.filter((k) => k in (v.properties ?? {})).length;
      if (score > bestScore) {
        best = i;
        bestScore = score;
      }
    });
    return best;
  }
  if (typeof value === "string") return variants.findIndex((v) => v.type === "string");
  return -1;
}

export type FieldErrors = Record<string, string>;

export function joinPath(base: string, key: string | number): string {
  return base ? `${base}.${key}` : String(key);
}

/** Client-side checks before a save; core validates again and its issues map by field path. */
export function validate(schema: JSONSchema | undefined, value: unknown, root: SchemaRoot, path = "", depth = 0): FieldErrors {
  const errs: FieldErrors = {};
  if (depth > MAX_DEPTH) return errs;
  const c = classify(schema, root);
  const s = c.schema;
  if (value === null || value === undefined) return errs;
  switch (c.kind) {
    case "string": {
      if (typeof value !== "string") break;
      if (s.minLength !== undefined && value.length < s.minLength) errs[path] = `At least ${s.minLength} characters.`;
      else if (s.maxLength !== undefined && value.length > s.maxLength) errs[path] = `At most ${s.maxLength} characters.`;
      else if (s.pattern && value !== "") {
        try {
          if (!new RegExp(s.pattern, "u").test(value)) errs[path] = `Doesn't match ${s.pattern}.`;
        } catch {
          // A pattern JS can't compile is left to core.
        }
      }
      break;
    }
    case "number":
    case "integer": {
      if (typeof value !== "number" || Number.isNaN(value)) {
        errs[path] = "Enter a number.";
        break;
      }
      if (c.kind === "integer" && !Number.isInteger(value)) errs[path] = "Enter a whole number.";
      else if (s.minimum !== undefined && value < s.minimum) errs[path] = `At least ${s.minimum}.`;
      else if (s.maximum !== undefined && value > s.maximum) errs[path] = `At most ${s.maximum}.`;
      break;
    }
    case "array": {
      if (!Array.isArray(value)) break;
      if (s.minItems !== undefined && value.length < s.minItems) errs[path] = `At least ${s.minItems} items.`;
      if (s.maxItems !== undefined && value.length > s.maxItems) errs[path] = `At most ${s.maxItems} items.`;
      value.forEach((item, i) => Object.assign(errs, validate(s.items, item, root, joinPath(path, i), depth + 1)));
      break;
    }
    case "object": {
      if (typeof value !== "object" || Array.isArray(value)) break;
      const v = value as Record<string, unknown>;
      for (const r of s.required ?? []) {
        const pv = v[r];
        const ps = deref(s.properties?.[r], root);
        if ((pv === undefined || pv === "" || pv === null) && ps.default === undefined && !classify(ps, root).nullable) {
          errs[joinPath(path, r)] = "Required.";
        }
      }
      for (const [k, p] of Object.entries(s.properties ?? {})) {
        Object.assign(errs, validate(p, v[k], root, joinPath(path, k), depth + 1));
      }
      break;
    }
    case "map": {
      if (typeof value !== "object" || Array.isArray(value)) break;
      for (const [k, item] of Object.entries(value as Record<string, unknown>)) {
        Object.assign(errs, validate(s.additionalProperties, item, root, joinPath(path, k), depth + 1));
      }
      break;
    }
    case "union": {
      const i = matchVariant(c, value);
      if (i >= 0 && c.variants) Object.assign(errs, validate(c.variants[i], value, root, path, depth + 1));
      break;
    }
    default:
      break;
  }
  return errs;
}
