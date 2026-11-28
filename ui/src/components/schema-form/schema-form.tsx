// The one generic form component (core.md §12): feed and lookup provider `Config` forms, the
// lookup-provider settings form, module preset parameters and the entity forms are rendered
// from JSON Schema, so a new module needs no UI code. Field warnings: `x-picket-warning`
// (providers.md §1). Descriptions become tooltips.
import * as React from "react";
import { AlertTriangleIcon, ArrowDownIcon, ArrowUpIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { InfoTip } from "@/components/common/info-tip";
import { RichText } from "@/components/common/text";
import { TagInput } from "@/components/common/tag-input";
import { useDraft } from "@/components/common/drafts";
import { humanize } from "@/lib/format";
import { displayValue } from "@/lib/text";
import { deepEqual } from "@/lib/merge";
import { cn } from "@/lib/utils";
import {
  activeWarning,
  classify,
  defaultValue,
  deref,
  isReadOnly,
  joinPath,
  matchVariant,
  tagValue,
  variantLabel,
  type Classified,
  type FieldErrors,
  type JSONSchema,
  type SchemaObject,
  type SchemaRoot,
} from "@/lib/schema";

export interface FieldRenderProps {
  path: string;
  name: string;
  label: string;
  id: string;
  c: Classified;
  value: unknown;
  onChange: (v: unknown) => void;
  required: boolean;
  error?: string;
  disabled: boolean;
  /** The whole form's value, for a control that depends on another field. */
  form: unknown;
  /** The control the form would render without the override. */
  renderDefault: () => React.ReactNode;
}

/**
 * Renders a field in place of the form's control. The form's label points at the control with
 * the field's `id`; an override that renders a group of controls instead sets `block`, so the
 * label names the group (see `blockOverride`).
 */
export type FieldOverride = ((p: FieldRenderProps) => React.ReactNode) & { block?: boolean };

/** An override that renders a group of controls (labelled by the field's name, not `for` one control). */
export const blockOverride = (render: (p: FieldRenderProps) => React.ReactNode): FieldOverride => Object.assign(render, { block: true });

interface Ctx {
  root: SchemaRoot;
  errors: FieldErrors;
  overrides: Record<string, FieldOverride>;
  hidden: Set<string>;
  readOnly: Set<string>;
  labels: Record<string, string>;
  placeholders: Record<string, string>;
  disabled: boolean;
  mode: "create" | "edit";
  idPrefix: string;
  form: unknown;
}

const CtxContext = React.createContext<Ctx | null>(null);

export interface SchemaFormProps {
  schema: JSONSchema;
  root?: SchemaRoot;
  value: unknown;
  onChange: (v: unknown) => void;
  errors?: FieldErrors;
  overrides?: Record<string, FieldOverride>;
  /** Field paths not shown. */
  hidden?: string[];
  /** Field paths shown but not editable. */
  readOnly?: string[];
  /** Labels by path, replacing the humanised property name. */
  labels?: Record<string, string>;
  /** Placeholders of text fields by path (e.g. the id a create form takes from the name). */
  placeholders?: Record<string, string>;
  /** Top-level fields first, in this order; the rest follow. */
  order?: string[];
  disabled?: boolean;
  /** `create` hides read-only fields core sets; `edit` shows them. */
  mode?: "create" | "edit";
  idPrefix?: string;
  className?: string;
}

export function SchemaForm({
  schema,
  root,
  value,
  onChange,
  errors = {},
  overrides = {},
  hidden = [],
  readOnly = [],
  labels = {},
  placeholders,
  order,
  disabled = false,
  mode = "edit",
  idPrefix,
  className,
}: SchemaFormProps) {
  const autoId = React.useId();
  const rootDoc = React.useMemo(() => root ?? (typeof schema === "object" ? (schema as SchemaRoot) : {}), [root, schema]);
  const ctx = React.useMemo<Ctx>(
    () => ({
      root: rootDoc,
      errors,
      overrides,
      hidden: new Set(hidden),
      readOnly: new Set(readOnly),
      labels,
      placeholders: placeholders ?? {},
      disabled,
      mode,
      idPrefix: idPrefix ?? `sf${autoId.replace(/:/g, "")}`,
      form: value,
    }),
    [rootDoc, errors, overrides, hidden, readOnly, labels, placeholders, disabled, mode, idPrefix, autoId, value],
  );
  const c = classify(schema, rootDoc);
  return (
    <CtxContext.Provider value={ctx}>
      <div className={cn("space-y-4", className)}>
        {c.kind === "object" ? (
          <ObjectFields c={c} value={value} onChange={onChange} path="" order={order} depth={0} />
        ) : (
          <Field schema={schema} name="" path="" value={value} onChange={onChange} required depth={0} />
        )}
      </div>
    </CtxContext.Provider>
  );
}

function useCtx(): Ctx {
  const c = React.useContext(CtxContext);
  if (!c) throw new Error("SchemaForm field outside a SchemaForm");
  return c;
}

const KIND_RANK: Record<string, number> = {
  string: 1,
  enum: 1,
  integer: 1,
  number: 1,
  boolean: 2,
  array: 3,
  map: 4,
  any: 4,
  union: 5,
  object: 6,
};

function orderKeys(props: Record<string, JSONSchema>, root: SchemaRoot, required: Set<string>, first?: string[]): string[] {
  const keys = Object.keys(props);
  const pinned = ["id", "name", ...(first ?? [])];
  const rank = (k: string) => {
    const i = pinned.indexOf(k);
    if (i >= 0) return -100 + i;
    const c = classify(props[k], root);
    return (KIND_RANK[c.kind] ?? 9) * 2 - (required.has(k) ? 1 : 0);
  };
  return keys.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

function ObjectFields({
  c,
  value,
  onChange,
  path,
  order,
  depth,
}: {
  c: Classified;
  value: unknown;
  onChange: (v: unknown) => void;
  path: string;
  order?: string[];
  depth: number;
}) {
  const ctx = useCtx();
  const obj = (value && typeof value === "object" && !Array.isArray(value) ? value : {}) as Record<string, unknown>;
  const props = c.schema.properties ?? {};
  const required = new Set(c.schema.required ?? []);
  const keys = orderKeys(props, ctx.root, required, order);
  return (
    <div className="grid grid-cols-1 gap-x-4 gap-y-4 md:grid-cols-2">
      {keys.map((k) => {
        const p = joinPath(path, k);
        if (ctx.hidden.has(p)) return null;
        const ps = deref(props[k], ctx.root);
        if (isReadOnly(ps) && ctx.mode === "create") return null;
        const kc = classify(props[k], ctx.root);
        const wide = ["object", "array", "map", "union", "any"].includes(kc.kind) || (kc.kind === "string" && isMultiline(k, kc.schema));
        return (
          <div key={k} className={cn("min-w-0", wide && "md:col-span-2")}>
            <Field
              schema={props[k]}
              name={k}
              path={p}
              value={obj[k]}
              required={required.has(k)}
              depth={depth + 1}
              onChange={(v) => {
                const next = { ...obj };
                if (v === undefined) delete next[k];
                else next[k] = v;
                onChange(next);
              }}
            />
          </div>
        );
      })}
    </div>
  );
}

/** An array edited as tags (strings or numbers): one input, so its label points at it. */
function isTagArray(c: Classified, root: SchemaRoot): boolean {
  if (c.kind !== "array") return false;
  const k = classify(c.schema.items, root).kind;
  return k === "string" || k === "number" || k === "integer";
}

function isMultiline(name: string, s: SchemaObject): boolean {
  return (
    name === "trust_store" ||
    /\bPEM\b/.test(s.description ?? "") ||
    (s.maxLength !== undefined && s.maxLength > 512) ||
    s.format === "textarea"
  );
}

/** A field's control id: the form's prefix and the field's path. */
const fieldId = (prefix: string, path: string) => `${prefix}-${path.replace(/[^a-zA-Z0-9_-]/g, "_") || "root"}`;

export function Field({
  schema,
  name,
  path,
  value,
  onChange,
  required,
  depth,
  labelOverride,
}: {
  schema: JSONSchema | undefined;
  name: string;
  path: string;
  value: unknown;
  onChange: (v: unknown) => void;
  required: boolean;
  depth: number;
  labelOverride?: string;
}) {
  const ctx = useCtx();
  const c = classify(schema, ctx.root);
  const id = fieldId(ctx.idPrefix, path);
  const label = labelOverride ?? ctx.labels[path] ?? (c.schema.title && c.schema.title !== "Config" ? c.schema.title : humanize(name));
  const error = ctx.errors[path];
  const ro = ctx.readOnly.has(path) || isReadOnly(c.schema);
  const disabled = ctx.disabled || ro;
  const renderDefault = () =>
    ro ? (
      <ReadOnlyValue value={value} />
    ) : (
      <Control c={c} id={id} name={name} label={label} path={path} value={value} onChange={onChange} required={required} disabled={disabled} depth={depth} error={error} />
    );
  const override = ctx.overrides[path];
  const control = override
    ? override({ path, name, label, id, c, value, onChange, required, error, disabled, form: ctx.form, renderDefault })
    : renderDefault();
  if (!name) return <>{control}</>;
  const warning = activeWarning(c.schema, value);
  const block = ["object", "array", "map", "union", "any"].includes(c.kind) && !isTagArray(c, ctx.root);
  return (
    <FieldShell
      id={id}
      label={label}
      name={name}
      description={c.schema.description}
      required={required && !c.nullable && c.schema.default === undefined}
      error={error}
      warning={warning}
      inline={c.kind === "boolean" && !override}
      block={override ? !!override.block : block}
    >
      {control}
    </FieldShell>
  );
}

export function FieldShell({
  id,
  label,
  name,
  description,
  required,
  error,
  warning,
  inline,
  block,
  children,
}: {
  id: string;
  label: string;
  name?: string;
  description?: string;
  required?: boolean;
  error?: string;
  warning?: string | null;
  inline?: boolean;
  block?: boolean;
  children: React.ReactNode;
}) {
  const head = (
    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
      {block ? (
        <span className="text-sm font-medium" id={`${id}-label`}>
          {label}
        </span>
      ) : (
        <label htmlFor={id} className="text-sm font-medium" id={`${id}-label`}>
          {label}
        </label>
      )}
      {required && (
        <span className="text-destructive" aria-hidden>
          *
        </span>
      )}
      {name && name !== label && <code className="font-mono text-[0.7rem] text-muted-foreground">{name}</code>}
      <InfoTip text={description} label={`About ${label}`} />
    </div>
  );
  return (
    <div className="space-y-1.5" data-field={name}>
      {inline ? (
        <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
          {head}
          {children}
        </div>
      ) : (
        <>
          {head}
          {children}
        </>
      )}
      {warning && (
        <div role="alert" className="flex items-start gap-2 rounded-md border border-warning/60 bg-warning/10 p-2 text-xs">
          <AlertTriangleIcon className="mt-px size-3.5 shrink-0 text-warning" aria-hidden />
          <RichText text={warning} />
        </div>
      )}
      {error && (
        <p id={`${id}-error`} className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

function ReadOnlyValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") return <p className="text-sm text-muted-foreground">—</p>;
  if (typeof value === "object") {
    return <pre className="overflow-auto rounded-md bg-muted p-2 font-mono text-xs">{displayValue(value)}</pre>;
  }
  return <p className="font-mono text-sm break-all">{displayValue(value)}</p>;
}

interface ControlProps {
  c: Classified;
  id: string;
  name: string;
  /** The field's label (empty for a nameless field: an array item, a map value). */
  label: string;
  path: string;
  value: unknown;
  onChange: (v: unknown) => void;
  required: boolean;
  disabled: boolean;
  depth: number;
  error?: string;
}

function Control(p: ControlProps) {
  const { c } = p;
  const complex = ["object", "array", "map", "union", "any"].includes(c.kind);
  if (c.nullable && complex) return <NullableControl {...p} />;
  return <BaseControl {...p} />;
}

/** A nullable complex value: unset (null) until "Set" is ticked. */
function NullableControl(p: ControlProps) {
  const ctx = useCtx();
  const isSet = p.value !== null && p.value !== undefined;
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 text-xs text-muted-foreground">
        <Checkbox
          checked={isSet}
          disabled={p.disabled}
          aria-label={`Set ${p.name || "value"}`}
          onCheckedChange={(on) => {
            if (on) {
              const d = defaultValue({ ...p.c.schema, nullable: false, default: undefined }, ctx.root);
              p.onChange(d ?? (p.c.kind === "array" ? [] : {}));
            } else p.onChange(null);
          }}
        />
        {isSet ? "Set" : "Not set (core's default)"}
      </label>
      {isSet && <BaseControl {...p} />}
    </div>
  );
}

function BaseControl(p: ControlProps) {
  const { c, id, value, onChange, disabled, error } = p;
  const describedBy = error ? `${id}-error` : undefined;
  switch (c.kind) {
    case "boolean":
      return (
        <Switch
          id={id}
          checked={value === true}
          disabled={disabled}
          onCheckedChange={(v) => onChange(v)}
          aria-describedby={describedBy}
        />
      );
    case "enum":
      return <EnumControl {...p} />;
    case "string":
      return <StringControl {...p} />;
    case "number":
    case "integer":
      return <NumberControl {...p} />;
    case "array":
      return <ArrayControl {...p} />;
    case "object":
      return (
        <div className={cn("rounded-md border p-3", p.depth > 2 && "bg-muted/30")} role="group" aria-labelledby={`${id}-label`}>
          <ObjectFields c={c} value={value} onChange={onChange} path={p.path} depth={p.depth} />
        </div>
      );
    case "map":
      return <MapControl {...p} />;
    case "union":
      return <UnionControl {...p} />;
    default:
      return <JsonControl {...p} />;
  }
}

const NULL_KEY = "__unset__";

function EnumControl({ c, id, value, onChange, disabled, error }: ControlProps) {
  const options = c.options ?? [];
  const idx = options.findIndex((o) => o.value === value);
  const current = idx >= 0 ? String(idx) : c.nullable || value === undefined ? NULL_KEY : "";
  const selected = idx >= 0 ? options[idx] : undefined;
  return (
    <div className="space-y-1">
      <Select
        value={current}
        disabled={disabled}
        onValueChange={(v) => onChange(v === NULL_KEY ? (c.nullable ? null : undefined) : options[Number(v)]?.value)}
      >
        <SelectTrigger id={id} className="w-full" aria-invalid={!!error || undefined}>
          <SelectValue placeholder="Choose…" />
        </SelectTrigger>
        <SelectContent>
          {(c.nullable || value === undefined) && (
            <SelectItem value={NULL_KEY}>
              <span className="text-muted-foreground">{c.nullable ? "Not set (default)" : "Choose…"}</span>
            </SelectItem>
          )}
          {options.map((o, i) => (
            <SelectItem key={i} value={String(i)}>
              <span className="font-mono">{o.label}</span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {selected?.description && (
        <p className="text-xs text-muted-foreground">
          <RichText text={selected.description} />
        </p>
      )}
    </div>
  );
}

function StringControl({ c, id, name, path, value, onChange, disabled, error }: ControlProps) {
  const s = c.schema;
  const given = useCtx().placeholders[path];
  const str = typeof value === "string" ? value : value === null || value === undefined ? "" : String(value);
  const set = (v: string) => onChange(v === "" && (c.nullable || value === undefined || value === null) ? (c.nullable ? null : undefined) : v);
  const placeholder =
    given ??
    (c.nullable && s.default === undefined
      ? "Not set"
      : s.examples?.[0] !== undefined
        ? String(s.examples[0])
        : s.__ref === "#/components/schemas/Duration"
          ? "e.g. 30s, 5m, 24h, 7d"
          : undefined);
  if (isMultiline(name, s)) {
    return (
      <Textarea
        id={id}
        value={str}
        disabled={disabled}
        placeholder={placeholder}
        rows={5}
        className="font-mono text-xs"
        aria-invalid={!!error || undefined}
        aria-describedby={error ? `${id}-error` : undefined}
        onChange={(e) => set(e.target.value)}
      />
    );
  }
  return (
    <Input
      id={id}
      value={str}
      disabled={disabled}
      placeholder={placeholder}
      maxLength={s.maxLength}
      aria-invalid={!!error || undefined}
      aria-describedby={error ? `${id}-error` : undefined}
      spellCheck={false}
      autoComplete="off"
      type={/password|secret/i.test(name) && !/\$\{secret/.test(s.description ?? "") ? "password" : "text"}
      onChange={(e) => set(e.target.value)}
    />
  );
}

function NumberControl({ c, id, value, onChange, disabled, error }: ControlProps) {
  const [draft, setDraft] = React.useState<string>(value === null || value === undefined ? "" : String(value));
  const last = React.useRef(value);
  React.useEffect(() => {
    if (value !== last.current) {
      last.current = value;
      setDraft(value === null || value === undefined ? "" : String(value));
    }
  }, [value]);
  const s = c.schema;
  return (
    <Input
      id={id}
      inputMode={c.kind === "integer" ? "numeric" : "decimal"}
      value={draft}
      disabled={disabled}
      // An omitted field gets the schema's default from core, even when null is allowed;
      // only an explicit null is "Not set".
      placeholder={value !== null && s.default != null ? String(s.default) : c.nullable ? "Not set" : undefined}
      aria-invalid={!!error || undefined}
      aria-describedby={error ? `${id}-error` : undefined}
      onChange={(e) => {
        const t = e.target.value;
        setDraft(t);
        let next: unknown;
        if (t.trim() === "") next = c.nullable ? null : undefined;
        else {
          const n = Number(t);
          next = Number.isNaN(n) ? t : n;
        }
        last.current = next;
        onChange(next);
      }}
    />
  );
}

function ArrayControl(p: ControlProps) {
  const ctx = useCtx();
  const { c, id, value, onChange, disabled, error } = p;
  const items = Array.isArray(value) ? value : [];
  const ic = classify(c.schema.items, ctx.root);
  if (ic.kind === "enum" && ic.options) {
    return (
      <div className="flex flex-wrap gap-3 rounded-md border p-2" role="group" aria-labelledby={`${id}-label`}>
        {ic.options.map((o, i) => {
          const checked = items.includes(o.value);
          return (
            <label key={i} className="flex items-center gap-1.5 text-sm">
              <Checkbox
                checked={checked}
                disabled={disabled}
                onCheckedChange={(on) => onChange(on ? [...items, o.value] : items.filter((x) => x !== o.value))}
              />
              <span className="font-mono text-xs">{o.label}</span>
            </label>
          );
        })}
      </div>
    );
  }
  if (ic.kind === "string" || ic.kind === "number" || ic.kind === "integer") {
    return (
      <TagInput
        id={id}
        value={items.map((x) => String(x))}
        disabled={disabled}
        invalid={!!error}
        aria-describedby={error ? `${id}-error` : undefined}
        placeholder="Type and press Enter"
        onChange={(v) => onChange(ic.kind === "string" ? v : v.map((x) => Number(x)).filter((n) => !Number.isNaN(n)))}
      />
    );
  }
  return (
    <ObjectArrayItems
      c={c}
      id={id}
      path={p.path}
      items={items}
      onChange={onChange}
      disabled={disabled}
      depth={p.depth + 1}
      root={ctx.root}
    />
  );
}

export interface ObjectArrayItemsProps {
  /** The array field; `c.schema.items` describes each item. */
  c: Classified;
  id: string;
  path: string;
  items: unknown[];
  onChange: (v: unknown[]) => void;
  disabled: boolean;
  /** The depth each item's fields render at. */
  depth: number;
  root: SchemaRoot;
  emptyText?: string;
  addLabel?: string;
  /** The heading of an item's card; "#n" when not given. */
  heading?: (item: unknown, i: number) => React.ReactNode;
  removeLabel?: (i: number) => string;
}

/**
 * A reorderable list of object items, each in its own card with move and remove buttons.
 * Rows are keyed by index, which matches their field paths, so after a move the focus is put
 * back on the moved row's button by hand: React would otherwise leave it on the row's old place.
 */
export function ObjectArrayItems({
  c,
  id,
  path,
  items,
  onChange,
  disabled,
  depth,
  root,
  emptyText = "None.",
  addLabel = "Add",
  heading = (_item, i) => <span className="tabular-nums">#{i + 1}</span>,
  removeLabel = (i) => `Remove item ${i + 1}`,
}: ObjectArrayItemsProps) {
  const focusAfterMove = React.useRef<string | null>(null);
  React.useEffect(() => {
    const target = focusAfterMove.current;
    if (target === null) return;
    focusAfterMove.current = null;
    document.getElementById(target)?.focus();
  });
  const move = (i: number, d: number) => {
    const next = [...items];
    const [x] = next.splice(i, 1);
    const to = i + d;
    next.splice(to, 0, x);
    // Keep the same button focused on the moved row, or its other move button once it reaches an end.
    const up = d < 0 ? to > 0 : to === next.length - 1;
    focusAfterMove.current = `${id}-${up ? "up" : "down"}-${to}`;
    onChange(next);
  };
  return (
    // The group carries the field's id: a field label pointing here names the list without
    // activating any of its buttons.
    <div id={id} className="space-y-2" role="group" aria-labelledby={`${id}-label`}>
      {items.length === 0 && <p className="text-xs text-muted-foreground">{emptyText}</p>}
      {items.map((item, i) => (
        <div key={i} className="rounded-md border p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="flex min-w-0 items-center gap-1.5 text-xs font-medium text-muted-foreground">{heading(item, i)}</span>
            {!disabled && (
              <div className="flex gap-1">
                <Button id={`${id}-up-${i}`} variant="ghost" size="icon-sm" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)}>
                  <ArrowUpIcon />
                </Button>
                <Button id={`${id}-down-${i}`} variant="ghost" size="icon-sm" aria-label="Move down" disabled={i === items.length - 1} onClick={() => move(i, 1)}>
                  <ArrowDownIcon />
                </Button>
                <Button variant="ghost" size="icon-sm" aria-label={removeLabel(i)} onClick={() => onChange(items.filter((_, j) => j !== i))}>
                  <Trash2Icon />
                </Button>
              </div>
            )}
          </div>
          <Field
            schema={c.schema.items}
            name=""
            path={joinPath(path, i)}
            value={item}
            required
            depth={depth}
            onChange={(v) => onChange(items.map((x, j) => (j === i ? v : x)))}
          />
        </div>
      ))}
      {!disabled && (
        <Button
          aria-labelledby={`${id}-add`}
          variant="outline"
          size="sm"
          onClick={() => onChange([...items, defaultValue(c.schema.items, root) ?? {}])}
          disabled={c.schema.maxItems !== undefined && items.length >= c.schema.maxItems}
        >
          <PlusIcon aria-hidden />
          <span id={`${id}-add`}>{addLabel}</span>
        </Button>
      )}
    </div>
  );
}

function MapControl(p: ControlProps) {
  const ctx = useCtx();
  const { c, id, value, onChange, disabled } = p;
  const obj = (value && typeof value === "object" && !Array.isArray(value) ? value : {}) as Record<string, unknown>;
  const entries = Object.entries(obj);
  const vs: JSONSchema | undefined = c.schema.additionalProperties === true ? {} : c.schema.additionalProperties;
  const [newKey, setNewKey] = React.useState("");
  // A key typed but not added is a draft (components/common/drafts.tsx).
  useDraft(newKey.trim() !== "");
  return (
    <div className="space-y-2 rounded-md border p-3" role="group" aria-labelledby={`${id}-label`}>
      {entries.length === 0 && <p className="text-xs text-muted-foreground">None.</p>}
      {entries.map(([k, v]) => {
        const path = joinPath(p.path, k);
        const vid = fieldId(ctx.idPrefix, path);
        return (
          <div key={k} className="grid grid-cols-[minmax(6rem,12rem)_1fr_auto] items-start gap-2">
            {/* The value's label: its key, named with its field for assistive technology (a value that is a group takes it by id). */}
            <label htmlFor={vid} id={`${vid}-label`} className="truncate pt-2" title={k}>
              <span className="sr-only">{p.label ? `${p.label}: ${displayValue(k)}` : displayValue(k)}</span>
              <code className="font-mono text-xs" aria-hidden>
                {displayValue(k)}
              </code>
            </label>
            <Field schema={vs} name="" path={path} value={v} required depth={p.depth + 1} onChange={(nv) => onChange({ ...obj, [k]: nv })} />
            {!disabled && (
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove ${k}`}
                onClick={() => {
                  const next = { ...obj };
                  delete next[k];
                  onChange(next);
                }}
              >
                <Trash2Icon />
              </Button>
            )}
          </div>
        );
      })}
      {!disabled && (
        <div className="flex gap-2">
          <Input
            value={newKey}
            placeholder="New key"
            aria-label="New key"
            className="max-w-xs"
            onChange={(e) => setNewKey(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") e.preventDefault();
            }}
          />
          <Button
            variant="outline"
            size="sm"
            disabled={!newKey.trim() || newKey.trim() in obj}
            onClick={() => {
              onChange({ ...obj, [newKey.trim()]: defaultValue(vs, ctx.root) ?? "" });
              setNewKey("");
            }}
          >
            <PlusIcon /> Add
          </Button>
        </div>
      )}
    </div>
  );
}

function UnionControl(p: ControlProps) {
  const ctx = useCtx();
  const { c, id, value, onChange, disabled } = p;
  const variants = c.variants ?? [];
  const current = matchVariant(c, value);
  const v = current >= 0 ? variants[current] : undefined;
  const choose = (i: number) => {
    const target = variants[i];
    let next = defaultValue(target, ctx.root);
    if (c.tag) {
      // Keep fields both variants share.
      const base = (next && typeof next === "object" ? next : {}) as Record<string, unknown>;
      const old = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
      for (const k of Object.keys(target.properties ?? {})) {
        if (k !== c.tag && old[k] !== undefined) base[k] = old[k];
      }
      base[c.tag] = tagValue(target, c.tag);
      next = base;
    } else if (target.const !== undefined) {
      next = target.const;
    }
    onChange(next);
  };
  const isScalarVariant = v && (v.const !== undefined || v.enum !== undefined || v.type === "string");
  return (
    <div className="space-y-3 rounded-md border p-3">
      <Select value={current >= 0 ? String(current) : ""} disabled={disabled} onValueChange={(x) => choose(Number(x))}>
        <SelectTrigger id={id} className="w-full sm:w-auto" aria-label={`${p.name || "Value"}: kind`}>
          <SelectValue placeholder="Choose…" />
        </SelectTrigger>
        <SelectContent>
          {variants.map((vv, i) => (
            <SelectItem key={i} value={String(i)}>
              {c.tag ? String(tagValue(vv, c.tag)) : variantLabel(vv, i)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {v?.description && (
        <p className="text-xs text-muted-foreground">
          <RichText text={v.description} />
        </p>
      )}
      {v && !isScalarVariant && (
        <Field
          schema={c.tag ? { ...v, properties: Object.fromEntries(Object.entries(v.properties ?? {}).filter(([k]) => k !== c.tag)) } : v}
          name=""
          path={p.path}
          value={value}
          required
          depth={p.depth + 1}
          onChange={(nv) =>
            onChange(c.tag && nv && typeof nv === "object" ? { ...(nv as object), [c.tag]: tagValue(v, c.tag) } : nv)
          }
        />
      )}
    </div>
  );
}

/**
 * Free-form JSON (a schema without a type): edited as text, applied when it parses. Text that
 * doesn't parse leaves the value as it was and makes the control invalid, so its form isn't
 * submitted (the browser's constraint validation) while the text on screen isn't what would be saved;
 * it is a draft meanwhile (components/common/drafts.tsx). The text follows the value when the value
 * changes, not when it is only copied (a merge keeping the form's changes).
 */
function JsonControl({ id, value, onChange, disabled }: ControlProps) {
  const [text, setText] = React.useState(() => (value === undefined ? "" : JSON.stringify(value, null, 2)));
  const [bad, setBad] = React.useState<string | null>(null);
  useDraft(bad !== null);
  const last = React.useRef(value);
  const area = React.useRef<HTMLTextAreaElement>(null);
  React.useEffect(() => {
    area.current?.setCustomValidity(bad ? `Not valid JSON: ${bad}` : "");
  }, [bad]);
  React.useEffect(() => {
    if ((value === undefined) !== (last.current === undefined) || !deepEqual(value, last.current)) {
      last.current = value;
      setText(value === undefined ? "" : JSON.stringify(value, null, 2));
      setBad(null);
    }
  }, [value]);
  return (
    <div className="space-y-1">
      <Textarea
        ref={area}
        id={id}
        value={text}
        disabled={disabled}
        rows={Math.min(14, Math.max(3, text.split("\n").length))}
        className="font-mono text-xs"
        spellCheck={false}
        aria-invalid={!!bad || undefined}
        onChange={(e) => {
          setText(e.target.value);
          if (e.target.value.trim() === "") {
            setBad(null);
            last.current = undefined;
            onChange(undefined);
            return;
          }
          try {
            const v = JSON.parse(e.target.value) as unknown;
            setBad(null);
            last.current = v;
            onChange(v);
          } catch (err) {
            setBad(err instanceof Error ? err.message : "Not valid JSON");
          }
        }}
      />
      <p className={cn("text-xs", bad ? "text-destructive" : "text-muted-foreground")}>{bad ? `Not valid JSON: ${bad}` : "JSON"}</p>
    </div>
  );
}
