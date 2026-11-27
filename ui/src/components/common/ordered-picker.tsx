import * as React from "react";
import { ArrowDownIcon, ArrowUpIcon, GripVerticalIcon, PlusIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { escapeControl } from "@/lib/text";
import { cn } from "@/lib/utils";

export interface PickOption {
  value: string;
  label?: string;
  hint?: string;
  disabled?: boolean;
}

/**
 * Picks ids from a list. Ordered lists (a profile's allow and block bundles, a group's
 * upstreams) reorder by drag, or with the arrow buttons from the keyboard. With the field's `id`
 * (schema-form's FieldShell labels it `${id}-label`), the picker is a group named by its field,
 * and its add control (which takes the id, so the field's label focuses it) by the field and
 * `addLabel`, telling apart pickers that add the same kind of thing.
 */
export function OrderedPicker({
  value,
  onChange,
  options,
  ordered = true,
  disabled,
  id,
  addLabel = "Add…",
  emptyText = "None.",
  renderItem,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  options: PickOption[];
  ordered?: boolean;
  disabled?: boolean;
  id?: string;
  addLabel?: string;
  emptyText?: string;
  renderItem?: (v: string) => React.ReactNode;
}) {
  const [drag, setDrag] = React.useState<number | null>(null);
  const [over, setOver] = React.useState<number | null>(null);
  const byValue = new Map(options.map((o) => [o.value, o]));
  const remaining = options.filter((o) => !value.includes(o.value));
  const move = (from: number, to: number) => {
    if (to < 0 || to >= value.length || from === to) return;
    const next = [...value];
    const [x] = next.splice(from, 1);
    next.splice(to, 0, x);
    onChange(next);
  };
  return (
    <div className="space-y-2" role="group" aria-labelledby={id ? `${id}-label` : undefined}>
      {value.length === 0 ? (
        <p className="text-xs text-muted-foreground">{emptyText}</p>
      ) : (
        <ol className="space-y-1">
          {value.map((v, i) => {
            const opt = byValue.get(v);
            return (
              <li
                key={v}
                draggable={ordered && !disabled}
                onDragStart={(e) => {
                  setDrag(i);
                  e.dataTransfer.effectAllowed = "move";
                  e.dataTransfer.setData("text/plain", String(i));
                }}
                onDragOver={(e) => {
                  if (drag === null) return;
                  e.preventDefault();
                  setOver(i);
                }}
                onDragLeave={() => setOver((o) => (o === i ? null : o))}
                onDrop={(e) => {
                  e.preventDefault();
                  if (drag !== null) move(drag, i);
                  setDrag(null);
                  setOver(null);
                }}
                onDragEnd={() => {
                  setDrag(null);
                  setOver(null);
                }}
                className={cn(
                  "flex items-center gap-2 rounded-md border bg-card px-2 py-1 text-sm",
                  over === i && drag !== i && "border-primary ring-2 ring-primary/30",
                  drag === i && "opacity-50",
                  !opt && "border-dashed",
                )}
              >
                {ordered && <GripVerticalIcon className="size-4 shrink-0 cursor-grab text-muted-foreground" aria-hidden />}
                {ordered && <span className="w-5 text-xs text-muted-foreground tabular-nums">{i + 1}.</span>}
                <span className="min-w-0 flex-1 truncate">
                  {renderItem ? renderItem(v) : <span className="font-mono text-xs">{escapeControl(opt?.label ?? v)}</span>}
                  {!opt && <span className="ml-2 text-xs text-destructive">(not found)</span>}
                  {opt?.hint && <span className="ml-2 text-xs text-muted-foreground">{escapeControl(opt.hint)}</span>}
                </span>
                {ordered && !disabled && (
                  <>
                    <Button variant="ghost" size="icon-sm" aria-label={`Move ${v} up`} disabled={i === 0} onClick={() => move(i, i - 1)}>
                      <ArrowUpIcon />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={`Move ${v} down`} disabled={i === value.length - 1} onClick={() => move(i, i + 1)}>
                      <ArrowDownIcon />
                    </Button>
                  </>
                )}
                {!disabled && (
                  <Button variant="ghost" size="icon-sm" aria-label={`Remove ${v}`} onClick={() => onChange(value.filter((x) => x !== v))}>
                    <XIcon />
                  </Button>
                )}
              </li>
            );
          })}
        </ol>
      )}
      {!disabled && remaining.length > 0 && (
        <Select value="" onValueChange={(v) => v && onChange([...value, v])}>
          <SelectTrigger
            id={id}
            size="sm"
            className="w-full sm:w-72"
            aria-label={id ? undefined : addLabel}
            aria-labelledby={id ? `${id}-label ${id}-add` : undefined}
          >
            <span id={id ? `${id}-add` : undefined} className="flex items-center gap-1.5 text-muted-foreground">
              <PlusIcon className="size-3.5" />
              <SelectValue placeholder={addLabel} />
            </span>
          </SelectTrigger>
          <SelectContent>
            {remaining.map((o) => (
              <SelectItem key={o.value} value={o.value} disabled={o.disabled}>
                {escapeControl(o.label ?? o.value)}
                {o.hint ? ` · ${escapeControl(o.hint)}` : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  );
}

/** A single id from a list (an upstream group, a profile), with an optional "none". */
export function IdSelect({
  value,
  onChange,
  options,
  nullable,
  noneLabel = "None",
  id,
  disabled,
}: {
  value: string | null | undefined;
  onChange: (v: string | null) => void;
  options: PickOption[];
  nullable?: boolean;
  noneLabel?: string;
  id?: string;
  disabled?: boolean;
}) {
  const NONE = "__none__";
  const known = options.some((o) => o.value === value);
  return (
    <Select value={value ?? NONE} onValueChange={(v) => onChange(v === NONE ? null : v)} disabled={disabled}>
      <SelectTrigger id={id} className="w-full">
        <SelectValue placeholder="Choose…" />
      </SelectTrigger>
      <SelectContent>
        {nullable && <SelectItem value={NONE}>{noneLabel}</SelectItem>}
        {value && !known && <SelectItem value={value}>{escapeControl(value)} (not found)</SelectItem>}
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value} disabled={o.disabled}>
            {escapeControl(o.label ?? o.value)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
