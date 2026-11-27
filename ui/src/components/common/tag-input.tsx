import * as React from "react";
import { XIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { useDraft } from "./drafts";

/**
 * A list of strings edited as chips: Enter, comma, paste or leaving the input adds; Backspace on
 * empty removes the last. Values are shown as text (escaped by React). Text typed but not added
 * yet is a draft (components/common/drafts.tsx): Escape on a sheet would drop it.
 */
export function TagInput({
  value,
  onChange,
  placeholder,
  disabled,
  id,
  suggestions,
  invalid,
  "aria-describedby": describedBy,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
  id?: string;
  suggestions?: string[];
  invalid?: boolean;
  "aria-describedby"?: string;
}) {
  const [draft, setDraft] = React.useState("");
  useDraft(draft.trim() !== "");
  const listId = React.useId();
  const add = (raw: string) => {
    const items = raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (items.length === 0) return;
    const next = [...value];
    for (const it of items) if (!next.includes(it)) next.push(it);
    onChange(next);
    setDraft("");
  };
  return (
    <div
      className={cn(
        "flex min-h-9 w-full flex-wrap items-center gap-1 rounded-md border border-input bg-transparent px-2 py-1 text-sm shadow-xs focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50 dark:bg-input/30",
        invalid && "border-destructive",
        disabled && "opacity-50",
      )}
    >
      {value.map((v, i) => (
        <span key={`${v}-${i}`} className="inline-flex max-w-full items-center gap-1 rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">
          <span className="truncate">{v}</span>
          {!disabled && (
            <button
              type="button"
              className="text-muted-foreground hover:text-foreground"
              aria-label={`Remove ${v}`}
              onClick={() => onChange(value.filter((_, j) => j !== i))}
            >
              <XIcon className="size-3" />
            </button>
          )}
        </span>
      ))}
      <input
        id={id}
        className="min-w-24 flex-1 bg-transparent py-0.5 outline-none placeholder:text-muted-foreground"
        value={draft}
        disabled={disabled}
        placeholder={value.length === 0 ? placeholder : undefined}
        list={suggestions?.length ? listId : undefined}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        onChange={(e) => {
          const v = e.target.value;
          if (v.includes(",")) add(v);
          else setDraft(v);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            add(draft);
          } else if (e.key === "Backspace" && draft === "" && value.length > 0) {
            onChange(value.slice(0, -1));
          }
        }}
        onBlur={() => add(draft)}
        onPaste={(e) => {
          const text = e.clipboardData.getData("text");
          if (/[\n,]/.test(text)) {
            e.preventDefault();
            add(text);
          }
        }}
      />
      {suggestions?.length ? (
        <datalist id={listId}>
          {suggestions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      ) : null}
    </div>
  );
}
