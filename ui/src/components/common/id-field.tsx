import * as React from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { idFromName, isProfileId, isSlug } from "@/lib/ids";

export interface DerivedId {
  /** The id sent. */
  id: string;
  /** What the input shows: the id, or "" after the admin cleared it (the id then shows as its placeholder). */
  input: string;
  /** The id the name gives (or the fallback). */
  derived: string;
  valid: boolean;
  /** The admin typed it rather than taking the one from the name. */
  edited: boolean;
  set: (v: string) => void;
}

/**
 * An id that follows a name until the admin edits it (feeds.md §1's rule; profiles: core.md §2's
 * DNS label), so it is shown before saving: core derives none and refuses an empty one. A
 * cleared id counts as not typed: it follows the name again, shown as the placeholder while the
 * field stays empty (refilling the field would undo the admin's delete key mid-edit).
 */
export function useDerivedId(kind: string, name: string, fallback?: string): DerivedId {
  const [typed, setTyped] = React.useState<string | null>(null);
  const derived = fallback || idFromName(kind, name);
  const id = typed || derived;
  const valid = kind === "profiles" ? isProfileId(id) : isSlug(id);
  return { id, input: typed ?? derived, derived, valid, edited: !!typed, set: setTyped };
}

export function idRule(kind: string): string {
  return kind === "profiles"
    ? "A DNS label: lowercase letters, digits and hyphens, not ending in -full."
    : "1–64 of a-z, 0-9, - and _, starting with a letter or digit.";
}

/** The id input of a create dialog, with what the id will be and its rule. */
export function IdField({ htmlId, kind, state, label = "Id" }: { htmlId: string; kind: string; state: DerivedId; label?: string }) {
  const bad = state.id !== "" && !state.valid;
  const following = !state.edited;
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlId}>{label}</Label>
      <Input
        id={htmlId}
        value={state.input}
        placeholder={state.derived || undefined}
        onChange={(e) => state.set(e.target.value)}
        className="font-mono"
        aria-invalid={bad || undefined}
        aria-describedby={`${htmlId}-help`}
        autoComplete="off"
      />
      <p id={`${htmlId}-help`} className={bad ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
        {bad
          ? idRule(kind)
          : state.id === ""
            ? "Taken from the name; or type one."
            : following
              ? "From the name; edit it if you like. It never changes once created."
              : "It never changes once created."}
      </p>
    </div>
  );
}
