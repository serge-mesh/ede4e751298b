import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ShieldCheckIcon, ShieldXIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { IdSelect } from "./ordered-picker";
import { qk, useEntities } from "@/api/queries";
import { client, unwrap } from "@/api/http";
import { errorMessage } from "@/api/errors";
import { escapeControl } from "@/lib/text";

/**
 * A name or IPv4 address that can go into an adblock rule as is. Outside text (a query name, an
 * entry key) with other characters could turn into a different rule (`$`, `|`, `^`, spaces), so
 * one-click edits refuse it. An IPv6 address too: `||2001:db8::1^` is a pattern over the address
 * text (rules.md §1), which also matches `2001:db8::1:5`, and no allow form names an IPv6 address
 * (an exception with a scheme, `@@|https://[…]^`, is a browser rule).
 */
export function ruleSafe(name: string): boolean {
  return /^[a-z0-9_]([a-z0-9_.-]{0,252})$/i.test(name);
}

export function ruleFor(action: "allow" | "block", name: string): string {
  const n = name.replace(/\.$/, "").toLowerCase();
  return action === "allow" ? `@@||${n}^` : `||${n}^`;
}

/**
 * One-click Allow/Block (feeds.md §6): appends one line to an `adblock` manual feed the admin
 * picks (default `manual-allow` / `manual-block`), as one new run.
 */
export function AppendRuleButton({ action, name, size = "sm", label }: { action: "allow" | "block"; name: string; size?: "sm" | "default"; label?: string }) {
  const [open, setOpen] = React.useState(false);
  const safe = ruleSafe(name.replace(/\.$/, ""));
  const Icon = action === "allow" ? ShieldCheckIcon : ShieldXIcon;
  return (
    <>
      <Button
        size={size}
        variant="outline"
        disabled={!safe}
        title={safe ? undefined : "This name has characters a rule can't hold; add it in the feed's editor."}
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
      >
        <Icon /> {label ?? (action === "allow" ? "Allow" : "Block")}
      </Button>
      {open && <AppendRuleDialog action={action} name={name} onClose={() => setOpen(false)} />}
    </>
  );
}

function AppendRuleDialog({ action, name, onClose }: { action: "allow" | "block"; name: string; onClose: () => void }) {
  const feeds = useEntities("feeds");
  const qc = useQueryClient();
  const manual = (feeds.data ?? []).filter((f) => !f.provider && (f.format ?? "adblock") === "adblock");
  const fallback = action === "allow" ? "manual-allow" : "manual-block";
  const [target, setTarget] = React.useState<string>(fallback);
  const [busy, setBusy] = React.useState(false);
  const line = ruleFor(action, name);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent onClick={(e) => e.stopPropagation()}>
        <DialogHeader>
          <DialogTitle>{action === "allow" ? "Allow permanently" : "Block"}</DialogTitle>
          <DialogDescription>
            Appends one line to a manual feed, as one new run.{" "}
            {action === "allow" ? "An allow covers the name in every block list of profiles that use its bundle." : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Line</Label>
            <pre className="rounded-md bg-muted p-2 font-mono text-sm">{escapeControl(line)}</pre>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="append-target">Manual feed (adblock format)</Label>
            <IdSelect
              id="append-target"
              value={target}
              onChange={(v) => setTarget(v ?? fallback)}
              options={manual.map((f) => ({ value: f.id ?? "", label: f.name ? `${f.name} (${f.id})` : f.id }))}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await unwrap(client.POST("/api/ui/v1/feeds/{id}/file/lines", { params: { path: { id: target } }, body: { lines: [line] } }));
                toast.success(`Added to ${escapeControl(target)}`);
                void qc.invalidateQueries({ queryKey: ["feeds"] });
                // Its file changed: an editor opened later reads it again (an open one sees the run).
                void qc.invalidateQueries({ queryKey: qk.manualFile(target), refetchType: "none" });
                onClose();
              } catch (e) {
                toast.error(errorMessage(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            Append
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
