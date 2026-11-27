// The rule policy switches (core.md §12 Rule policy controls, feeds.md §8): one drop/keep switch
// per option, whose tooltip is core's field description; unset options show their default.
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { InfoTip } from "@/components/common/info-tip";
import type { FeedDef } from "@/api/types";
import { fieldDescription } from "@/lib/openapi";

export const POLICY_OPTIONS = ["redirects", "client_rules", "browser_changes"] as const;

/** The option's default: manual feeds keep all three; others drop redirects and client rules. */
export function policyDefault(option: (typeof POLICY_OPTIONS)[number], manual: boolean): "drop" | "keep" {
  if (manual) return "keep";
  return option === "browser_changes" ? "keep" : "drop";
}

export function RulePolicyControls({
  value,
  onChange,
  manual,
  browserMode,
  disabled,
}: {
  value: FeedDef["rule_policy"];
  onChange: (v: FeedDef["rule_policy"]) => void;
  manual: boolean;
  browserMode: string;
  disabled?: boolean;
}) {
  const v = value ?? {};
  return (
    <div className="space-y-2 rounded-md border p-3" role="group" aria-label="Rule policy">
      {POLICY_OPTIONS.map((opt) => {
        const set = v[opt];
        const def = policyDefault(opt, manual);
        const effective = set ?? def;
        // core's description is the tooltip (core.md §12): the rules covered with examples, what
        // `keep` lets the feed do, the default, and browser_changes' browser-mode note.
        const tip = fieldDescription("RulePolicy", opt);
        const id = `rule-policy-${opt}`;
        return (
          <div key={opt} className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <label htmlFor={id} className="font-mono text-sm">
                {opt}
              </label>
              <InfoTip text={tip} label={`About ${opt}`} />
              {set === null || set === undefined ? <Badge variant="outline">default</Badge> : null}
              {opt === "browser_changes" && browserMode === "drop" && <span className="text-xs text-muted-foreground">(no effect: browser mode is drop)</span>}
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className={effective === "drop" ? "font-medium" : "text-muted-foreground"}>drop</span>
              <Switch id={id} checked={effective === "keep"} disabled={disabled} onCheckedChange={(on) => onChange({ ...v, [opt]: on ? "keep" : "drop" })} aria-label={`${opt}: keep`} />
              <span className={effective === "keep" ? "font-medium" : "text-muted-foreground"}>keep</span>
              {set !== null && set !== undefined && (
                <Button variant="ghost" size="sm" disabled={disabled} onClick={() => onChange({ ...v, [opt]: null })}>
                  Use default
                </Button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
