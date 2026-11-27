import * as React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { FeedDef } from "@/api/types";
import { RulePolicyControls, policyDefault } from "@/components/common/rule-policy";

function Harness({ manual, browserMode, onValue }: { manual: boolean; browserMode: string; onValue: (v: FeedDef["rule_policy"]) => void }) {
  const [v, setV] = React.useState<FeedDef["rule_policy"]>({ redirects: null, client_rules: null, browser_changes: null });
  return (
    <TooltipProvider>
      <RulePolicyControls
        value={v}
        manual={manual}
        browserMode={browserMode}
        onChange={(n) => {
          setV(n);
          onValue(n);
        }}
      />
    </TooltipProvider>
  );
}

describe("rule policy controls (feeds.md §8)", () => {
  it("knows each option's default", () => {
    expect(policyDefault("redirects", false)).toBe("drop");
    expect(policyDefault("client_rules", false)).toBe("drop");
    expect(policyDefault("browser_changes", false)).toBe("keep");
    expect(policyDefault("redirects", true)).toBe("keep");
  });

  it("shows defaults for a downloaded feed, notes browser mode drop, and sets an explicit value", async () => {
    const user = userEvent.setup();
    const values: FeedDef["rule_policy"][] = [];
    render(<Harness manual={false} browserMode="drop" onValue={(v) => values.push(v)} />);
    expect(screen.getAllByText("default")).toHaveLength(3);
    expect(screen.getByRole("switch", { name: "redirects: keep" })).toHaveAttribute("data-state", "unchecked");
    expect(screen.getByRole("switch", { name: "browser_changes: keep" })).toHaveAttribute("data-state", "checked");
    expect(screen.getByText(/no effect: browser mode is drop/)).toBeInTheDocument();
    await user.click(screen.getByRole("switch", { name: "client_rules: keep" }));
    expect(values.at(-1)).toEqual({ redirects: null, client_rules: "keep", browser_changes: null });
    await user.click(screen.getByRole("button", { name: "Use default" }));
    expect(values.at(-1)).toEqual({ redirects: null, client_rules: null, browser_changes: null });
  });
});
