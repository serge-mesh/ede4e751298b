// Issue #65: the provider status shows what the per-provider planning budget did to the weekly
// `k` choice, including each feed's estimated cost after a compromise.
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import type { KChoiceRecord } from "@/api/types";
import { PlanningBudget } from "./feed-provider-detail";

const base: KChoiceRecord = {
  chosen_at: "2026-11-25T00:00:00.000000Z",
  window_start: "2026-10-28T00:00:00.000000Z",
  window_end: "2026-11-25T00:00:00.000000Z",
  voting_feeds: ["oisd", "adguard"],
  budget_per_day: 400,
  choice: { k: 2, preferred: 2, budget: "within", checks_per_day: 317.7, preferred_checks_per_day: 317.7 },
  feeds: [],
};

describe("PlanningBudget", () => {
  it("says a choice fits the budget", () => {
    render(<PlanningBudget choice={base} />);
    expect(screen.getByText(/fits: 317\.7 predicted checks a day of 400/)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Estimated cost per feed" })).toBeNull();
  });

  it("shows a slowdown with each feed's estimated cost", () => {
    render(
      <PlanningBudget
        choice={{
          ...base,
          choice: { k: 3, preferred: 2, budget: "slowed", checks_per_day: 357.8, preferred_checks_per_day: 432.1 },
          feeds: [
            { feed: "oisd", standalone_k: 2, changes: 624, standalone_share_2min: 0.974, grouped_share_2min: 0.962, change_points: -1.2 },
            { feed: "adguard", standalone_k: 3, changes: 332, standalone_share_2min: 0.98, grouped_share_2min: 0.99, change_points: 1.0 },
          ],
        }}
      />,
    );
    expect(screen.getByText(/slowed from k 2 to 3: 432\.1 → 357\.8 predicted checks a day of 400/)).toBeInTheDocument();
    const items = within(screen.getByRole("list", { name: "Estimated cost per feed" })).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("oisd: 97.4 % alone, 96.2 % grouped (-1.2 points, 624 changes)");
    expect(items[1]).toHaveTextContent("adguard: 98.0 % alone, 99.0 % grouped (+1 points, 332 changes)");
  });

  it("says when no k fits", () => {
    render(<PlanningBudget choice={{ ...base, choice: { k: 5, preferred: 2, budget: "none_fits", checks_per_day: 900, preferred_checks_per_day: 1200 } }} />);
    expect(screen.getByText(/no k fits: k 5 predicts 900 checks a day of 400/)).toBeInTheDocument();
  });
});
