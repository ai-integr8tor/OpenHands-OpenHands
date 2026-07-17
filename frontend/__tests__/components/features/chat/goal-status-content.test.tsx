import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GoalStatusContent } from "#/components/features/chat/goal-status-content";
import { GoalStatus } from "#/types/v1/core/events/conversation-state-event";

const makeStatus = (overrides: Partial<GoalStatus> = {}): GoalStatus => ({
  active: true,
  status: "running",
  iteration: 1,
  max_iterations: 10,
  objective: "make pytest pass",
  verdict: null,
  ...overrides,
});

// t is mocked to return the key (see vitest.setup.ts), so the judge's "missing"
// note renders as the raw i18n key GOAL$MISSING.
const MISSING_KEY = "GOAL$MISSING";

describe("<GoalStatusContent />", () => {
  it("shows the objective and a spinner while running", () => {
    render(<GoalStatusContent status={makeStatus()} />);
    expect(screen.getByText("make pytest pass")).toBeInTheDocument();
    expect(screen.getByTestId("goal-spinner")).toBeInTheDocument();
    expect(screen.queryByTestId("goal-done")).toBeNull();
    expect(screen.queryByTestId("goal-ended")).toBeNull();
  });

  it("shows a green check when complete", () => {
    render(
      <GoalStatusContent
        status={makeStatus({
          active: false,
          status: "complete",
          verdict: { score: 1, complete: true, missing: "" },
        })}
      />,
    );
    expect(screen.getByTestId("goal-done")).toBeInTheDocument();
    expect(screen.queryByTestId("goal-spinner")).toBeNull();
    expect(screen.queryByTestId("goal-ended")).toBeNull();
  });

  it("shows a muted cross (not a check) when it ends without completing", () => {
    render(
      <GoalStatusContent
        status={makeStatus({
          active: false,
          status: "capped",
          verdict: { score: 0.7, complete: false, missing: "needs more tests" },
        })}
      />,
    );
    expect(screen.getByTestId("goal-ended")).toBeInTheDocument();
    expect(screen.queryByTestId("goal-done")).toBeNull();
    expect(screen.queryByTestId("goal-spinner")).toBeNull();
  });

  it("expands the judge's missing note for a terminal status", () => {
    render(
      <GoalStatusContent
        status={makeStatus({
          active: false,
          status: "capped",
          verdict: { score: 0.7, complete: false, missing: "needs more tests" },
        })}
      />,
    );
    expect(screen.getByText(MISSING_KEY)).toBeInTheDocument();
  });

  it("keeps the missing note collapsed while the loop is still running", () => {
    render(
      <GoalStatusContent
        status={makeStatus({
          verdict: { score: 0.5, complete: false, missing: "needs more tests" },
        })}
      />,
    );
    expect(screen.queryByText(MISSING_KEY)).toBeNull();
  });
});
