import { describe, expect, it } from "vitest";
import {
  createPlanningFileEditorActionEvent,
  createOtherActionEvent,
  createPlanningObservationEvent,
  createUserMessageEvent,
} from "test-utils";
import { shouldRenderEvent } from "#/components/v1/chat/event-content-helpers/should-render-event";
import { ACPToolCallEvent } from "#/types/v1/core/events/acp-tool-call-event";
import { OpenHandsEvent } from "#/types/v1/core";

const makeACPEvent = (
  overrides: Partial<ACPToolCallEvent> = {},
): ACPToolCallEvent => ({
  id: "acp-1",
  kind: "ACPToolCallEvent",
  timestamp: "2024-01-01T00:00:00Z",
  source: "agent",
  tool_call_id: "tc-1",
  title: "Run command",
  status: "completed",
  tool_kind: "execute",
  raw_input: { command: "ls" },
  raw_output: "file.txt",
  content: null,
  is_error: false,
  ...overrides,
});

describe("shouldRenderEvent - PlanningFileEditorAction", () => {
  it("should return false for PlanningFileEditorAction", () => {
    const event = createPlanningFileEditorActionEvent("action-1");

    expect(shouldRenderEvent(event)).toBe(false);
  });

  it("should return true for other action types", () => {
    const event = createOtherActionEvent("action-1");

    expect(shouldRenderEvent(event)).toBe(true);
  });

  it("should return true for PlanningFileEditorObservation", () => {
    const event = createPlanningObservationEvent("obs-1");

    // Observations should still render (they're handled separately in event-message)
    expect(shouldRenderEvent(event)).toBe(true);
  });

  it("should return true for user message events", () => {
    const event = createUserMessageEvent("msg-1");

    expect(shouldRenderEvent(event)).toBe(true);
  });
});

describe("shouldRenderEvent - ACPToolCallEvent", () => {
  it("should return false for in_progress events (suppress empty-args flash)", () => {
    const event = makeACPEvent({ status: "in_progress", raw_input: {} });

    expect(shouldRenderEvent(event)).toBe(false);
  });

  it("should return true for completed events", () => {
    const event = makeACPEvent({ status: "completed" });

    expect(shouldRenderEvent(event)).toBe(true);
  });

  it("should return true for failed events", () => {
    const event = makeACPEvent({ status: "failed", is_error: true });

    expect(shouldRenderEvent(event)).toBe(true);
  });

  it("should return false for null status (pre-terminal — no production events yet)", () => {
    // ACP feature flag has never shipped to production with the GUI, so
    // there are no legacy null-status events in the wild. Treat null as
    // pre-terminal and suppress to avoid flashing an empty card during
    // the intermediate updates some ACP servers emit before settling.
    const event = makeACPEvent({ status: null });

    expect(shouldRenderEvent(event)).toBe(false);
  });
});

describe("shouldRenderEvent - /goal status updates", () => {
  const makeGoalEvent = (active: boolean): OpenHandsEvent =>
    ({
      id: "goal-1",
      kind: "ConversationStateUpdateEvent",
      timestamp: "2024-01-01T00:00:00Z",
      source: "environment",
      key: "goal",
      value: {
        active,
        status: active ? "running" : "complete",
        iteration: 1,
        max_iterations: 10,
        objective: "make pytest pass",
        verdict: null,
      },
    }) as unknown as OpenHandsEvent;

  const makeStatsEvent = (): OpenHandsEvent =>
    ({
      id: "stats-1",
      kind: "ConversationStateUpdateEvent",
      timestamp: "2024-01-01T00:00:00Z",
      source: "environment",
      key: "stats",
      value: {},
    }) as unknown as OpenHandsEvent;

  it("renders the terminal goal status inline", () => {
    expect(shouldRenderEvent(makeGoalEvent(false))).toBe(true);
  });

  it("hides the in-progress goal status (shown by the live banner instead)", () => {
    expect(shouldRenderEvent(makeGoalEvent(true))).toBe(false);
  });

  it("still hides non-goal state updates", () => {
    expect(shouldRenderEvent(makeStatsEvent())).toBe(false);
  });
});

describe("shouldRenderEvent - /goal loop re-prompts", () => {
  const makeUserMessage = (text: string): OpenHandsEvent =>
    ({
      id: "m1",
      kind: "MessageEvent",
      source: "user",
      timestamp: "2024-01-01T00:00:00Z",
      llm_message: { role: "user", content: [{ type: "text", text }] },
    }) as unknown as OpenHandsEvent;

  it("hides the per-round follow-up re-prompt", () => {
    const followup = makeUserMessage(
      "The goal is NOT yet complete (audit iteration 1).\nOutstanding: needs tests",
    );
    expect(shouldRenderEvent(followup)).toBe(false);
  });

  it("hides the resume re-prompt", () => {
    expect(
      shouldRenderEvent(
        makeUserMessage("Resuming a goal that was paused or interrupted. ..."),
      ),
    ).toBe(false);
  });

  it("still renders the objective and ordinary user messages", () => {
    expect(
      shouldRenderEvent(makeUserMessage("create roman.py with to_roman(n)")),
    ).toBe(true);
    expect(shouldRenderEvent(createUserMessageEvent("m2"))).toBe(true);
  });
});
