import { OpenHandsParsedEvent } from "#/types/core";
import { OpenHandsEvent } from "#/types/v1/core";
import { MessageEvent } from "#/types/v1/core/events/message-event";
import {
  isActionEvent,
  isObservationEvent,
  isMessageEvent,
  isAgentErrorEvent,
  isConversationStateUpdateEvent,
  isGoalConversationStateUpdateEvent,
  isHookExecutionEvent,
  isACPToolCallEvent,
  isStreamingDeltaEvent,
  isV1Event,
} from "#/types/v1/type-guards";

// Prefixes of the SDK goal-loop re-prompts (FOLLOWUP_PROMPT / RESUME_PROMPT in
// openhands.sdk .../conversation/goal/prompts.py). The goal loop injects these
// as `user` messages each round to steer the agent, and FOLLOWUP_PROMPT embeds
// the judge's verdict — which the goal banner already surfaces. The persisted
// event carries no marker distinguishing them from real user input, so we match
// the prompt text to keep this machinery out of the chat. Brittle by design;
// keep in sync with the SDK prompts.
const GOAL_REPROMPT_PREFIXES = [
  "The goal is NOT yet complete (audit iteration",
  "Resuming a goal that was paused or interrupted.",
];

const isGoalLoopReprompt = (event: MessageEvent): boolean => {
  if (event.llm_message.role !== "user") return false;
  const { content } = event.llm_message;
  // content is typed as an array but can arrive as a plain string at runtime.
  const text = Array.isArray(content)
    ? content
        .filter((c) => c.type === "text")
        .map((c) => c.text)
        .join("\n")
    : "";
  return GOAL_REPROMPT_PREFIXES.some((prefix) => text.startsWith(prefix));
};

export const shouldRenderEvent = (event: OpenHandsEvent) => {
  if (isConversationStateUpdateEvent(event)) {
    // A finished `/goal` loop renders inline so it settles into the
    // conversation; the live (active) banner is shown separately by
    // GoalStatusBanner, and all other state updates (and the in-progress goal
    // events) stay hidden.
    return isGoalConversationStateUpdateEvent(event) && !event.value.active;
  }

  // Render action events (with filtering)
  if (isActionEvent(event)) {
    // For V1, action is an object with kind property
    const actionType = event.action.kind;

    if (!actionType) {
      return false;
    }

    // Hide user commands from the chat interface
    if (actionType === "ExecuteBashAction" && event.source === "user") {
      return false;
    }

    // Hide PlanningFileEditorAction - handled separately with PlanPreview component
    if (actionType === "PlanningFileEditorAction") {
      return false;
    }

    return true;
  }

  // Render observation events
  if (isObservationEvent(event)) {
    return true;
  }

  // Render message events (user and assistant messages), except the goal loop's
  // injected re-prompts — the judge feedback they carry is shown in the goal
  // banner, so otherwise they leak into the chat as fake user turns.
  if (isMessageEvent(event)) {
    return !isGoalLoopReprompt(event);
  }

  // Render streaming token deltas (the live, growing assistant bubble).
  // Empty boundary deltas are dropped upstream in handleEventForUI.
  if (isStreamingDeltaEvent(event)) {
    return true;
  }

  // Render agent error events
  if (isAgentErrorEvent(event)) {
    return true;
  }

  // Render hook execution events
  if (isHookExecutionEvent(event)) {
    return true;
  }

  // Render ACP sub-agent tool call events only once they've reached a
  // terminal status. The ACP server emits multiple events per
  // ``tool_call_id`` as the call progresses; ``handleEventForUI`` dedupes
  // them into a single in-place card. Showing pre-terminal events flashes
  // an empty ``Input: {}`` / ``Output: [no output]`` card while
  // ``raw_input`` / ``raw_output`` are still streaming in. Wait for the
  // call to settle before rendering anything.
  if (isACPToolCallEvent(event)) {
    return event.status === "completed" || event.status === "failed";
  }

  // Don't render any other event types (system events, etc.)
  return false;
};

export const hasUserEvent = (events: OpenHandsEvent[]) =>
  events.some((event) => event.source === "user");

/**
 * Narrow a mixed V0/V1 event list to V1 events that actually render in chat.
 * Single source of truth: callers (e.g. `useFilteredEvents`, slash-command
 * interceptors that anchor to the latest visible event) MUST use this rather
 * than re-implementing `isV1Event` + `shouldRenderEvent` chains, so updates
 * to the rendering rules are picked up everywhere.
 */
export const getRenderedV1Events = (
  events: ReadonlyArray<OpenHandsEvent | OpenHandsParsedEvent>,
): OpenHandsEvent[] => events.filter(isV1Event).filter(shouldRenderEvent);
