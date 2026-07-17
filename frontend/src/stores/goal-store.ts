import { create } from "zustand";
import { devtools } from "zustand/middleware";
import { GoalStatus } from "#/types/v1/core/events/conversation-state-event";

interface GoalState {
  /** Latest goal status per conversation, fed by goal state-update events. */
  statusByConversation: Record<string, GoalStatus>;
}

interface GoalActions {
  /** Replace the latest goal status for a conversation. */
  setStatus: (conversationId: string, status: GoalStatus) => void;
}

type GoalStore = GoalState & GoalActions;

export const useGoalStore = create<GoalStore>()(
  devtools(
    (set) => ({
      statusByConversation: {},
      setStatus: (conversationId, status) =>
        set((s) => ({
          statusByConversation: {
            ...s.statusByConversation,
            [conversationId]: status,
          },
        })),
    }),
    { name: "GoalStore" },
  ),
);
