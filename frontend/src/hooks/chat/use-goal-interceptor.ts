import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import axios from "axios";
import { startV1Goal } from "#/hooks/mutation/conversation-mutation-utils";
import { displayErrorToast } from "#/utils/custom-toast-handlers";
import { retrieveAxiosErrorMessage } from "#/utils/retrieve-axios-error-message";
import { I18nKey } from "#/i18n/declaration";
import { GOAL_COMMAND } from "#/utils/constants";

const GOAL_PREFIX = `${GOAL_COMMAND} `;

/** Optional leading "--max <n>" (or "--max=<n>") flag that caps the audit rounds. */
const MAX_FLAG = /^--max(?:=|\s+)(\d+)\s*/;

/**
 * Intercepts "/goal [--max N] <objective>" submissions and starts a goal loop
 * on the agent server: it pursues the objective, judging completion after each
 * run until done or the cap is reached. Live progress streams back as goal
 * ConversationStateUpdateEvents (rendered by GoalStatusBanner). Everything else
 * falls through to `onSubmit`. Passthrough when `conversationId` is null.
 */
export const useGoalInterceptor = (
  conversationId: string | null | undefined,
  onSubmit: (message: string) => void,
) => {
  const { t } = useTranslation();

  return useCallback(
    (message: string) => {
      const trimmed = message.trim();
      const isGoal =
        trimmed === GOAL_COMMAND || trimmed.startsWith(GOAL_PREFIX);
      if (!conversationId || !isGoal) {
        onSubmit(message);
        return;
      }

      let rest = trimmed.slice(GOAL_COMMAND.length).trim();
      let maxIterations: number | undefined;
      const maxMatch = rest.match(MAX_FLAG);
      if (maxMatch) {
        maxIterations = parseInt(maxMatch[1], 10);
        rest = rest.slice(maxMatch[0].length).trim();
      }

      const objective = rest;
      if (!objective) {
        // bare /goal — no objective to pursue
        displayErrorToast(t(I18nKey.GOAL$OBJECTIVE_REQUIRED));
        return;
      }

      startV1Goal(
        conversationId,
        objective,
        maxIterations && maxIterations >= 1 ? maxIterations : undefined,
      ).catch((err: unknown) => {
        // Surface the agent-server's reason instead of a bare "Request failed
        // with status code 409" — e.g. "Conversation run or goal loop already
        // running." when a prior run/goal hasn't settled yet.
        let messageText = t(I18nKey.GOAL$START_FAILED);
        if (axios.isAxiosError(err)) {
          messageText = retrieveAxiosErrorMessage(err) || messageText;
        } else if (err instanceof Error && err.message) {
          messageText = err.message;
        }
        displayErrorToast(messageText);
      });
    },
    [conversationId, onSubmit, t],
  );
};
