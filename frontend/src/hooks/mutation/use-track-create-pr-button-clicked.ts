import { useMutation } from "@tanstack/react-query";
import { usePostHog } from "posthog-js/react";
import { analyticsEventsService } from "#/api/analytics-service/analytics-events.api";
import { Provider } from "#/types/settings";

const EVENT_NAME = "create pr button clicked";

/**
 * Mutation hook that notifies the server when the user clicks the
 * "Pull Request" button. Posts to the generic
 * `POST /api/analytics/events` endpoint with `event_type =
 * "create pr button clicked"`; the server fires the matching PostHog event.
 *
 * A client-side `posthog.capture()` is also fired so that PostHog
 * surveys targeting this event can be triggered by the JS SDK.
 *
 * Tracking is fire-and-forget: errors are swallowed so a telemetry outage
 * never blocks the user's primary action of submitting the prompt.
 */
export const useTrackCreatePrButtonClicked = () => {
  const posthog = usePostHog();

  return useMutation({
    mutationFn: (gitProvider: Provider | null) => {
      posthog?.capture(EVENT_NAME, { git_provider: gitProvider });

      return analyticsEventsService.trackEvent({
        event_type: EVENT_NAME,
        git_provider: gitProvider,
      });
    },
    // Intentionally swallow errors - analytics must not block the UX.
    onError: () => {},
  });
};
