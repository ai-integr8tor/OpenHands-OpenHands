import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useGoalInterceptor } from "#/hooks/chat/use-goal-interceptor";

const mockStartV1Goal = vi.hoisted(() =>
  vi.fn<
    (id: string, objective: string, maxIterations?: number) => Promise<void>
  >(),
);
const mockToast = vi.hoisted(() => vi.fn<(message: string) => void>());

vi.mock("#/hooks/mutation/conversation-mutation-utils", () => ({
  startV1Goal: (id: string, objective: string, maxIterations?: number) =>
    mockStartV1Goal(id, objective, maxIterations),
}));

vi.mock("#/utils/custom-toast-handlers", () => ({
  displayErrorToast: (message: string) => mockToast(message),
}));

const CONV = "conv-1";

describe("useGoalInterceptor", () => {
  beforeEach(() => {
    mockStartV1Goal.mockReset();
    mockStartV1Goal.mockResolvedValue(undefined);
    mockToast.mockReset();
  });

  it("falls through to onSubmit for non-/goal messages", () => {
    const onSubmit = vi.fn();
    const { result } = renderHook(() => useGoalInterceptor(CONV, onSubmit));
    act(() => result.current("hello world"));
    expect(onSubmit).toHaveBeenCalledWith("hello world");
    expect(mockStartV1Goal).not.toHaveBeenCalled();
  });

  it("intercepts /goal and starts the loop with the objective", () => {
    const onSubmit = vi.fn();
    const { result } = renderHook(() => useGoalInterceptor(CONV, onSubmit));
    act(() => result.current("/goal make pytest pass"));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(mockStartV1Goal).toHaveBeenCalledWith(
      CONV,
      "make pytest pass",
      undefined,
    );
  });

  it("parses a leading --max N flag", () => {
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal --max 3 make pytest pass"));
    expect(mockStartV1Goal).toHaveBeenCalledWith(CONV, "make pytest pass", 3);
  });

  it("parses the --max=N form", () => {
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal --max=5 ship it"));
    expect(mockStartV1Goal).toHaveBeenCalledWith(CONV, "ship it", 5);
  });

  it("ignores an invalid --max value and treats the rest as the objective", () => {
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal --max abc do the thing"));
    expect(mockStartV1Goal).toHaveBeenCalledWith(
      CONV,
      "--max abc do the thing",
      undefined,
    );
  });

  it("does nothing but warn for a bare /goal with no objective", () => {
    const onSubmit = vi.fn();
    const { result } = renderHook(() => useGoalInterceptor(CONV, onSubmit));
    act(() => result.current("/goal"));
    expect(onSubmit).not.toHaveBeenCalled();
    expect(mockStartV1Goal).not.toHaveBeenCalled();
    expect(mockToast).toHaveBeenCalledWith("GOAL$OBJECTIVE_REQUIRED");
  });

  it("falls through when conversationId is null (feature off for V0)", () => {
    const onSubmit = vi.fn();
    const { result } = renderHook(() => useGoalInterceptor(null, onSubmit));
    act(() => result.current("/goal do it"));
    expect(onSubmit).toHaveBeenCalledWith("/goal do it");
    expect(mockStartV1Goal).not.toHaveBeenCalled();
  });

  it("surfaces the agent-server detail (not a bare axios message) on a 409", async () => {
    mockStartV1Goal.mockRejectedValueOnce({
      isAxiosError: true,
      message: "Request failed with status code 409",
      response: {
        data: { detail: "Conversation run or goal loop already running." },
      },
    });
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal do it"));
    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        "Conversation run or goal loop already running.",
      ),
    );
  });

  it("falls back to the i18n start-failed key when the error carries no detail", async () => {
    mockStartV1Goal.mockRejectedValueOnce({});
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal do it"));
    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith("GOAL$START_FAILED"),
    );
  });

  it("shows a plain Error message when startV1Goal rejects", async () => {
    mockStartV1Goal.mockRejectedValueOnce(new Error("boom"));
    const { result } = renderHook(() => useGoalInterceptor(CONV, vi.fn()));
    act(() => result.current("/goal do it"));
    await waitFor(() => expect(mockToast).toHaveBeenCalledWith("boom"));
  });
});
