import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import {
  nativeUiObservationInputSchema,
  nativeUiScenarioInputSchema,
  nativeUiHelperSnapshotSchema,
  nativeUiResultSchema,
  withStableKeys,
} from "../domain/native/nativeUiObservation.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { type AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import { createNativeUiHelperRuntime } from "./NativeUiHelperRuntime.js";
import { runNativeUiStep, type NativeUiCapture } from "./NativeUiSteps.js";
import {
  NATIVE_UI_OUTPUT_BUDGET_BYTES,
  NATIVE_UI_OUTPUT_WEIGHT,
} from "./NativeUiOutputBudget.js";

const helper = fileURLToPath(
  new URL("../../bridge/native/ReaNativeUI.swift", import.meta.url),
);
const responseSchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), result: nativeUiHelperSnapshotSchema }),
  z.strictObject({
    ok: z.literal(false),
    code: z.string(),
    message: z.string(),
  }),
]);
/** Narrow process seam preserves the native helper's OS and target failures. */
export type NativeUiHelper = (
  parameters: Readonly<Record<string, unknown>>,
  signal?: AbortSignal,
) => Promise<unknown>;

/** Capture a selected existing app window and run explicitly selected scenarios. */
export const observeNativeUi = async (
  target: BinaryTarget,
  operation: "observe_native_ui" | "capture_native_ui_scenario",
  parameters: unknown,
  options: { signal?: AbortSignal | undefined; invoke?: NativeUiHelper } = {},
): Promise<Result<z.infer<typeof nativeUiResultSchema>, AnalysisError>> => {
  const runtime = createNativeUiHelperRuntime();
  try {
    return await observeWithHelper(target, operation, parameters, {
      ...options,
      invoke: options.invoke ?? runtime.invoke,
    });
  } finally {
    await runtime.close();
  }
};

const observeWithHelper = async (
  target: BinaryTarget,
  operation: "observe_native_ui" | "capture_native_ui_scenario",
  parameters: unknown,
  options: { signal?: AbortSignal | undefined; invoke: NativeUiHelper },
): Promise<Result<z.infer<typeof nativeUiResultSchema>, AnalysisError>> => {
  const parsed = (
    operation === "observe_native_ui"
      ? nativeUiObservationInputSchema
      : nativeUiScenarioInputSchema
  ).safeParse(parameters);
  if (!parsed.success)
    return err(new AnalysisInputError(operation, { cause: parsed.error }));
  if (target.kind !== "executable" || target.format !== "mach-o")
    return err(
      new AnalysisCapabilityUnavailableError(
        "native-macos",
        operation,
        "Native UI observation requires an active Mach-O executable or app target",
      ),
    );
  const input = parsed.data;
  if (!input.screenshot && !input.accessibility)
    return err(
      new AnalysisInputError(operation, {
        cause: new Error("Enable screenshot or accessibility capture"),
      }),
    );
  const steps =
    operation === "capture_native_ui_scenario"
      ? nativeUiScenarioInputSchema.parse(parameters).steps
      : [];
  const signal =
    options.signal === undefined
      ? AbortSignal.timeout(180_000)
      : AbortSignal.any([options.signal, AbortSignal.timeout(180_000)]);
  const invoke = options.invoke;
  let launchTime: number | undefined;
  let outputBytes = 0;
  const take: NativeUiCapture = async (action, captureOptions = {}) => {
    if (signal.aborted) return err(new AnalysisCancelledError(operation));
    try {
      const response = responseSchema.parse(
        await invoke(
          {
            pid: input.pid,
            window_id: input.window_id,
            executable: target.path,
            sha256: target.sha256,
            ...(launchTime === undefined ? {} : { launch_time: launchTime }),
            screenshot: captureOptions.screenshot ?? input.screenshot,
            accessibility: input.accessibility,
            max_nodes: input.max_nodes,
            ...(action === undefined ? {} : { action }),
          },
          signal,
        ),
      );
      if (!response.ok)
        return err(
          new AnalysisCapabilityUnavailableError(
            "native-macos",
            operation,
            `${response.code}: ${response.message}`,
          ),
        );
      if (
        response.result.window.pid !== input.pid ||
        response.result.window.window_id !== input.window_id ||
        response.result.window.executable !== target.path ||
        (launchTime !== undefined &&
          response.result.window.launch_time !== launchTime)
      )
        return err(
          new AnalysisCapabilityUnavailableError(
            "native-macos",
            operation,
            "Native helper returned a different target process or window",
          ),
        );
      launchTime = response.result.window.launch_time;
      if (captureOptions.retained === false)
        return ok(withStableKeys(response.result));
      outputBytes +=
        NATIVE_UI_OUTPUT_WEIGHT *
        Buffer.byteLength(JSON.stringify(response.result));
      if (outputBytes > NATIVE_UI_OUTPUT_BUDGET_BYTES)
        return err(
          new AnalysisCapabilityUnavailableError(
            "native-macos",
            operation,
            "Scenario captures exceeded the 64 MiB output budget",
          ),
        );
      return ok(withStableKeys(response.result));
    } catch (cause) {
      return err(
        signal.aborted
          ? new AnalysisCancelledError(operation)
          : new ProviderAdapterError("native-macos", operation, {
              cause,
              diagnostics: {
                helper_path: helper,
                reason: cause instanceof Error ? cause.message : String(cause),
                remediation:
                  "Native helper failed, timed out, or returned malformed capture data; install compatible Xcode command-line tools and inspect local OS permissions",
              },
            }),
      );
    }
  };
  const initial = await take();
  if (!initial.ok) return initial;
  const results: z.infer<typeof nativeUiResultSchema>["steps"] = [];
  let before = initial.value;
  for (const [index, step] of steps.entries()) {
    if (signal.aborted) {
      results.push({
        index,
        kind: step.kind,
        label: null,
        target: null,
        assertion: null,
        before,
        after: null,
        outcome: "cancelled",
        reason: "Scenario cancelled before action",
      });
      break;
    }
    const outcome = await runNativeUiStep(step, before, take, signal);
    results.push({ index, kind: step.kind, before, ...outcome.record });
    if (outcome.stop) break;
    before = outcome.next;
  }
  return ok(
    nativeUiResultSchema.parse({
      target_sha256: target.sha256,
      initial: initial.value,
      steps: results,
      restore: "leave-as-is",
      limitations: [
        "Only the explicitly selected already-running process/window is admitted. REA starts no target process and does not change permissions, foreground applications, or restore application data.",
        "Click uses AXPress; scroll uses AXIncrement/AXDecrement; key-entry sets the selected element's AXValue. Unsupported elements fail without global event fallback.",
        "keys posts synthetic key events to the selected process only (CGEvent postToPid); no global event tap is used and the system cursor is untouched. Chords go to the application's focused element and use US ANSI virtual key codes, so produced characters depend on the active keyboard layout.",
        "pointer moves the real system cursor and posts system-wide (HID-level) mouse events, because mouse events posted to a process are not delivered to AppKit windows. Before posting, the helper raises the selected window and activates its application, re-resolves element targets from their live frames, and checks every event point (start, each drag step, end): it must lie inside the selected window, and an accessibility hit test there must return an element of that window, so the menu bar, Dock, other applications and the application's other windows refuse the step with point-occluded and nothing is posted. Afterwards the cursor is restored to within one point; the previously active application is not restored, and user input during a gesture can interleave with it.",
        "expect evaluates its condition on the capture before it and never stops the scenario. wait_for polls accessibility-only captures (no screenshots, not retained) until the condition passes or its timeout expires, then records one retained capture; a timeout fails the step. Conditions on truncated captures are unknown rather than pass or fail.",
        "Each completed action is followed immediately by capture; use wait_for or wait for delayed UI changes. A failed after-capture can follow a completed action, so failure does not prove absence of application effects.",
        "Scenarios can change app data, cause app network activity and persist changes. The caller explicitly chooses leave-as-is; automatic restoration is unsupported.",
        "Selectors resolve against the capture taken immediately before each action; the helper re-checks role, subrole, identifier and title at the resolved path and fails if the element changed. Selector steps fail closed on truncated captures, no match, or ambiguous matches without index. Stable keys derive from accessibility identity and parent keys; they are REA-derived, not application-assigned.",
        "Window matching uses exact PID and window ID for screenshots and unique accessibility geometry. Accessibility paths can change as the UI changes; stale or ambiguous paths fail. Screenshots are scaled to at most 2048 pixels; scenario output is budgeted at 64 MiB and execution is cancelled after 180 seconds.",
      ],
    }),
  );
};
