import {
  resolveNativeUiSelector,
  type NativeUiSnapshot,
  type NativeUiStep,
} from "../domain/native/nativeUiObservation.js";
import {
  evaluateNativeUiCondition,
  type NativeUiAssertion,
} from "../domain/native/nativeUiConditions.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ok, type Result } from "../domain/result.js";

/** Capture options: polls skip screenshots and are not retained or budgeted. */
export interface CaptureOptions {
  readonly screenshot?: boolean;
  readonly retained?: boolean;
}

/** One helper round trip, optionally performing an action first. */
export type NativeUiCapture = (
  action?: Readonly<Record<string, unknown>>,
  options?: CaptureOptions,
) => Promise<Result<NativeUiSnapshot, AnalysisError>>;

/** Everything a step adds to the result besides its index, kind and before capture. */
export interface NativeUiStepRecord {
  readonly label: string | null;
  readonly target: { path: number[]; stable_key: string | null } | null;
  readonly assertion: NativeUiAssertion | null;
  readonly after: NativeUiSnapshot | null;
  readonly outcome: "completed" | "failed" | "cancelled";
  readonly reason: string | null;
}

/** A step's record, the capture the next step starts from, and whether to stop. */
export interface NativeUiStepOutcome {
  readonly record: NativeUiStepRecord;
  readonly next: NativeUiSnapshot;
  readonly stop: boolean;
}

const record = (
  fields: Partial<NativeUiStepRecord> & Pick<NativeUiStepRecord, "outcome">,
): NativeUiStepRecord => ({
  label: null,
  target: null,
  assertion: null,
  after: null,
  reason: null,
  ...fields,
});

type ElementAddress = {
  readonly path?: readonly number[];
  readonly selector?: Parameters<typeof resolveNativeUiSelector>[1];
};

/**
 * Resolve an element address against the preceding capture. Selectors pin
 * the identity the helper must re-check; paths keep their positional meaning.
 */
const resolveElement = (
  address: ElementAddress,
  before: NativeUiSnapshot,
): Result<
  {
    readonly request: Readonly<Record<string, unknown>>;
    readonly target: { path: number[]; stable_key: string | null };
  },
  string
> => {
  if (address.selector !== undefined) {
    const resolved = resolveNativeUiSelector(before, address.selector);
    if (!resolved.ok) return resolved;
    const path = [...resolved.value.path];
    return ok({
      request: { path, expect: resolved.value.expect },
      target: { path, stable_key: resolved.value.stable_key },
    });
  }
  const path = [...(address.path ?? [])];
  const node = before.nodes.find(
    (candidate) =>
      candidate.path.length === path.length &&
      candidate.path.every((value, index) => value === path[index]),
  );
  return ok({
    request: { path },
    target: { path, stable_key: node?.stable_key ?? null },
  });
};

type PointTarget = Extract<NativeUiStep, { kind: "pointer" }>["at"];

/** Resolve a pointer location; element targets keep the identity the helper re-checks. */
const resolvePoint = (
  point: PointTarget,
  before: NativeUiSnapshot,
): Result<
  {
    readonly request: Readonly<Record<string, unknown>>;
    readonly target: { path: number[]; stable_key: string | null } | null;
  },
  string
> => {
  if (point.window_point !== undefined)
    return ok({ request: { window_point: point.window_point }, target: null });
  const element = resolveElement(point, before);
  if (!element.ok) return element;
  return ok({
    request: {
      ...element.value.request,
      ...(point.offset === undefined ? {} : { offset: point.offset }),
    },
    target: element.value.target,
  });
};

const sleep = (milliseconds: number, signal: AbortSignal): Promise<boolean> =>
  new Promise((resolve) => {
    if (signal.aborted) return resolve(false);
    const abort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve(true);
    }, milliseconds);
    signal.addEventListener("abort", abort, { once: true });
  });

/** Capture after an action, mapping a capture failure to a failed or cancelled step. */
const capture = async (
  take: NativeUiCapture,
  before: NativeUiSnapshot,
  fields: Partial<NativeUiStepRecord>,
  action?: Readonly<Record<string, unknown>>,
): Promise<NativeUiStepOutcome> => {
  const after = await take(action);
  if (!after.ok)
    return {
      record: record({
        ...fields,
        outcome:
          after.error._tag === "AnalysisCancelledError"
            ? "cancelled"
            : "failed",
        reason: after.error.message,
      }),
      next: before,
      stop: true,
    };
  return {
    record: record({ ...fields, after: after.value, outcome: "completed" }),
    next: after.value,
    stop: false,
  };
};

const refused = (
  before: NativeUiSnapshot,
  reason: string,
): NativeUiStepOutcome => ({
  record: record({ outcome: "failed", reason }),
  next: before,
  stop: true,
});

/** Poll captures until the condition passes or the timeout expires. */
const waitFor = async (
  step: Extract<NativeUiStep, { kind: "wait_for" }>,
  before: NativeUiSnapshot,
  take: NativeUiCapture,
  signal: AbortSignal,
): Promise<NativeUiStepOutcome> => {
  const deadline = Date.now() + step.timeout_ms;
  let latest = before;
  let assertion = evaluateNativeUiCondition(latest, step.condition);
  while (assertion.status !== "pass" && Date.now() < deadline) {
    if (
      !(await sleep(
        Math.min(step.poll_ms, Math.max(0, deadline - Date.now())),
        signal,
      ))
    )
      return {
        record: record({
          assertion,
          outcome: "cancelled",
          reason: "Scenario cancelled while waiting",
        }),
        next: latest,
        stop: true,
      };
    const polled = await take(undefined, {
      screenshot: false,
      retained: false,
    });
    if (!polled.ok)
      return {
        record: record({
          assertion,
          outcome:
            polled.error._tag === "AnalysisCancelledError"
              ? "cancelled"
              : "failed",
          reason: polled.error.message,
        }),
        next: latest,
        stop: true,
      };
    latest = polled.value;
    assertion = evaluateNativeUiCondition(latest, step.condition);
  }
  const settled = await capture(take, latest, { assertion });
  if (settled.stop || assertion.status === "pass") return settled;
  return {
    record: {
      ...settled.record,
      outcome: "failed",
      reason: `Condition not met within ${step.timeout_ms} ms: ${assertion.detail}`,
    },
    next: settled.next,
    stop: true,
  };
};

/** Execute one scenario step against the capture that precedes it. */
export const runNativeUiStep = async (
  step: NativeUiStep,
  before: NativeUiSnapshot,
  take: NativeUiCapture,
  signal: AbortSignal,
): Promise<NativeUiStepOutcome> => {
  switch (step.kind) {
    case "wait":
      if (!(await sleep(step.milliseconds, signal)))
        return {
          record: record({
            outcome: "cancelled",
            reason: "Scenario cancelled during wait",
          }),
          next: before,
          stop: true,
        };
      return capture(take, before, {});
    case "checkpoint":
      return capture(take, before, { label: step.name });
    case "expect":
      return {
        record: record({
          assertion: evaluateNativeUiCondition(before, step.condition),
          outcome: "completed",
        }),
        next: before,
        stop: false,
      };
    case "wait_for":
      return waitFor(step, before, take, signal);
    case "keys":
      return capture(take, before, {}, { kind: "keys", keys: step.keys });
    case "pointer": {
      const at = resolvePoint(step.at, before);
      if (!at.ok) return refused(before, at.error);
      const to =
        step.to === undefined ? undefined : resolvePoint(step.to, before);
      if (to !== undefined && !to.ok) return refused(before, to.error);
      return capture(
        take,
        before,
        { target: at.value.target },
        {
          kind: "pointer",
          gesture: step.gesture,
          at: at.value.request,
          ...(to === undefined ? {} : { to: to.value.request }),
          modifiers: step.modifiers ?? [],
          duration_ms: step.duration_ms,
        },
      );
    }
    default: {
      const element = resolveElement(step, before);
      if (!element.ok) return refused(before, element.error);
      const { path: _path, selector: _selector, ...action } = step;
      return capture(
        take,
        before,
        { target: element.value.target },
        { ...action, ...element.value.request },
      );
    }
  }
};
