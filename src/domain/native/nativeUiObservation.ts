import { z } from "zod";

import {
  elementPathSchema,
  nativeUiSelectorSchema,
  nativeUiSnapshotSchema,
} from "./nativeUiCapture.js";
import {
  nativeUiAssertionSchema,
  nativeUiConditionSchema,
} from "./nativeUiConditions.js";

export {
  nativeUiHelperSnapshotSchema,
  resolveNativeUiSelector,
  withStableKeys,
  type NativeUiSnapshot,
} from "./nativeUiCapture.js";

const scope = {
  pid: z.number().int().positive(),
  window_id: z.number().int().positive(),
  screenshot: z.boolean().default(true),
  accessibility: z.boolean().default(true),
  max_nodes: z
    .number()
    .int()
    .positive()
    .safe()
    .default(500)
    .describe(
      "Maximum accessibility nodes per capture; increase for large windows.",
    ),
};
/** Opt-in passive observation binds one already-running process and window. */
export const nativeUiObservationInputSchema = z.strictObject(scope);

const elementTarget = {
  path: elementPathSchema
    .exactOptional()
    .describe(
      "Child-index path from the window; exactly one of path or selector",
    ),
  selector: nativeUiSelectorSchema
    .exactOptional()
    .describe("Attribute selector; exactly one of path or selector"),
};

const pointSchema = z.strictObject({ x: z.number(), y: z.number() });

/**
 * Pointer location: an element (path or selector) plus an optional offset
 * from its top-left corner (default: its centre), or a window-relative point.
 */
export const nativeUiPointTargetSchema = z.strictObject({
  ...elementTarget,
  offset: pointSchema
    .exactOptional()
    .describe(
      "Points from the element's top-left corner; defaults to its centre",
    ),
  window_point: pointSchema
    .exactOptional()
    .describe("Points from the window's top-left corner"),
});

const modifiersSchema = z
  .array(z.enum(["command", "shift", "option", "control"]))
  .max(4)
  .exactOptional();

/** Virtual keys for chords; mapped to US ANSI key codes by the helper. */
export const NATIVE_UI_KEYS = [
  ..."abcdefghijklmnopqrstuvwxyz0123456789",
  "return",
  "tab",
  "space",
  "delete",
  "forward_delete",
  "escape",
  "left",
  "right",
  "up",
  "down",
  "home",
  "end",
  "page_up",
  "page_down",
  "minus",
  "equal",
  "comma",
  "period",
  "slash",
  "f1",
  "f2",
  "f3",
  "f4",
  "f5",
  "f6",
  "f7",
  "f8",
  "f9",
  "f10",
  "f11",
  "f12",
] as const;

const stepSchemas = [
  z.strictObject({ kind: z.literal("click"), ...elementTarget }),
  z.strictObject({
    kind: z.literal("scroll"),
    ...elementTarget,
    direction: z.enum(["increment", "decrement"]),
  }),
  z.strictObject({
    kind: z.literal("key-entry"),
    ...elementTarget,
    text: z.string(),
  }),
  z.strictObject({
    kind: z.literal("pointer"),
    gesture: z.enum(["click", "double_click", "right_click", "drag"]),
    at: nativeUiPointTargetSchema,
    to: nativeUiPointTargetSchema
      .exactOptional()
      .describe("Drag destination; required for drag only"),
    modifiers: modifiersSchema,
    duration_ms: z
      .number()
      .int()
      .min(0)
      .max(10_000)
      .default(200)
      .describe("Drag duration"),
  }),
  z.strictObject({
    kind: z.literal("keys"),
    keys: z
      .array(
        z.strictObject({
          key: z.enum(NATIVE_UI_KEYS),
          modifiers: modifiersSchema,
          hold_ms: z.number().int().min(0).max(5_000).default(0),
        }),
      )
      .min(1)
      .max(64)
      .describe("Chords sent in order to the application's focused element"),
  }),
  z.strictObject({
    kind: z.literal("wait"),
    milliseconds: z
      .number()
      .int()
      .min(0)
      .max(180_000)
      .describe(
        "Wait duration in milliseconds, within the 180-second operation deadline.",
      ),
  }),
  z.strictObject({
    kind: z.literal("wait_for"),
    condition: nativeUiConditionSchema,
    timeout_ms: z.number().int().min(1).max(180_000),
    poll_ms: z.number().int().min(50).max(10_000).default(200),
  }),
  z.strictObject({
    kind: z.literal("expect"),
    condition: nativeUiConditionSchema,
  }),
  z.strictObject({
    kind: z.literal("checkpoint"),
    name: z.string().min(1).max(128),
  }),
] as const;
export type NativeUiStep = z.infer<(typeof stepSchemas)[number]>;

/** Element targets need exactly one address; selectors need accessibility. */
const checkTarget = (
  target: {
    readonly path?: unknown;
    readonly selector?: unknown;
    readonly window_point?: unknown;
    readonly offset?: unknown;
  },
  where: {
    readonly accessibility: boolean;
    readonly path: (string | number)[];
    readonly allowWindowPoint?: boolean;
  },
  context: z.RefinementCtx,
): void => {
  const { accessibility, path, allowWindowPoint = false } = where;
  const addresses = [
    target.path,
    target.selector,
    allowWindowPoint ? target.window_point : undefined,
  ].filter((value) => value !== undefined).length;
  if (addresses !== 1)
    context.addIssue({
      code: "custom",
      path,
      message: allowWindowPoint
        ? "Supply exactly one of path, selector or window_point"
        : "Supply exactly one of path or selector",
    });
  if (target.window_point !== undefined && target.offset !== undefined)
    context.addIssue({
      code: "custom",
      path,
      message: "offset applies to element targets, not window_point",
    });
  if (target.selector !== undefined && !accessibility)
    context.addIssue({
      code: "custom",
      path: [...path, "selector"],
      message: "Selector targeting requires accessibility capture",
    });
};

/** Active scenarios use explicit actions and leave application state as-is. */
export const nativeUiScenarioInputSchema = z
  .strictObject({
    ...scope,
    steps: z.array(z.discriminatedUnion("kind", stepSchemas)).min(1),
  })
  .superRefine((input, context) => {
    for (const [index, step] of input.steps.entries()) {
      const at = ["steps", index];
      switch (step.kind) {
        case "click":
        case "scroll":
        case "key-entry":
          checkTarget(
            step,
            {
              accessibility: input.accessibility,
              path: at,
            },
            context,
          );
          break;
        case "pointer": {
          const where = (side: "at" | "to") => ({
            accessibility: input.accessibility,
            path: [...at, side],
            allowWindowPoint: true,
          });
          checkTarget(step.at, where("at"), context);
          if (step.to !== undefined) checkTarget(step.to, where("to"), context);
          if (step.gesture === "drag" && step.to === undefined)
            context.addIssue({
              code: "custom",
              path: at,
              message: "drag requires a to target",
            });
          else if (step.gesture !== "drag" && step.to !== undefined)
            context.addIssue({
              code: "custom",
              path: [...at, "to"],
              message: "to applies only to drag",
            });
          break;
        }
        case "wait_for":
        case "expect":
          if (!input.accessibility && !("window_title" in step.condition))
            context.addIssue({
              code: "custom",
              path: [...at, "condition"],
              message: "Element conditions require accessibility capture",
            });
          break;
        default:
          break;
      }
    }
  });

export const nativeUiResultSchema = z.strictObject({
  target_sha256: z.string(),
  initial: nativeUiSnapshotSchema,
  steps: z.array(
    z.strictObject({
      index: z.number().int().nonnegative(),
      kind: z.string(),
      label: z
        .string()
        .nullable()
        .describe("Checkpoint name; null for other steps"),
      target: z
        .strictObject({
          path: elementPathSchema,
          stable_key: z.string().nullable(),
        })
        .nullable()
        .describe(
          "Element the action addressed; stable_key is null when a path named no captured node",
        ),
      assertion: nativeUiAssertionSchema
        .nullable()
        .describe("expect and wait_for verdict; null for other steps"),
      before: nativeUiSnapshotSchema,
      after: nativeUiSnapshotSchema
        .nullable()
        .describe(
          "Capture after the step; null for expect or when capture failed",
        ),
      outcome: z.enum(["completed", "failed", "cancelled"]),
      reason: z.string().nullable(),
    }),
  ),
  restore: z.literal("leave-as-is"),
  limitations: z.array(z.string()),
});
