import { z } from "zod";

import {
  nativeUiSelectorSchema,
  selectorMatches,
  type NativeUiNode,
  type NativeUiSnapshot,
} from "./nativeUiCapture.js";

const elementStates = [
  "exists",
  "absent",
  "enabled",
  "disabled",
  "focused",
  "selected",
] as const;

/**
 * Observable UI condition for `wait_for` and `expect` steps. Element states
 * other than `exists`/`absent` need one element: a unique match, or `index`.
 */
export const nativeUiConditionSchema = z.union([
  z.strictObject({
    selector: nativeUiSelectorSchema,
    state: z.enum(elementStates),
  }),
  z.strictObject({
    selector: nativeUiSelectorSchema,
    attribute: z.enum(["title", "value", "description"]),
    equals: z.string(),
  }),
  z.strictObject({
    window_title: z.string().describe("Exact window title"),
  }),
]);
export type NativeUiCondition = z.infer<typeof nativeUiConditionSchema>;

/** Assertion verdict; `unknown` means the capture cannot decide the condition. */
export const nativeUiAssertionSchema = z.strictObject({
  status: z.enum(["pass", "fail", "unknown"]),
  detail: z.string(),
});
export type NativeUiAssertion = z.infer<typeof nativeUiAssertionSchema>;

const verdict = (
  status: NativeUiAssertion["status"],
  detail: string,
): NativeUiAssertion => ({ status, detail });

const flagVerdict = (
  value: boolean | null,
  expected: boolean,
  name: string,
): NativeUiAssertion =>
  value === null
    ? verdict("unknown", `The element does not expose ${name}`)
    : verdict(
        value === expected ? "pass" : "fail",
        `${name} is ${String(value)}`,
      );

/**
 * Evaluate a condition against one capture. A truncated capture can hide
 * matches, so a missing match is `unknown` rather than `fail` (or `pass`
 * for `absent`).
 */
export const evaluateNativeUiCondition = (
  snapshot: NativeUiSnapshot,
  condition: NativeUiCondition,
): NativeUiAssertion => {
  if ("window_title" in condition)
    return verdict(
      snapshot.window.title === condition.window_title ? "pass" : "fail",
      `Window title is ${JSON.stringify(snapshot.window.title)}`,
    );
  const matches = selectorMatches(snapshot, condition.selector);
  const unseen = snapshot.truncated
    ? " in a truncated capture; raise max_nodes"
    : "";
  if ("state" in condition && condition.state === "exists")
    return matches.length > 0
      ? verdict("pass", `${matches.length} element(s) match`)
      : verdict(
          snapshot.truncated ? "unknown" : "fail",
          `No element matches${unseen}`,
        );
  if ("state" in condition && condition.state === "absent")
    return matches.length > 0
      ? verdict("fail", `${matches.length} element(s) match`)
      : verdict(
          snapshot.truncated ? "unknown" : "pass",
          `No element matches${unseen}`,
        );
  const node = singleMatch(matches, condition.selector.index);
  if (node === undefined)
    return matches.length > 1 && condition.selector.index === undefined
      ? verdict(
          "fail",
          `Selector is ambiguous: ${matches.length} elements match; add fields, within, or index`,
        )
      : verdict(
          snapshot.truncated ? "unknown" : "fail",
          `No single element matches${unseen}`,
        );
  return elementVerdict(node, condition);
};

const singleMatch = (
  matches: readonly NativeUiNode[],
  index: number | undefined,
): NativeUiNode | undefined =>
  index === undefined
    ? matches.length === 1
      ? matches[0]
      : undefined
    : matches[index];

/** Attribute and state conditions on one resolved element. */
const elementVerdict = (
  node: NativeUiNode,
  condition: Exclude<NativeUiCondition, { window_title: string }>,
): NativeUiAssertion => {
  if ("attribute" in condition) {
    const value = node[condition.attribute];
    return value === null
      ? verdict("unknown", `The element does not expose ${condition.attribute}`)
      : verdict(
          value === condition.equals ? "pass" : "fail",
          `${condition.attribute} is ${JSON.stringify(value)}`,
        );
  }
  if (condition.state === "enabled")
    return flagVerdict(node.enabled, true, "enabled");
  if (condition.state === "disabled")
    return flagVerdict(node.enabled, false, "enabled");
  if (condition.state === "focused")
    return flagVerdict(node.focused, true, "focused");
  return flagVerdict(node.selected, true, "selected");
};
