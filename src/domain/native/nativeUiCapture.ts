import { createHash } from "node:crypto";

import { z } from "zod";

import { err, ok, type Result } from "../result.js";
import { decodeCanonicalBase64 } from "../webScreenshot.js";

/** Child-index path from the selected window to one accessibility element. */
export const elementPathSchema = z
  .array(z.number().int().nonnegative())
  .max(32);

const selectorFields = {
  role: z.string().min(1).exactOptional(),
  subrole: z.string().min(1).exactOptional(),
  identifier: z
    .string()
    .min(1)
    .exactOptional()
    .describe("Exact accessibility identifier (AXIdentifier)"),
  title: z.string().exactOptional(),
  description: z.string().exactOptional(),
};
const selectorCriteria = [
  "role",
  "subrole",
  "identifier",
  "title",
  "description",
] as const;
const hasCriterion = (selector: Partial<Record<string, unknown>>): boolean =>
  selectorCriteria.some((field) => selector[field] !== undefined);
const criterionMessage =
  "A selector needs at least one of role, subrole, identifier, title or description";

/**
 * Attribute selector resolved against the capture taken just before the
 * action. Every supplied field must match exactly; `within` requires a
 * matching ancestor and `index` picks one match in document order.
 */
export const nativeUiSelectorSchema = z
  .strictObject({
    ...selectorFields,
    within: z
      .strictObject(selectorFields)
      .refine(hasCriterion, criterionMessage)
      .exactOptional()
      .describe("Ancestor that must enclose the selected element"),
    index: z
      .number()
      .int()
      .nonnegative()
      .exactOptional()
      .describe(
        "Zero-based choice among several matches in document order; without it several matches fail as ambiguous",
      ),
  })
  .refine(hasCriterion, criterionMessage);
export type NativeUiSelector = z.infer<typeof nativeUiSelectorSchema>;

/** Ordered captures and failures distinguish missing observation from a failed action. */
const nativeUiScreenshotSchema = z
  .strictObject({
    mime_type: z.literal("image/png"),
    base64: z
      .string()
      .min(4)
      .describe(
        "Canonical base64 encoding of PNG bytes; the decoded bytes must have a PNG signature and IHDR chunk.",
      ),
    sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/u)
      .describe("SHA-256 digest of the decoded PNG bytes."),
    width: z
      .number()
      .int()
      .positive()
      .describe("Must equal the width encoded in the PNG IHDR chunk."),
    height: z
      .number()
      .int()
      .positive()
      .describe("Must equal the height encoded in the PNG IHDR chunk."),
  })
  .superRefine((screenshot, context) => {
    const bytes = decodeCanonicalBase64(screenshot.base64);
    if (bytes === undefined) {
      context.addIssue({
        code: "custom",
        message: "Invalid canonical PNG base64",
      });
      return;
    }
    if (createHash("sha256").update(bytes).digest("hex") !== screenshot.sha256)
      context.addIssue({
        code: "custom",
        message: "PNG screenshot digest mismatch",
      });
    if (
      bytes.byteLength < 24 ||
      !bytes.subarray(0, 8).equals(PNG_SIGNATURE) ||
      bytes.subarray(12, 16).toString("ascii") !== "IHDR"
    ) {
      context.addIssue({
        code: "custom",
        message: "Screenshot bytes are not a PNG image",
      });
      return;
    }
    if (
      bytes.readUInt32BE(16) !== screenshot.width ||
      bytes.readUInt32BE(20) !== screenshot.height
    )
      context.addIssue({
        code: "custom",
        message: "PNG screenshot dimensions mismatch",
      });
  });

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

const nodeBoundsSchema = z
  .strictObject({
    x: z.number(),
    y: z.number(),
    width: z.number().nonnegative(),
    height: z.number().nonnegative(),
  })
  .describe(
    "Element frame in points, relative to the window's top-left corner",
  );

/** Accessibility attributes reported by the helper; unsupported attributes are null. */
const helperNodeFields = {
  path: z.array(z.number().int().nonnegative()),
  role: z.string().nullable(),
  subrole: z.string().nullable(),
  identifier: z.string().nullable(),
  title: z.string().nullable(),
  description: z.string().nullable(),
  value: z.string().nullable(),
  enabled: z.boolean().nullable(),
  focused: z.boolean().nullable(),
  selected: z.boolean().nullable(),
  bounds: nodeBoundsSchema.nullable(),
  actions: z.array(z.string()),
  children_count: z.number().int().nonnegative().nullable(),
};
const helperNodeSchema = z.strictObject(helperNodeFields);
type HelperNode = z.infer<typeof helperNodeSchema>;

const windowSchema = z.strictObject({
  pid: z.number().int().positive(),
  window_id: z.number().int().positive(),
  executable: z.string(),
  launch_time: z.number(),
  title: z.string(),
});
const snapshotFields = {
  window: windowSchema,
  truncated: z.boolean(),
  screenshot: nativeUiScreenshotSchema.nullable(),
  gaps: z.array(z.string()),
};

/** One capture exactly as the native helper reports it. */
export const nativeUiHelperSnapshotSchema = z.strictObject({
  ...snapshotFields,
  nodes: z.array(helperNodeSchema),
});

/** One capture with REA-derived stable keys for cross-capture node matching. */
export const nativeUiSnapshotSchema = z.strictObject({
  ...snapshotFields,
  nodes: z.array(
    z.strictObject({
      ...helperNodeFields,
      stable_key: z
        .string()
        .regex(/^uik_[a-f0-9]{32}$/u)
        .describe(
          "Digest of the node's identity (identifier, or role/subrole/title/description) chained through its parent's key; sibling order only breaks ties between identical siblings",
        ),
    }),
  ),
});
export type NativeUiSnapshot = z.infer<typeof nativeUiSnapshotSchema>;
export type NativeUiNode = NativeUiSnapshot["nodes"][number];

const nodeIdentity = (node: HelperNode): readonly (string | null)[] =>
  node.identifier === null
    ? ["attributes", node.role, node.subrole, node.title, node.description]
    : ["identifier", node.identifier];

/**
 * Derive keys that survive sibling insertion and value changes. Parents are
 * always captured before their children, so each parent key is known first.
 */
export const withStableKeys = (
  snapshot: z.infer<typeof nativeUiHelperSnapshotSchema>,
): NativeUiSnapshot => {
  const keys = new Map<string, string>();
  const seen = new Map<string, number>();
  const nodes = snapshot.nodes.map((node) => {
    const parentKey = keys.get(JSON.stringify(node.path.slice(0, -1))) ?? "";
    const identity = JSON.stringify([parentKey, nodeIdentity(node)]);
    const ordinal = seen.get(identity) ?? 0;
    seen.set(identity, ordinal + 1);
    const stableKey = `uik_${createHash("sha256")
      .update(JSON.stringify([identity, ordinal]))
      .digest("hex")
      .slice(0, 32)}`;
    keys.set(JSON.stringify(node.path), stableKey);
    return { ...node, stable_key: stableKey };
  });
  return { ...snapshot, nodes };
};

const matchesSelector = (
  node: NativeUiNode,
  selector: Partial<Record<(typeof selectorCriteria)[number], string>>,
): boolean =>
  selectorCriteria.every(
    (field) => selector[field] === undefined || node[field] === selector[field],
  );

/** Every captured node matching a selector's fields and `within`, in document order; `index` is ignored. */
export const selectorMatches = (
  snapshot: NativeUiSnapshot,
  selector: NativeUiSelector,
): NativeUiNode[] => {
  const encloses = (ancestor: NativeUiNode, node: NativeUiNode) =>
    ancestor.path.length < node.path.length &&
    ancestor.path.every((step, index) => node.path[index] === step);
  const within = selector.within;
  return snapshot.nodes.filter(
    (node) =>
      matchesSelector(node, selector) &&
      (within === undefined ||
        snapshot.nodes.some(
          (ancestor) =>
            encloses(ancestor, node) && matchesSelector(ancestor, within),
        )),
  );
};

/** The element a selector resolved to, with the identity the helper must re-check. */
export interface ResolvedNativeUiTarget {
  readonly path: readonly number[];
  readonly stable_key: string;
  readonly expect: {
    readonly role: string | null;
    readonly subrole: string | null;
    readonly identifier: string | null;
    readonly title: string | null;
  };
}

/**
 * Resolve a selector against one capture. A truncated capture fails closed:
 * unseen nodes could make a single match ambiguous or hold the only match.
 */
export const resolveNativeUiSelector = (
  snapshot: NativeUiSnapshot,
  selector: NativeUiSelector,
): Result<ResolvedNativeUiTarget, string> => {
  if (snapshot.truncated)
    return err(
      "The capture before this step is truncated, so selector uniqueness is unknown; raise max_nodes or target a path",
    );
  const matches = selectorMatches(snapshot, selector);
  const choice =
    selector.index === undefined
      ? matches.length === 1
        ? matches[0]
        : undefined
      : matches[selector.index];
  if (choice === undefined)
    return err(
      matches.length === 0
        ? "No captured element matches the selector"
        : selector.index === undefined
          ? `Selector is ambiguous: ${matches.length} elements match (${matches
              .slice(0, 5)
              .map((node) => `[${node.path.join(",")}]`)
              .join(" ")}); add fields, within, or index`
          : `Selector index ${selector.index} exceeds its ${matches.length} matches`,
    );
  return ok({
    path: choice.path,
    stable_key: choice.stable_key,
    expect: {
      role: choice.role,
      subrole: choice.subrole,
      identifier: choice.identifier,
      title: choice.title,
    },
  });
};
