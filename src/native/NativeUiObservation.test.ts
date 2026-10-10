import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";
import { observeNativeUi } from "./NativeUiObservation.js";
import type { BinaryTarget } from "../domain/binaryTarget.js";

const target: BinaryTarget = {
  path: "/fixture/App",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "mach-o",
  architecture: "arm64",
  availableArchitectures: ["arm64"],
};
const scope = {
  pid: 123,
  window_id: 456,
  screenshot: false,
};
const snapshot = {
  window: {
    pid: 123,
    window_id: 456,
    executable: target.path,
    launch_time: 1,
    title: "Fixture",
  },
  nodes: [],
  screenshot: null,
  gaps: [],
  truncated: false,
};

/** Helper-shaped accessibility node with every attribute explicitly reported. */
const node = (
  path: number[],
  attributes: Readonly<Record<string, unknown>> = {},
) => ({
  path,
  role: "AXButton",
  subrole: null,
  identifier: null,
  title: null,
  description: null,
  value: null,
  enabled: true,
  focused: false,
  selected: null,
  bounds: { x: 0, y: 0, width: 10, height: 10 },
  actions: ["AXPress"],
  children_count: 0,
  ...attributes,
});

const validPng = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jv4sAAAAASUVORK5CYII=",
  "base64",
);
describe("native UI screenshot validation", () => {
  it("rejects malformed or mismatched screenshot bytes from the helper", async () => {
    const screenshot = {
      mime_type: "image/png",
      base64: validPng.toString("base64"),
      sha256: "0".repeat(64),
      width: 1,
      height: 1,
    };
    const result = await observeNativeUi(
      target,
      "observe_native_ui",
      { ...scope, screenshot: true },
      {
        invoke: async () => ({
          ok: true,
          result: { ...snapshot, screenshot },
        }),
      },
    );
    expect(result.ok).toBe(false);
  });

  it.each([
    { base64: "%%%=" },
    { base64: Buffer.from("not a PNG").toString("base64") },
    { width: 2 },
  ])(
    "rejects invalid screenshot field variants from the helper",
    async (change) => {
      const screenshot = {
        mime_type: "image/png",
        base64: validPng.toString("base64"),
        sha256: createHash("sha256").update(validPng).digest("hex"),
        width: 1,
        height: 1,
        ...change,
      };
      const result = await observeNativeUi(
        target,
        "observe_native_ui",
        { ...scope, screenshot: true },
        {
          invoke: async () => ({
            ok: true,
            result: { ...snapshot, screenshot },
          }),
        },
      );
      expect(result.ok).toBe(false);
    },
  );

  it("accepts a self-consistent PNG screenshot from the helper", async () => {
    const bytes = validPng;
    const screenshot = {
      mime_type: "image/png",
      base64: bytes.toString("base64"),
      sha256: createHash("sha256").update(bytes).digest("hex"),
      width: 1,
      height: 1,
    };
    const result = await observeNativeUi(
      target,
      "observe_native_ui",
      { ...scope, screenshot: true },
      {
        invoke: async () => ({
          ok: true,
          result: { ...snapshot, screenshot },
        }),
      },
    );
    expect(result.ok).toBe(true);
  });

  it("preserves an unknown AX child count and its truncation gap", async () => {
    const partial = {
      ...snapshot,
      nodes: [
        node([], { role: "AXWindow", title: "Fixture", children_count: null }),
      ],
      truncated: true,
      gaps: ["AX child count unavailable at path []: AXError -25204"],
    };
    const result = await observeNativeUi(
      target,
      "observe_native_ui",
      { ...scope, accessibility: true },
      { invoke: async () => ({ ok: true, result: partial }) },
    );
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.initial).toMatchObject({
        truncated: true,
        gaps: ["AX child count unavailable at path []: AXError -25204"],
        nodes: [{ children_count: null }],
      });
  });
});

describe("native UI capture selection and budgets", () => {
  it("accepts observations and scenarios without compatibility flags", async () => {
    let calls = 0;
    const invoke = async () => {
      calls++;
      return { ok: true, result: snapshot };
    };
    const observed = await observeNativeUi(
      target,
      "observe_native_ui",
      { pid: 123, window_id: 456, screenshot: false, accessibility: true },
      { invoke },
    );
    expect(observed.ok).toBe(true);
    const captured = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        pid: 123,
        window_id: 456,
        screenshot: false,
        accessibility: true,
        steps: [{ kind: "click", path: [] }],
      },
      { invoke },
    );
    expect(captured.ok).toBe(true);
    expect(calls).toBe(3);
  });
  it("returns caller-selected large observations and complete action lists", async () => {
    const nodeLimits: unknown[] = [];
    const steps = Array.from({ length: 17 }, () => ({
      kind: "wait" as const,
      milliseconds: 0,
    }));
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        pid: 123,
        window_id: 456,
        screenshot: false,
        accessibility: true,
        max_nodes: 2_001,
        steps,
      },
      {
        invoke: async (parameters) => {
          nodeLimits.push(parameters.max_nodes);
          return { ok: true, result: snapshot };
        },
      },
    );
    expect(result.ok).toBe(true);
    expect(nodeLimits).toEqual(Array.from({ length: 18 }, () => 2_001));
    if (result.ok) {
      expect(result.value.steps).toHaveLength(17);
      expect(
        result.value.steps.every(({ outcome }) => outcome === "completed"),
      ).toBe(true);
    }
  });
  it("accepts caller-selected waits beyond the old aggregate cutoff", async () => {
    const controller = new AbortController();
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        pid: 123,
        window_id: 456,
        screenshot: false,
        accessibility: true,
        steps: Array.from({ length: 4 }, () => ({
          kind: "wait" as const,
          milliseconds: 10_001,
        })),
      },
      {
        signal: controller.signal,
        invoke: async () => {
          controller.abort();
          return { ok: true, result: snapshot };
        },
      },
    );
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.steps[0]).toMatchObject({
        kind: "wait",
        outcome: "cancelled",
      });
  });
  it("reports aggregate output exhaustion after individually valid captures", async () => {
    const largeSnapshot = {
      ...snapshot,
      window: { ...snapshot.window, title: "x".repeat(17 * 1024 * 1024) },
    };
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        ...scope,
        steps: [{ kind: "wait", milliseconds: 0 }],
      },
      { invoke: async () => ({ ok: true, result: largeSnapshot }) },
    );
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.steps[0]).toMatchObject({
        outcome: "failed",
        reason: expect.stringContaining("64 MiB output budget"),
      });
  });
});

describe("native UI target and cancellation failures", () => {
  it.each([
    "accessibility-denied",
    "screen-recording-denied",
    "ambiguous-window",
  ])("preserves actionable %s without fallback", async (code) => {
    const result = await observeNativeUi(target, "observe_native_ui", scope, {
      invoke: async () => ({
        ok: false,
        code,
        message: "Grant permission or select an unambiguous window",
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.message).toContain(code);
  });
  it("preserves the underlying helper failure reason in diagnostics", async () => {
    const result = await observeNativeUi(target, "observe_native_ui", scope, {
      invoke: async () => {
        throw new Error(
          "Native helper returned invalid JSON: Unexpected token",
        );
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatchObject({
      diagnostics: {
        reason: "Native helper returned invalid JSON: Unexpected token",
        remediation:
          "Native helper failed, timed out, or returned malformed capture data; install compatible Xcode command-line tools and inspect local OS permissions",
      },
    });
  });
  it("stops on a failed action and returns ordered before/capture-gap evidence", async () => {
    const calls: Readonly<Record<string, unknown>>[] = [];
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        ...scope,
        steps: [
          { kind: "scroll", path: [1], direction: "increment" },
          { kind: "click", path: [2] },
        ],
      },
      {
        invoke: async (parameters) => {
          calls.push(parameters);
          return calls.length === 1
            ? { ok: true, result: snapshot }
            : {
                ok: false,
                code: "action-failed",
                message: "AXIncrement unsupported",
              };
        },
      },
    );
    expect(calls).toHaveLength(2);
    expect(calls[1]).toMatchObject({
      launch_time: 1,
      action: { kind: "scroll", path: [1] },
    });
    expect(result.ok).toBe(true);
    if (result.ok)
      expect(result.value.steps).toMatchObject([
        { index: 0, outcome: "failed", before: snapshot, after: null },
      ]);
  });
  it("rejects target replacement and stops subsequent actions after cancellation", async () => {
    const controller = new AbortController();
    let calls = 0;
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      {
        ...scope,
        steps: [
          { kind: "wait", milliseconds: 1000 },
          { kind: "click", path: [] },
        ],
      },
      {
        signal: controller.signal,
        invoke: async () => {
          calls++;
          controller.abort();
          return { ok: true, result: snapshot };
        },
      },
    );
    expect(calls).toBe(1);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.steps[0]?.outcome).toBe("cancelled");
    const replaced = await observeNativeUi(target, "observe_native_ui", scope, {
      invoke: async () => ({
        ok: true,
        result: { ...snapshot, window: { ...snapshot.window, pid: 999 } },
      }),
    });
    expect(replaced.ok).toBe(false);
  });
});

const window = node([], {
  role: "AXWindow",
  title: "Fixture",
  actions: [],
  children_count: 4,
});
const toolbar = node([0], {
  role: "AXToolbar",
  actions: [],
  children_count: 2,
});
const saveInToolbar = node([0, 0], {
  title: "Save",
  identifier: "save-toolbar",
});
const okButton = node([1], { title: "OK" });
const cancelButton = node([2], { title: "Cancel" });
const secondOk = node([3], { title: "OK" });
const tree = (nodes: unknown[], truncated = false) => ({
  ...snapshot,
  nodes,
  truncated,
});
const scenario = async (
  steps: unknown[],
  captured: unknown,
  accessibility = true,
) => {
  const calls: Readonly<Record<string, unknown>>[] = [];
  const result = await observeNativeUi(
    target,
    "capture_native_ui_scenario",
    { ...scope, accessibility, steps },
    {
      invoke: async (parameters) => {
        calls.push(parameters);
        return { ok: true, result: captured };
      },
    },
  );
  return { calls, result };
};

describe("native UI selectors and stable keys", () => {
  it("keys nodes by identity so sibling insertion and value changes keep them", async () => {
    const observe = async (nodes: unknown[]) => {
      const result = await observeNativeUi(
        target,
        "observe_native_ui",
        { ...scope, accessibility: true },
        { invoke: async () => ({ ok: true, result: tree(nodes) }) },
      );
      if (!result.ok) throw result.error;
      return result.value.initial.nodes.map((captured) => captured.stable_key);
    };
    const before = await observe([window, okButton, cancelButton]);
    const after = await observe([
      window,
      node([1], { role: "AXStaticText", title: "Inserted" }),
      node([2], { title: "OK", value: "changed" }),
      node([3], { title: "Cancel" }),
    ]);
    expect(new Set(before).size).toBe(3);
    expect(after[2]).toBe(before[1]);
    expect(after[3]).toBe(before[2]);
    expect(after[0]).toBe(before[0]);
  });

  it("resolves a selector against the preceding capture and pins the element identity", async () => {
    const { calls, result } = await scenario(
      [{ kind: "click", selector: { role: "AXButton", title: "Cancel" } }],
      tree([window, okButton, cancelButton]),
    );
    expect(calls[1]).toMatchObject({
      action: {
        kind: "click",
        path: [2],
        expect: {
          role: "AXButton",
          subrole: null,
          identifier: null,
          title: "Cancel",
        },
      },
    });
    if (!result.ok) throw result.error;
    const [step] = result.value.steps;
    expect(step?.outcome).toBe("completed");
    expect(step?.target).toEqual({
      path: [2],
      stable_key: result.value.initial.nodes[2]?.stable_key,
    });
  });

  it("narrows a selector by ancestor and by index", async () => {
    const { calls } = await scenario(
      [
        {
          kind: "click",
          selector: { title: "Save", within: { role: "AXToolbar" } },
        },
        { kind: "click", selector: { title: "OK", index: 1 } },
      ],
      tree([window, toolbar, saveInToolbar, okButton, secondOk]),
    );
    expect(calls[1]).toMatchObject({ action: { path: [0, 0] } });
    expect(calls[2]).toMatchObject({ action: { path: [3] } });
  });
});

describe("native UI selector refusals", () => {
  it.each([
    [
      "an ambiguous selector",
      { title: "OK" },
      tree([window, okButton, secondOk]),
      "Selector is ambiguous: 2 elements match",
    ],
    [
      "a selector without a match",
      { identifier: "missing" },
      tree([window, okButton]),
      "No captured element matches the selector",
    ],
    [
      "a selector on a truncated capture",
      { title: "OK" },
      tree([window, okButton], true),
      "selector uniqueness is unknown",
    ],
  ])("fails %s without acting", async (_name, selector, captured, reason) => {
    const { calls, result } = await scenario(
      [{ kind: "click", selector }],
      captured,
    );
    expect(calls).toHaveLength(1);
    if (!result.ok) throw result.error;
    expect(result.value.steps).toMatchObject([
      { index: 0, target: null, outcome: "failed", after: null },
    ]);
    expect(result.value.steps[0]?.reason).toContain(reason);
  });

  it.each([
    [
      "both path and selector",
      [{ kind: "click", path: [1], selector: { title: "OK" } }],
      true,
    ],
    ["neither path nor selector", [{ kind: "click" }], true],
    ["an empty selector", [{ kind: "click", selector: {} }], true],
    [
      "a selector without accessibility",
      [{ kind: "click", selector: { title: "OK" } }],
      false,
    ],
  ])("rejects %s before capturing", async (_name, steps, accessibility) => {
    const { calls, result } = await scenario(
      steps,
      tree([window, okButton]),
      accessibility,
    );
    expect(result.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe("native UI keys, conditions and checkpoints", () => {
  const titled = (title: string) =>
    tree([window, node([1], { identifier: "status", title })]);
  /** Fake helper returning queued captures, then repeating the last one. */
  const scripted = (...captures: unknown[]) => {
    const calls: Readonly<Record<string, unknown>>[] = [];
    const invoke = async (parameters: Readonly<Record<string, unknown>>) => {
      calls.push(parameters);
      const next = captures[Math.min(calls.length - 1, captures.length - 1)];
      return { ok: true, result: next };
    };
    return { calls, invoke };
  };
  const run = (steps: unknown[], helper: ReturnType<typeof scripted>) =>
    observeNativeUi(
      target,
      "capture_native_ui_scenario",
      { ...scope, accessibility: true, steps },
      { invoke: helper.invoke },
    );

  it("sends key chords with their modifiers and records a checkpoint label", async () => {
    const helper = scripted(titled("idle"));
    const result = await run(
      [
        { kind: "keys", keys: [{ key: "s", modifiers: ["command"] }] },
        { kind: "checkpoint", name: "saved" },
      ],
      helper,
    );
    if (!result.ok) throw result.error;
    expect(helper.calls[1]).toMatchObject({
      action: {
        kind: "keys",
        keys: [{ key: "s", modifiers: ["command"], hold_ms: 0 }],
      },
    });
    expect(helper.calls).toHaveLength(3);
    expect(result.value.steps[1]).toMatchObject({
      kind: "checkpoint",
      label: "saved",
      outcome: "completed",
    });
  });

  it("evaluates expect on the preceding capture without capturing or stopping", async () => {
    const helper = scripted(titled("idle"));
    const result = await run(
      [
        {
          kind: "expect",
          condition: {
            selector: { identifier: "status" },
            attribute: "title",
            equals: "done",
          },
        },
        { kind: "checkpoint", name: "still-running" },
      ],
      helper,
    );
    if (!result.ok) throw result.error;
    expect(result.value.steps[0]).toMatchObject({
      outcome: "completed",
      after: null,
      assertion: { status: "fail", detail: 'title is "idle"' },
    });
    expect(result.value.steps[1]).toMatchObject({ outcome: "completed" });
    expect(helper.calls).toHaveLength(2);
  });

  it("polls without screenshots until the condition passes, then keeps one capture", async () => {
    const helper = scripted(
      titled("idle"),
      titled("busy"),
      titled("done"),
      titled("done"),
    );
    const result = await run(
      [
        {
          kind: "wait_for",
          condition: {
            selector: { identifier: "status" },
            attribute: "title",
            equals: "done",
          },
          timeout_ms: 5_000,
          poll_ms: 50,
        },
      ],
      helper,
    );
    if (!result.ok) throw result.error;
    expect(helper.calls.slice(1, 3).map((call) => call["screenshot"])).toEqual([
      false,
      false,
    ]);
    expect(helper.calls[3]?.["screenshot"]).toBe(scope.screenshot);
    expect(result.value.steps[0]).toMatchObject({
      outcome: "completed",
      assertion: { status: "pass" },
    });
  });

  it("fails a wait_for that times out and stops the scenario", async () => {
    const helper = scripted(titled("idle"));
    const result = await run(
      [
        {
          kind: "wait_for",
          condition: { window_title: "Never" },
          timeout_ms: 120,
          poll_ms: 50,
        },
        { kind: "checkpoint", name: "unreached" },
      ],
      helper,
    );
    if (!result.ok) throw result.error;
    expect(result.value.steps).toHaveLength(1);
    expect(result.value.steps[0]).toMatchObject({
      outcome: "failed",
      assertion: { status: "fail" },
      reason: expect.stringContaining("Condition not met within 120 ms"),
    });
  });

  it.each([
    [
      "an element condition without accessibility",
      [
        {
          kind: "expect",
          condition: { selector: { title: "OK" }, state: "exists" },
        },
      ],
    ],
    ["an unknown key", [{ kind: "keys", keys: [{ key: "hyper" }] }]],
    ["an empty chord list", [{ kind: "keys", keys: [] }]],
  ])("rejects %s before capturing", async (_name, steps) => {
    const helper = scripted(titled("idle"));
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      { ...scope, accessibility: false, screenshot: true, steps },
      { invoke: helper.invoke },
    );
    expect(result.ok).toBe(false);
    expect(helper.calls).toHaveLength(0);
  });
});

describe("native UI pointer requests", () => {
  const canvasNode = node([1], {
    role: "AXGroup",
    identifier: "canvas",
    bounds: { x: 30, y: 50, width: 200, height: 100 },
  });
  const pointerTree = tree([window, canvasNode]);
  const run = async (steps: unknown[]) => {
    const calls: Readonly<Record<string, unknown>>[] = [];
    const result = await observeNativeUi(
      target,
      "capture_native_ui_scenario",
      { ...scope, accessibility: true, steps },
      {
        invoke: async (parameters) => {
          calls.push(parameters);
          return { ok: true, result: pointerTree };
        },
      },
    );
    return { calls, result };
  };

  it("sends both drag endpoints with pinned identities, offsets and modifiers", async () => {
    const { calls, result } = await run([
      {
        kind: "pointer",
        gesture: "drag",
        at: { selector: { identifier: "canvas" }, offset: { x: 5, y: 6 } },
        to: { window_point: { x: 100, y: 120 } },
        modifiers: ["shift"],
      },
    ]);
    if (!result.ok) throw result.error;
    expect(calls[1]).toMatchObject({
      action: {
        kind: "pointer",
        gesture: "drag",
        at: {
          path: [1],
          offset: { x: 5, y: 6 },
          expect: { role: "AXGroup", identifier: "canvas" },
        },
        to: { window_point: { x: 100, y: 120 } },
        modifiers: ["shift"],
        duration_ms: 200,
      },
    });
    expect(result.value.steps[0]?.target).toEqual({
      path: [1],
      stable_key: result.value.initial.nodes[1]?.stable_key,
    });
  });

  it("records no element target for a window point", async () => {
    const { result } = await run([
      {
        kind: "pointer",
        gesture: "click",
        at: { window_point: { x: 10, y: 10 } },
      },
    ]);
    if (!result.ok) throw result.error;
    expect(result.value.steps[0]?.target).toBeNull();
  });

  it.each([
    ["a drag without to", { gesture: "drag", at: { path: [1] } }],
    [
      "to on a click",
      { gesture: "click", at: { path: [1] }, to: { path: [1] } },
    ],
    [
      "an offset on a window point",
      {
        gesture: "click",
        at: { window_point: { x: 1, y: 1 }, offset: { x: 1, y: 1 } },
      },
    ],
    [
      "two point addresses",
      { gesture: "click", at: { path: [1], window_point: { x: 1, y: 1 } } },
    ],
  ])("rejects %s before capturing", async (_name, step) => {
    const { calls, result } = await run([{ kind: "pointer", ...step }]);
    expect(result.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
