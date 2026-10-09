import { describe, expect, it } from "vitest";

import {
  nativeUiHelperSnapshotSchema,
  withStableKeys,
} from "./nativeUiCapture.js";
import {
  evaluateNativeUiCondition,
  type NativeUiCondition,
} from "./nativeUiConditions.js";

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
  bounds: null,
  actions: [],
  children_count: 0,
  ...attributes,
});

const capture = (nodes: unknown[], truncated = false) =>
  withStableKeys(
    nativeUiHelperSnapshotSchema.parse({
      window: {
        pid: 1,
        window_id: 2,
        executable: "/fixture",
        launch_time: 1,
        title: "Editor",
      },
      nodes,
      truncated,
      screenshot: null,
      gaps: [],
    }),
  );

const window = node([], {
  role: "AXWindow",
  title: "Editor",
  children_count: 3,
});
const save = node([0], { identifier: "save", title: "Save" });
const off = node([1], { identifier: "off", enabled: false, focused: null });
const ok = node([2], { title: "OK", value: "ready" });
const complete = capture([window, save, off, ok]);

const status = (condition: NativeUiCondition, snapshot = complete) =>
  evaluateNativeUiCondition(snapshot, condition).status;

describe("native UI conditions", () => {
  it("compares the window title exactly", () => {
    expect(status({ window_title: "Editor" })).toBe("pass");
    expect(status({ window_title: "editor" })).toBe("fail");
  });

  it("treats a missing element as unknown when the capture is truncated", () => {
    const missing = { selector: { identifier: "gone" } };
    expect(status({ ...missing, state: "exists" })).toBe("fail");
    expect(status({ ...missing, state: "absent" })).toBe("pass");
    const truncated = capture([window, save], true);
    expect(status({ ...missing, state: "exists" }, truncated)).toBe("unknown");
    expect(status({ ...missing, state: "absent" }, truncated)).toBe("unknown");
    expect(
      status({ selector: { identifier: "save" }, state: "absent" }, truncated),
    ).toBe("fail");
  });

  it("reads element flags and reports unexposed flags as unknown", () => {
    expect(status({ selector: { identifier: "save" }, state: "enabled" })).toBe(
      "pass",
    );
    expect(status({ selector: { identifier: "off" }, state: "disabled" })).toBe(
      "pass",
    );
    expect(status({ selector: { identifier: "off" }, state: "enabled" })).toBe(
      "fail",
    );
    expect(status({ selector: { identifier: "off" }, state: "focused" })).toBe(
      "unknown",
    );
    expect(
      status({ selector: { identifier: "save" }, state: "selected" }),
    ).toBe("unknown");
  });

  it("compares attributes and treats an unexposed attribute as unknown", () => {
    expect(
      status({
        selector: { title: "OK" },
        attribute: "value",
        equals: "ready",
      }),
    ).toBe("pass");
    expect(
      status({ selector: { title: "OK" }, attribute: "value", equals: "busy" }),
    ).toBe("fail");
    expect(
      status({
        selector: { title: "OK" },
        attribute: "description",
        equals: "",
      }),
    ).toBe("unknown");
  });

  it("requires one element for state checks unless index chooses", () => {
    const ambiguous = {
      selector: { role: "AXButton" },
      state: "enabled",
    } as const;
    expect(evaluateNativeUiCondition(complete, ambiguous)).toMatchObject({
      status: "fail",
      detail: expect.stringContaining("ambiguous: 3 elements"),
    });
    expect(
      status({ selector: { role: "AXButton", index: 1 }, state: "disabled" }),
    ).toBe("pass");
    expect(status({ selector: { role: "AXButton" }, state: "exists" })).toBe(
      "pass",
    );
  });
});
