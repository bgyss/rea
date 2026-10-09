# UI/UX observation and validation

This is the main gap in the revit-decomp plan, and the place where this fork can add the most. revit-decomp treats GUI behaviour as a single experiment, E12 ("Human task success and visual defects"), and defers it to M08. Meanwhile `revit-bim` already has a deterministic document core with semantic hashes, but no UI and no way to check one. dcomp has the same need from the game side: scripted native playtesting (`~/src/dcomp/docs/scripted-native-playtesting.md`) requires three automated rounds per host before manual QC.

The proposal: make UI behaviour a first-class, machine-checkable evidence lane, on equal footing with document-state evidence, and built from rea primitives.

## What rea has today

`observe_native_ui` and `capture_native_ui_scenario` (`src/native/NativeUiObservation.ts`, `bridge/native/ReaNativeUI.swift`, about 170 lines of Swift):

- macOS only. The helper uses AXUIElement and ScreenCaptureKit.
- It binds to one running `pid` plus `window_id` and captures up to 500 accessibility nodes and a PNG.
- Scenario steps are `click`, `scroll`, `key-entry` (each addressed by a child-index `path`) and a fixed-duration `wait`.
- Each node records `path`, `role`, `title`, `value`, `actions`, and `children_count`.
- Every step captures a full before and after snapshot. The result ends `restore: leave-as-is`.

`compare_web_screenshots` (`src/browser/PngVisualDiff.ts`) is an exact per-pixel comparison that reports changed pixels and the mean channel delta.

Browser and Electron scenarios (`capture_browser_scenario`, `compare_web_captures`) already have the richer model this lane needs: normalized captures, scenario diffs, and evidence-linked deltas. The native lane should converge on that model.

## Gaps that block BIM and game UI validation

| #   | Gap                                                                                                             | Why it matters                                                                                                                                                                                                                                |
| --- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| U1  | Selectors are child-index paths                                                                                 | Paths shift whenever a panel opens or a list reorders. They can't be replayed across runs, and they can't map between Revit and a clone. Selectors need role, name, automation identifier, and ancestry, with the index only as a tiebreaker. |
| U2  | Nodes have no bounds, enabled, focused, selected, or identifier fields                                          | Without frames you can't check layout, hit testing, or focus order, and you can't crop screenshots per element.                                                                                                                               |
| U3  | No pointer actions at coordinates: drag, move, modifier-clicks, double-click, right-click, wheel with modifiers | A BIM canvas (draw a wall, drag a grip, box-select) and every game input are pointer or keyboard gestures, not accessibility actions.                                                                                                         |
| U4  | Only fixed `wait`                                                                                               | Real UIs need "wait until element X exists or is enabled", "wait until the window title changes", or "wait until the screen is stable for N ms". Fixed waits make the runs flaky.                                                             |
| U5  | No assertions inside a scenario                                                                                 | Each validation currently needs a second pass. Inline `expect` steps should record pass, fail, or unknown with evidence.                                                                                                                      |
| U6  | Exact pixel diff only                                                                                           | Font hinting, antialiasing, DPI and cursor blink make exact diffs useless across machines. It needs per-region SSIM or perceptual distance, ignore masks, and a tolerance policy carried as evidence.                                         |
| U7  | macOS only                                                                                                      | Revit runs on Windows, inside an ARM64 Parallels VM. rea's Windows native bundle is x64-only.                                                                                                                                                 |
| U8  | Full snapshots around every step                                                                                | That's expensive and noisy. It needs delta capture: changed subtrees, focus, and the window list.                                                                                                                                             |
| U9  | No timing                                                                                                       | UX quality depends on latency: input to first visual change, and input until the screen is stable. That's also dcomp's input-latency concern.                                                                                                 |
| U10 | No modal or window lifecycle events                                                                             | BIM workflows are dialog-heavy (warnings, type properties, "elements were deleted"). It should capture window open/close and the modal stack per step.                                                                                        |

## Proposed design

### 1. Stable selector model (U1, U2)

```jsonc
{
  "selector": {
    "role": "button", // normalized cross-platform role
    "name": "Wall", // accessible name; exact or regex
    "automation_id": "ID_OBJECTS_WALL", // UIA AutomationId / AXIdentifier / AccessKit node id
    "within": [{ "role": "tab", "name": "Architecture" }],
    "index": 0, // only to break ties
  },
}
```

Snapshot nodes gain `bounds` (in window and screen coordinates, plus DPI scale), `enabled`, `focused`, `selected`, `expanded`, `automation_id`, `class_name`, `subrole`, and a `stable_key`. The key is a digest of the role, automation id, name, and ancestor chain, so diffs can match nodes across snapshots. Keep the index `path` for backward compatibility.

### 2. Action set (U3, U4, U5)

The scenario step union gains:

- `invoke`, `focus`, `set_value`, `toggle`, `expand`, `select`: semantic actions through the accessibility API.
- `pointer`: `move | down | up | click | double_click | drag`, targeting either a selector anchor plus an offset or raw window coordinates, with a button, modifiers, a duration, and the intermediate points of a drag.
- `keys`: chorded key presses with hold durations (game inputs need held directions), separate from `key-entry` text.
- `wait_for`: a selector condition (exists, gone, enabled, value matches), a window title, or a screen-stable condition (N consecutive identical frames inside a region), always with a timeout.
- `expect`: a selector state or a visual region check. It records pass, fail, or unknown and never aborts silently.
- `checkpoint`: a named capture of the tree delta, a screenshot crop set, the window list, and an optional app-specific hook such as a semantic document hash (see 5).

### 3. Windows UI Automation helper (U7, U10)

Add `bridge/native/windows/rea-uia`: a small Rust binary built on the `windows` crate's UIAutomation COM bindings, compiled for both `aarch64-pc-windows-msvc` and `x86_64-pc-windows-msvc`. It speaks the same request and response JSON as `ReaNativeUI.swift`.

- UIA covers WPF and WinForms well. Revit's ribbon (Autodesk's AdWindows WPF ribbon), properties palette, project browser, and most dialogs should come out as a usable tree. Check that in the M01 VM qualification.
- The model canvas is a native graphics surface that UIA can't see into. Treat it as pixels plus the app's own semantic hooks (see 5).
- Window and modal lifecycle comes from UIA `WindowOpened` and `WindowClosed` events, recorded per step.
- Use `SendInput` for pointer and keys. Revit runs under x64 emulation on Windows ARM, and the ARM64 helper can still drive it.

**Transport.** `prlctl exec` was unreliable in the revit-decomp access check (`PrlJob_GetRetCode: Invalid argument`, then a hang). Instead, run the helper as a resident process inside the guest. It should listen on the Parallels host-only network using the authenticated-loopback-TCP pattern rea already uses for its Ghidra bridge (bearer token, one client, explicit shutdown). A new rea provider, `remote-windows-ui`, connects from the Mac. Screenshots travel back inline, as they do today.

### 4. Perceptual comparison (U6, U9)

Replace or extend `PngVisualDiff`:

- Per-region SSIM and changed-pixel ratio, with masks for ignored regions (clock, cursor, viewport noise).
- Element-anchored crops: compare the region of selector X in run A with the region of selector X in run B.
- Tolerance policies as named, versioned inputs, recorded in the evidence (same idea as dcomp's `trace-compare-policy-v1`).
- Report `equivalent`, `different`, or `unknown` per region, never one global boolean.
- Timing: each step records input-dispatch time, time of first visual change, and time the screen became stable (from frame polling at a declared rate). Present it as observed latency with the sampling resolution stated.

This is a good candidate for a Rust helper because it is CPU-bound pixel work. See [rust-strategy](rust-strategy.md).

### 5. App-specific semantic hooks

Screenshots can't establish BIM correctness. The checkpoint step should be able to call an optional hook that returns an app's semantic state:

- **Clone (revit-bim):** add a `--automation` socket or stdin JSON interface to the future app that returns `document-core`'s semantic hash, the selection set, the active view, and the undo depth. revit-bim already computes semantic hashes for deterministic replay; reuse them.
- **Revit oracle (restricted room only):** a documented-API add-in (`IExternalApplication`) that, on request, writes a JSON summary of element counts, parameter values for named synthetic elements, and the active view. Alternatively, read Revit's own journal files (`%LOCALAPPDATA%\Autodesk\Revit\Autodesk Revit 20XX\Journals`) to record which commands the UI actually issued. Confirm both in M01. Neither involves decompilation.
- **dcomp native candidates:** use the scripted and debug control channel the native output contract already requires (`native-control-request-v1`). The checkpoint can then ask for a RAM or state digest, cross-checked against the emulator oracle.

A scenario result then pairs "what the user saw" with "what the model contains". That pairing is exactly what E12 lacks.

### 6. Task-flow specs as the hand-off unit

For revit-decomp the room policy forbids passing proprietary expression to implementers. Screenshots, icon artwork, and exact ribbon layout are restricted evidence. A task-flow spec carries the functional behaviour, which a reviewer can release:

```yaml
task: create-wall-by-two-points
preconditions: [level "Level 1" active, plan view]
steps:
  - intent: start wall tool
  - intent: pick start point # pointer on canvas
  - intent: pick end point
  - intent: finish tool
observable_outcomes:
  - document: +1 wall, base level = Level 1, length = 5000 mm ± 1e-3
  - ui: wall is selected after finish (observed) # functional fact, not layout
  - ui: invalid zero-length pick → warning, no element (observed)
metrics: [step count = 4, modal count = 0, p50 input→stable ≤ X ms]
evidence_refs: [restricted ev_… ids, not released]
```

The reviewer releases the spec without screenshots. The implementation side writes its own scenario script for the clone UI and validates the same `observable_outcomes` and metrics against the clone. Comparisons stay functional (counts, states, errors, timings), so no visual copying is needed and the original-UI rule in M08 holds.

## Validation loop for revit-bim (M06 to M08)

1. **Restricted room:** run the scenario against Revit in the VM with `remote-windows-ui` and the journal and add-in hooks, repeated three times as experiments.md requires. Write the evidence bundle to the restricted volume.
2. **Review room:** turn the observations into task-flow specs. Release them with hashes, following `room-policy.md`'s release procedure.
3. **Implementation room:** build the clone UI on an AccessKit-backed toolkit (egui/eframe or Xilem) so the macOS accessibility tree is real from day one. Pick the toolkit partly on that criterion in the M08 spike.
4. Run the same task-flow spec against the clone with rea's macOS helper (`capture_native_ui_scenario` plus the U1–U5 upgrades), with the semantic hook returning `document-core` state.
5. Compare outcome fields and metrics, not pixels. Use perceptual diffs only clone-against-clone, as visual regression tests between builds.
6. Feed failures into the same repair loop dcomp uses: findings become regression scenarios that every build re-runs automatically.

That turns M08's "usability gates all pass" from a single human review into a CI-able gate, with human review kept for the final candidate.

## Validation loop for dcomp

- An emulator-oracle frame sequence and a native-candidate frame sequence go through the same region and tolerance comparator, with palette-aware exact mode for 8- and 16-bit consoles, where exact equality is achievable.
- Scenario inputs go through two paths: the deterministic control channel for the three automated rounds, and real OS input through rea's helper for at least one round. That proves the release input path works.
- The latency metric (input to first changed frame) is a natural playtest QC signal.
