# Using this fork with revit-decomp and revit-bim

`~/src/revit-decomp` is the planning repository: legal research, room policy, milestones M00–M10, and the experiment catalogue. `~/src/revit-bim` is the clean implementation room: `document-core` and `document-geometry` (Manifold), M04 and M05 done, with no UI and no IFC yet. The user authorized, on 2026-10-07, reverse-engineering inspection of Revit binaries with **documentation only** as output; raw decompiler output never leaves the restricted room.

That policy decides where this fork may run and what may leave it. Read [room separation](#room-separation-rules-for-rea) before using any tool below.

## Where rea fits each milestone

| Milestone                              | rea role                                                                                                                                     | Tools                                                                                                                                                                                         |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M01 Qualify the VM oracle              | Inventory installed modules (managed or native, mixed-mode, P/Invoke surface) without loading code; check that the UI automation tree exists | `inspect_artifact`, `inspect_managed_artifact`, `inspect_managed_native_boundaries`, and the future `remote-windows-ui` ([ui-evidence](ui-evidence.md#3-windows-ui-automation-helper-u7-u10)) |
| M02 Public domain model                | Compare public Revit API reference assemblies to the documented API, without decompiling                                                     | `inspect_managed_members` (after B11 makes its output queryable), `compare_managed_members`                                                                                                   |
| M03 Bounded restricted analysis        | Answer one approved question at a time with evidence. A reviewer turns the evidence into released specifications                             | Ghidra on macOS for native DLLs, the managed reader, and optionally ILSpy through `REA_ILSPY_CMD_PATH`                                                                                        |
| M06 Headless vertical slice comparison | Compare the clone's document state to the oracle's on synthetic models                                                                       | Evidence comparison, plus semantic hooks ([ui-evidence §5](ui-evidence.md#5-app-specific-semantic-hooks))                                                                                     |
| M08 Original macOS UI                  | Machine-checkable task-flow validation of the clone UI on macOS                                                                              | `capture_native_ui_scenario` with the U1–U6 upgrades and AccessKit in the clone                                                                                                               |
| M10 Release qualification              | Evidence bundles become the qualification record                                                                                             | `export_evidence_bundle`, `compare`, completion ledger                                                                                                                                        |

## Facts established in this session

- **PE DLLs work on a macOS host.** `rea inspect` with Ghidra on an x64 PE32+ DLL returned 399 procedures in 23 s. The Windows P0 boundary rejects DLLs (`inspectWindowsP0TargetSupport` in `src/ghidra/GhidraProvider.ts`), but the macOS and Linux path does not. Most of Revit's code lives in DLLs, so run native analysis on the Mac against copies on a restricted evidence volume, not inside the guest. This also avoids rea's x64-only Windows native bundle on what is almost certainly a Windows ARM64 guest (Apple Silicon host; confirm the guest architecture in M01).
- **Managed metadata scales badly as a single response.** A 6.5 MB assembly produced 231 MB of JSON in 8.7 s ([measurements](measurements.md#managed-net-metadata-reader)). Revit's API and DB assemblies will be larger. Backlog B11 (query and paging, plus a summary-first output) is a prerequisite for using the managed tools on Revit at all.
- **Mixed-mode C++/CLI** is partially modelled: rea records the managed declarations and mixed-mode flags. It does not map a managed member to its native body without explicit bridge evidence (`docs/managed-code-analysis.md`). Revit relies heavily on C++/CLI, so that mapping gap (B12) is where native-boundary questions will stall.

## Room separation rules for rea

rea output contains disassembly, pseudocode, and IL. Under `room-policy.md` that output is **restricted evidence**:

1. **Run rea only in the restricted room.** That means the VM, or a dedicated macOS user account or volume holding the module copies. Set `TMPDIR` and rea's private runtime roots to that volume; rea's Ghidra projects and snapshots are written there and deleted on close.
2. **Any agent session that called rea on Revit modules is exposed.** Don't reuse it, its memory, or its transcripts for revit-bim work. Keep the MCP registration out of the implementation repository's agent config entirely. A project-scoped `.mcp.json` in the restricted workspace only is a simple guard.
3. **Evidence bundles stay restricted.** The review room derives functional specifications from them (units, invariants, error conditions, task flows). Released packets cite only restricted evidence IDs, never the content.
4. **No cloud.** rea is local-only by design. Keep it that way for this lane: no hosted model reads restricted output unless the rights and service-data decision in M00 explicitly allows it.
5. **Prefer black-box observation.** UI scenarios, the journal, and documented-API add-in output answer most behavioural questions without disassembly, and they're legally lighter. Reach for Ghidra or IL only when a specific approved question can't be answered from behaviour.

## Concrete next steps

1. Fix VM access first (revit-decomp `current-status.md`: PowerShell inventory failed or hung). Deploy the resident `rea-uia` helper ([ui-evidence §3](ui-evidence.md#3-windows-ui-automation-helper-u7-u10)) to bypass `prlctl exec` instability; its first job is a read-only inventory script.
2. Build the module inventory on the restricted volume. For each file, run `inspect_managed_artifact` (managed or not, mixed-mode, references) and `inspect_managed_native_boundaries` (P/Invoke and native exports). Store the evidence bundle. This answers "which modules are .NET, which native, which C++/CLI" without decompiling anything.
3. Write the first three task-flow scenarios from experiments E02, E04, and E05 (placement, atomicity, undo/redo) and capture them three times against Revit. Use the journal or add-in hook for document state.
4. In revit-bim, add an `automation` crate exposing the document semantic hash, selection, and undo depth over a local socket. Pick the M08 UI toolkit with AccessKit support as a gating criterion.
5. Replay the released task-flow specs against the clone as automated tests, then human review on the final candidate (M08 acceptance).
