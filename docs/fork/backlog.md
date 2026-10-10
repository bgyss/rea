# Fork backlog

Ordered by value to dcomp and revit-decomp. Estimates assume one engineer (or a supervised agent) familiar with the codebase. Each item follows `AGENTS.md`: canonical contracts in `src/contracts/`, shared CLI and MCP workflows, tests in the matching Vitest project, and a real-provider verifier for any provider claim.

Legend: **[D]** dcomp, **[R]** revit-decomp or revit-bim, **[U]** UI/UX lane.

## P0: correctness and enabling work

### B1. Detect bound DOS-extender programs

**[D]** · ~1 day · `src/domain/dosMz.ts`, `src/domain/binaryTarget.ts`, `src/application/BinaryTargetResolver.ts`

SimCity 2000's `SC2K.EXE` (1.11 MB) is admitted as `dos-mz`, and Ghidra analyzes only its 59,003-byte DOS4GW real-mode load module. The result reports 312 procedures and no limitation. The LE header is at offset `0x37c3c`, inside the 1.05 MB overlay that `parseDosMzHeader` already measures as `overlayBytes`. Classification reads only a 4 KB prefix.

Fix: when `overlayBytes > 0`, read a bounded window of the overlay. Recognize bound extender layouts (an `LE`/`LX` header reached from the overlay, or a stub followed by a second `MZ` that declares LE/LX). Reject with `unsupported LE executable bound to a DOS extender stub`, or at minimum attach an explicit limitation naming the unanalyzed overlay byte range. Add an authored fixture (a tiny stub plus a fake LE header). Never use the SimCity bytes as a test fixture.

**Status: implemented in commit `79d9fd69` ([PR #1](https://github.com/bgyss/rea/pull/1)).**

- `findBoundLinearExecutable` in `src/domain/dosMz.ts` scans the overlay for an embedded MZ stub whose relative `e_lfanew` selects a structurally plausible LE/LX header (byte and word order, format level 0, CPU and OS fields).
- `BinaryTargetResolver` reads the overlay (at most 64 MiB) for DOS MZ targets and rejects them with both offsets.
- Authored fixtures are in `boundLinearOverlay`, with tests in `src/domain/dosMz.test.ts` and `tests/boundary/filesystem/binaryTarget.test.ts`.
- On the real game files, `SC2K.EXE`, `INTRO.EXE`, `MUNGE.EXE`, `VRF_DLL.EXE` and `WILLTV.EXE` are rejected. `INFO.EXE`, `INSTALL.EXE` and `DOS4GW.EXE` are still admitted.
- Follow-up: artifact inventory (`ArtifactGraphConstruction.ts`) still labels bound files `dos-mz` from its 4 KiB prefix. That is structurally true, but it could carry the bound-program relation.

### B2. Raw image target format

**[D]** · 3–5 days · `src/ghidra/GhidraAnalysisProfile.ts`, `GhidraLauncher.ts`, `bridge/ghidra/ReaGhidraPrepareCom.java` → `ReaGhidraPrepareRaw.java`, `src/contracts/sessionLifecycleInputs.ts`, `src/domain/binaryTargetTypes.ts`, and the ~20 files that mention `dos-com`

Generalize the DOS COM path into `format: "raw-image"` with a required `profile`: language, compiler spec, base address, entry points, an optional memory map (blocks, overlays, permissions, file offsets), and register context. Accept `dcomp.ghidra-profile.v1` verbatim. Include the profile in the canonical analysis-profile digest, so snapshots and evidence bind to it. Verifier: `verify:ghidra:raw` using dcomp's public 6502 and MIPS fixtures, run through both the CLI and MCP.

**Status: v1 implemented in commit `9b44f0d3` ([PR #1](https://github.com/bgyss/rea/pull/1)).** It accepts `dcomp.ghidra-profile.v1` verbatim: one base, one entry, flat image.

- **Domain:** `src/domain/rawImage.ts` holds the schema and layout validation. `resolveExecutableFormatHint` in `src/domain/dosCom.ts` is the single selector-and-profile coupling rule.
- **Target:** a `raw-image` target variant with `rawImage` and no inferred `architecture`. Evidence reports `architecture: null`, and the language ID lives in the analysis profile.
- **Inputs:** MCP `open_binary` takes `format: "raw-image"` plus an inline `raw_image_profile`. The CLI takes `--target-format raw-image --raw-image-profile <file>` on every native analysis command.
- **Ghidra:** BinaryLoader, `-loader-baseAddr`, `-processor` and `-cspec`, plus the `ReaGhidraPrepareRaw.java` pre-script, which seeds the entry. The bridge handshake enforces the declared language and compiler spec. The full profile is part of the analysis-profile digest.
- **Other providers:** Hopper and IDA decline raw images; Windows P0 declines them as non-PE.
- **Verification:** `npm run verify:ghidra:raw` passed on macOS arm64 with Ghidra 12.1.2, using authored 6502 and MIPS fixtures. Unit, boundary, composition and docs checks pass. dcomp's own `nes-nrom-mini` and `ps1-mips-mini` fixtures were also checked by hand through the CLI and MCP; the 6502 entry decompiles to `DAT_0200 = 1; return 0;`.
- **User guide:** [`docs/ghidra-raw-image.md`](../ghidra-raw-image.md).
- **Deferred to B3:** memory maps, multiple entries, overlays and banks, and register context. dcomp's v1 schema has none of these yet, so they need a v2 profile agreed in both repositories.

### B11. Queryable managed metadata

**[R]** · 3–4 days · `src/dotnet/ManagedMemberInspector*.ts`, `src/contracts/managed/`

`inspect_managed_members` emits 231 MB for a 6.5 MB assembly. Add summary-first output: counts per table, namespaces, and the type list. Add explicit selectors (`type`, `namespace`, `member` pattern) and a cursor for `call_edges`, `field_accesses`, and `methods`. Drop the duplicated raw copy when `normalized_result` is lossless. Completeness must still be reported (`complete`, `truncated` with a cursor, or `unknown`), never implied.

### B13. Compact function results

**[D][R]** · 2 days · `analyze_function` envelope

A 63-instruction function returned 179 KB. Add a `facets` selector (`pseudocode`, `cfg`, `instructions`, `xrefs`, `strings`), defaulting to a compact dossier. Keep the full evidence available through `export_evidence_bundle`, so nothing is lost. Check that the token cost changes in representative agent tasks (`src/evaluation/`).

## P1: decomp workflow

### B5. Persistent Ghidra projects and annotation ledger

**[D]** · 1–1.5 weeks

Add an opt-in project mode, keyed by target SHA-256 and profile digest, under a caller-selected private root. Reopen with `-process -noanalysis` (measured 3.8 s instead of a full import). Add an annotation ledger: append-only JSON of `{address_space, address, bytes_sha256, kind, value, author, evidence_ref, at}`. The ledger replays onto fresh imports and refuses entries whose bytes changed. `annotate_native_function`'s `persists_after_close: false` becomes `true` only in this mode, and the contract reports which mode was used.

### B6. Richer annotation operations

**[D]** · 1 week

Function signature and calling convention, data type and struct definitions (C header import through Ghidra's CParser), data labels, local and parameter names, bulk apply, and platform MMIO label packs (NES PPU and APU registers, PS1 hardware registers) as versioned JSON.

### B3. Banked and overlay address identity

**[D]** · 1 week, after B2

Memory-map overlay spaces per bank. Every address-bearing evidence row gains `{space, bank, physical_offset}`. `compare_functions` matches across banks only by bytes and evidence, never by bare CPU address.

### B4. Operator-pinned Ghidra loader extensions

**[D]** · 3–4 days

Like `REA_GHIDRA_NATIVEAOT_JAR`, but for loaders: a configured path plus SHA-256 and a declared loader name, installed into rea's private Ghidra user directory per session. Each loader is `advertised` until a verifier lane with an authored fixture passes.

### B8. Matching-decomp function compare

**[D]** · 1 week

Add `compare_compiled_function` (left: original target function evidence; right: caller-built object file and symbol). It returns an aligned instruction diff with relocation and immediate masking policy, plus a match score and the first divergence. This gives the matching-decomp loop (decomp.me, objdiff) evidence semantics.

### B7. Function ID and signature databases

**[D]** · 3–5 days

Run Ghidra FID or BSim against operator-supplied databases (pinned by digest). Matches are reported as `inferred`, with the database identity attached.

### B9. Encoded string search

**[D]** · 3 days

`search_strings` and `list_strings` gain an `encoding` parameter (`shift_jis`, `euc_jp`, `utf16le`, or a custom `.tbl` file by path and digest), plus a pointer-table candidate scan. Results preserve exact source bytes and offsets (the dcomp M10 catalog requirements).

## P1: UI/UX lane (see [ui-evidence](ui-evidence.md))

### B14. Selector model and node geometry (U1, U2)

**[U][R][D]** · 3–4 days · `src/domain/native/nativeUiObservation.ts`, `bridge/native/ReaNativeUI.swift`

Add `bounds`, `enabled`, `focused`, `selected`, `automation_id` (AXIdentifier), `subrole`, and `stable_key` to nodes. Add selector-based targets alongside `path`.

**Status: implemented on `feat/native-ui-selectors`.**

- **Nodes.** Each node reports `subrole`, `identifier`, `description`, `enabled`, `focused`, `selected`, and `bounds` (window-relative points); unsupported attributes are `null`.
- **Stable keys.** `stable_key` (`uik_` plus 32 hex characters) is derived from the identifier, or role, subrole, title and description, chained through the parent key. Sibling order only breaks ties, and `value` is excluded, so keys survive sibling insertion and value or title changes on identified elements.
- **Selectors.** Element steps take exactly one of `path` or `selector` (`role`, `subrole`, `identifier`, `title`, `description`, `within`, `index`). A selector resolves against the preceding capture and fails without acting on no match, on ambiguity without `index`, or on a truncated capture. The helper re-checks role, subrole, identifier and title at the resolved path (`element-changed`). Each step records the addressed `target: {path, stable_key}`.
- **Verified.** `npm run verify:native-ui` (macOS, real AX and Screen Recording) passes against the extended source-owned fixture: identified, disabled and field elements, a selector-driven key entry and click, an unchanged stable key across a title change, and an ambiguous selector refused before acting. There are 26 unit tests.
- **Not yet.** Selector matching is exact-string only (no regex), and `within` takes one ancestor selector. Path-addressed steps don't re-check identity, so they keep their positional meaning.

### B15. Pointer, keys, wait_for, expect, checkpoint actions (U3–U5)

**[U][R][D]** · 1 week

The scenario union grows as specified. Pointer actions use CGEvent on macOS and `SendInput` on Windows. Every `expect` records pass, fail, or unknown with the nodes and crops it examined.

**Status: keys, wait_for, expect and checkpoint committed in `9200a9f8` (`feat/native-ui-gestures`). System-wide pointer gestures are implemented on `feat/native-ui-pointer`.**

- **Steps.** `keys` posts chords to the selected process only (CGEvent `postToPid`, US ANSI key codes) and reaches its focused element. `wait_for` polls accessibility-only captures (no screenshots, not budgeted) until a condition passes or times out, keeps one capture, and fails the step on timeout. `expect` records pass, fail or unknown on the preceding capture without capturing or stopping. `checkpoint` is a labelled capture.
- **Conditions.** Element `exists`, `absent`, `enabled`, `disabled`, `focused` and `selected`; exact `title`, `value` or `description`; and window title. A truncated capture or an unexposed attribute yields `unknown`.
- **Pointer finding.** Mouse events posted to a process (`postToPid`, any window field or event source, background or foreground) never reached AppKit views, so pointer gestures are system-wide by explicit decision.
- **Pointer safeguards.** Before posting anything the helper:
  - raises the selected window (AXRaise) and activates its application;
  - re-resolves element targets from their live frames and re-checks their identity;
  - requires every event point (start, each drag step, end) to lie inside the window _and_ an accessibility hit test (`AXUIElementCopyElementAtPosition`) there to return an element of that window.

  A window-list topmost check was rejected because the Dock owns an invisible, click-through full-screen window at layer 20. After the gesture, the cursor is restored to within one point (warping snaps to whole points). The previously active application is not restored.

- **Verified.** `verify:native-ui` passes on macOS with real AX: a shift-drag, double-click and right-click on a custom canvas; a system-wide click on a standard `NSButton` (impossible with process-targeted events); a target under a floating window of the same application refused as `point-occluded` with nothing delivered; and the cursor restored. There are 39 native UI unit tests.

### B16. `rea-uia` Windows helper and `remote-windows-ui` provider (U7, U10)

**[U][R]** · 1.5–2 weeks · new `native/rust/rea-uia`, new `src/windows-ui/`

A Rust UIA helper for ARM64 and x64, resident in the guest, using the authenticated TCP transport. It captures the UIA tree, window and modal events, `SendInput` input, and screenshots through Windows Graphics Capture or `BitBlt`. Verifier lane: an authored WPF and WinForms fixture app, with Revit as an operator-only acceptance run.

### B17. Perceptual and region diff, plus latency (U6, U9)

**[U][R][D]** · 1 week · new `native/rust/rea-imgdiff`

Per-region SSIM, masks, element-anchored crops, palette-exact mode, frame-sequence stability detection, and input-to-change latency. Versioned tolerance policies are recorded in the evidence.

### B18. Semantic checkpoint hooks

**[U][R][D]** · 3 days in rea, plus app-side work

A checkpoint can call a declared local hook (socket or command) that returns JSON state. The digest is recorded beside the screenshot. App-side work: a revit-bim `automation` crate, a Revit documented-API add-in or journal reader in the restricted room, and dcomp's native control channel.

## P2: breadth

- **B10. LE/LX/NE loading** [D]: an operator-pinned Ghidra extension or a Rust pre-import normalizer that feeds B2. Unlocks DOS4GW-era PC titles and Win16 games.
- **B12. C++/CLI managed to native mapping** [R]: map mixed-mode method tokens to native thunks through the VTFixup and `IMAGE_COR20_HEADER` data, reported as `observed` only when the bridge structure is present.
- **B19. `ghidra-session` Rust crate** [D]: lives in dcomp. Pins `ReaGhidraBridge.java` by digest. See [rust-strategy](rust-strategy.md#targeted-rust-components).
- **B20. Windows ARM64 host support** [R]: build rea's Node-API Windows bundle for ARM64, so the full rea can run inside the guest if needed. Lower priority than B16 because the Mac-hosted path covers static analysis.
- **B21. Upstream sync automation**: a scheduled `git fetch upstream` plus `check:changed` on a merge branch, so the fork never drifts more than a few days.

## Ghidra performance (instead of porting Ghidra)

Rewriting Ghidra in Rust isn't worthwhile ([rust-strategy](rust-strategy.md#porting-ghidra-itself)). These two items capture the measurable wins. The evidence is in [measurements: Ghidra startup and analysis experiments](measurements.md#ghidra-startup-and-analysis-experiments).

### B22. Rust SLEIGH/p-code lifter for dcomp

**[D]** · spike 1 week, then per-ISA work · lives in dcomp, not rea

Give dcomp's static-recompilation lane one Rust lifter driven by Ghidra's own SLEIGH processor specs, instead of a hand-written front end per console. Ghidra stays the analysis oracle (functions, CFG, banks, through rea or `ghidra-session`). The Rust side does fast, parallel, deterministic instruction-to-p-code lifting and emits AOT code.

1. **Spike.** Evaluate icicle-emu's `sleigh` runtime (Rust, MIT or Apache-2.0, a custom SLEIGH runtime that parses and compiles SLEIGH specifications). Lift dcomp's authored 6502 (`nes-nrom-mini`) and MIPS (`ps1-mips-mini`) fixtures. Record the crate revision, the Ghidra spec version it reads, and its licence. If it isn't suitable, fall back to Ghidra's own `libsla` C++ through FFI (also Apache-2.0).
2. **Cross-check gate.** For every instruction, the Rust lifter's p-code must equal Ghidra's p-code (`Instruction.getPcode()`, exported by an added bridge operation or `export_facts.py`) for the same spec revision. Treat disagreements as blocking test cases, not as tolerance.
3. **Translator.** Replace the hand-written NROM instruction cases in `crates/dcomp-core/src/nes_translate.rs` with p-code to Rust emission behind the existing translation profile and report schemas. Keep `zero fallback` and checkpoint-exact oracle comparison as the acceptance tests.
4. **Next ISAs, by lane need:** MIPS R3000A (PS1, M3/M4), 65816 (SNES, through a community SLEIGH spec once qualified), SH-2 (Saturn, M9).

Success: the arithmetic and branch NROM slices reproduce their current MesenCE and FCEUmm RAM checkpoints from p-code-generated Rust, and the MIPS fixture lifts with zero p-code mismatches against Ghidra.

### B23. Platform analysis profiles and analysis tuning

**[D][R]** · 3–4 days in rea, after B2 · `src/ghidra/GhidraAnalysisProfile.ts`, `GhidraLauncher.ts`, the new `ReaGhidraPrepareRaw.java`

Make the analyzer set part of the committed analysis profile (and so part of its digest) instead of always using `analyzer_preset: "ghidra-default"`:

- Named presets per platform (`dos-16`, `nes-6502`, `ps1-mips`, `win-pe-x64`), each listing enabled and disabled analyzers and their options. Set them through a pre-script using `setAnalysisOption`, the mechanism the experiments used.
- **Keep Decompiler Switch Analysis on by default.** It is the single most expensive analyzer on the measured DOS targets, but turning it off lost every resolved jump table and the code reached through them ([measurements](measurements.md#ghidra-startup-and-analysis-experiments)). Offer a `fast-triage` preset that disables it, explicitly labelled, with a limitation stating that jump tables are unresolved.
- Record each analyzer's time from Ghidra's analysis summary in the session evidence, so slow analyzers on real targets are visible without a separate experiment.
- Track the 16-bit segmented decompiler exception (`AddressOutOfBoundsException` from `SegmentedAddressSpace.getAddress` during switch analysis on `INSTALL.EXE`) as an upstream Ghidra issue. Until it's fixed, mark affected functions' switch recovery as `unknown`.
- **Don't spend effort on JVM tuning.** Re-enabling class-data sharing, an AppCDS archive, and raising the launcher's GC and JIT thread caps were all within run-to-run noise. Ghidra's own class loader keeps about 5,800 classes out of any archive.

## Suggested order

1. B21 (remote setup only), then B1, B13, and B2. Two weeks; these unblock dcomp's interactive use.
2. B14, B15, B17. Two to three weeks; macOS UI lane complete, ready for revit-bim's M08 spike.
3. B16 and B18. Two to three weeks; Revit oracle capture, gated on revit-decomp M00 and M01.
4. B5, B6, B3, B8. Three to four weeks; durable decomp workflow.
5. B11 and B12 when revit-decomp M03 approves managed questions. B4, B7, B9, and B10 as dcomp lanes need them.
