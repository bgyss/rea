# Using this fork with dcomp

dcomp (`~/src/dcomp`) is a Rust, Nix, and mise evidence factory for native game reconstruction. Ghidra is its standard static-analysis adapter (decision D15), and its `dcomp.adapter.v1` subprocess JSON protocol comes before any MCP (D05). It currently runs PyGhidra once per probe (`crates/dcomp-cli/src/ghidra.rs`, `ghidra_scripts/export_facts.py`) on raw images described by `dcomp.ghidra-profile.v1`: language, compiler spec, loader, load address, and entry.

## What rea offers dcomp

| rea capability                                                                                                                            | dcomp use                                                                                                                                                                              | Fit                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Long-lived Ghidra bridge (`bridge/ghidra/ReaGhidraBridge.java`, newline-delimited JSON over an authenticated Unix socket or loopback TCP) | Interactive agent exploration, such as finding the NMI handler or the bank-switch routine, with warm queries in milliseconds instead of a 5 s or longer PyGhidra relaunch per question | Strong, once raw-image profiles exist                                                                                                        |
| Evidence model (`observed`, `inferred`, `unknown`, digests, provider identity, analysis profile digest, limitations)                      | Maps onto dcomp's split of candidate Ghidra facts vs verified oracle evidence vs human-confirmed labels                                                                                | Strong. Import rea evidence as candidate facts only                                                                                          |
| `analyze_function`, CFG, references, `resolve_native_call_targets`, `compare_functions`                                                   | Translation seeds, jump-table recovery, regional-revision diffs (Policenauts PS1, Saturn, 3DO)                                                                                         | Strong                                                                                                                                       |
| `annotate_native_function`                                                                                                                | Naming during exploration                                                                                                                                                              | Weak today. Name and comments only; doesn't persist after close                                                                              |
| Process capture (`capture_process_scenario`, `compare_process_captures`)                                                                  | Wrapping emulator CLIs, but dcomp already has stronger oracle adapters                                                                                                                 | Low                                                                                                                                          |
| Native UI scenarios                                                                                                                       | Final QC rounds through real OS input on native candidates                                                                                                                             | Medium, after the [UI upgrades](ui-evidence.md)                                                                                              |
| Firmware extraction (binwalk, unblob)                                                                                                     | Disc and archive carving for PS1 BIN/CUE, Saturn, and PC-98 images                                                                                                                     | Medium. dcomp's material intake already streams media                                                                                        |
| DOS MZ and COM profiles                                                                                                                   | PC-98 and DOS-era titles                                                                                                                                                               | Partial. LE/LX/NE (DOS4GW, Win16) are missing, and bound LE is misreported (see the [SC2K finding](measurements.md#ghidra-provider-latency)) |

## Gaps to close in the fork, in game-specific priority order

1. **Raw image profiles** (backlog B2). Generalize the DOS COM path (`ReaGhidraPrepareCom.java`, `ghidraHeadlessArguments` in `GhidraLauncher.ts`, `GhidraAnalysisProfile.ts`) into a `raw-image` target format. The caller supplies `processor_language_id`, `compiler_spec_id`, `base_address`, `entry_points[]`, an optional `memory_map[]` (named blocks with file offset, address, length, permissions, and overlay space), and initial register context. Accept dcomp's `dcomp.ghidra-profile.v1` JSON as-is, so one profile file serves both tools and the profile digest matches across them.
2. **Banked and overlay address identity** (B3). NES PRG banks, SNES HiROM/LoROM mirrors, and PS1 overlays need Ghidra overlay spaces. rea already keeps space-qualified addresses such as `HEADER:0x0` and `EXTERNAL:0x1`. Put `bank:physical_offset` into every address-bearing evidence row, to satisfy dcomp's D11 ("exact revision plus bank, image, and content identities").
3. **Loader extensions** (B4). Allow operator-pinned Ghidra loader extensions by path and SHA-256 digest, the same way `REA_GHIDRA_NATIVEAOT_JAR` pins an analysis extension. Typical candidates are an iNES/NES loader, a PS-X EXE loader with PsyQ support, an N64 loader, and a Switch NSO/NRO loader. Each enters as `advertised`, and only a verifier lane with an authored fixture promotes it.
4. **Persistent annotated projects** (B5). A decomp effort accumulates names, types, and signatures for weeks. Add a project mode in which the profile digest and target SHA-256 select a persistent Ghidra project under the caller's private root (`.dcomp/ghidra-projects/<sha>`). Reopen it with `-process -noanalysis`; that measured 3.8 s instead of a full re-analysis. Pair it with an **annotation ledger**: an append-only JSON log of `{address, bytes_digest, kind, value, author, evidence_ref}` that replays onto a fresh import. Then dcomp can version labels in Git-safe form without committing Ghidra databases.
5. **Richer annotations** (B6). Function signatures, data types and structs (C header import), data labels, local variable names, and bulk apply. Add a `memory`-scoped label for MMIO registers, so that `$2000`–`$4017` on the NES and the PS1 hardware registers come pre-named from a platform profile.
6. **Function ID and signature libraries** (B7). Run Ghidra's FID or BSim against operator-supplied SDK signature databases (PsyQ, libultra, Nintendo SDK). Report each match as `inferred` with its database digest. This names SDK functions before an agent spends any effort on them.
7. **Matching-decomp diff** (B8). Add a `compare_compiled_function` tool. Given a candidate object file and symbol (built by the caller's toolchain) and an original target function, it returns an instruction-level diff with relocation masking and a score. This is the decomp.me and objdiff loop. It gives dcomp's readable-decompilation lane a mechanical "this C reproduces those bytes" check that is stronger than trace agreement for straight-line code.
8. **Text and encoding search** (B9). `search_strings` with explicit encodings (Shift-JIS, EUC-JP, custom `.tbl` character tables) and pointer-table discovery. This feeds M10 localization, and Policenauts is Japanese text throughout.
9. **LE/LX/NE** (B1, B10). Detect DOS-extender and Win16 programs correctly now. Add loaders later, either through an operator-pinned Ghidra LE/LX loader extension or a rea-owned loader.

## Integration shape (recommended)

Keep dcomp's D05 decision (subprocess JSON before MCP) and add rea alongside, not underneath:

```text
agents ──MCP──> rea (this fork)            exploratory, interactive RE
                  │ evidence bundles (export_evidence_bundle)
                  ▼
dcomp-cli import-rea-evidence ──> SQLite/CAS as "candidate static facts"
                                    (never oracle evidence, never verified)
dcomp deterministic pipeline: ghidra probe → translate → oracle compare → QC
```

Concrete steps:

1. **Shared profile.** Make `dcomp.ghidra-profile.v1` the input format for rea's `raw-image` target (B2). Add a test in each repository that the same profile digest is computed from the same bytes.
2. **`dcomp-cli rea import`.** Read an exported rea evidence bundle, check `subject.digest.sha256` against the revision key, check that `provider.version` and `analysis_profile` match the pinned lane, then store rows as candidate facts with `confidence` preserved. Reject bundles whose profile disagrees, rather than coercing them.
3. **Optional Rust Ghidra session client.** Don't run rea's Node server inside dcomp jobs. Instead, vendor `ReaGhidraBridge.java` (pinned by digest) and write a small Rust client crate. The wire protocol is about 60 lines of schema (`src/ghidra/protocol.ts`), and the launch arguments are in `ghidraHeadlessArguments`. dcomp workers then get warm, persistent sessions without Node, under dcomp's own supervisor and lease model. See [rust-strategy](rust-strategy.md#targeted-rust-components).
4. **Agent ergonomics.** Register this fork's MCP server in dcomp's agent environment for M2 and M3 discovery work, such as mapping an NES title's banks or finding the PS1 overlay loader. Agents read evidence through MCP. The pipeline only trusts what passes through step 2 and the oracle comparison.

## UI and QC

See [ui-evidence](ui-evidence.md#validation-loop-for-dcomp): frame-sequence comparison with palette-aware tolerance, held-key input actions, input-to-frame latency, and one real-OS-input QC round per host through rea's native UI helper.

## What not to take from rea

- Its delivery and installer machinery (`rea setup`, agent registration). dcomp has Nix and mise.
- Hopper and IDA providers. dcomp standardizes on Ghidra, though IDA could be a qualified second static adapter under D15.
- Browser, JavaScript, Android, and EVM providers. They're irrelevant to dcomp and add size only.
