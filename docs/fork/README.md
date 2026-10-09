# Fork notes: REA as the base for game and BIM reverse engineering

Written 2026-10-08 for `bgyss/rea`, the personal fork of `morluto/rea`. It evaluates how this fork can serve `~/src/dcomp` (native game reconstruction) and `~/src/revit-decomp` with `~/src/revit-bim` (an independent Rust BIM application from clean-room specifications). It also covers UI/UX observation and validation, and whether to port to Rust.

## Verdict

| Question                                     | Answer                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Use rea as a base, or just as inspiration?   | **As a base for interactive, evidence-producing RE, alongside dcomp's deterministic pipeline, not underneath it.** rea's Ghidra bridge, evidence model, and MCP surface are directly reusable. Its delivery machinery and unrelated providers (browser, Android, EVM) are not needed.                    |
| Is it good with video game material today?   | **Partly.** Mainstream formats (PE, ELF, Mach-O, DOS MZ) work. Raw console images are rejected outright. DOS4GW games are silently misanalysed. Annotations don't persist. See [measurements](measurements.md) and the [dcomp gaps](dcomp.md#gaps-to-close-in-the-fork-in-game-specific-priority-order). |
| Is it useful for Revit?                      | **Yes, for static work on macOS today.** PE DLLs analyse with Ghidra on the Mac, and managed and mixed-mode inventory works without loading code. Two caveats: the managed member output must become queryable first, and every use must follow the room policy ([revit](revit.md)).                     |
| Can it fix revit's UI/UX validation problem? | **It's the best available starting point**, after a targeted set of upgrades: stable selectors, pointer, wait, and assert actions, a Windows UIA helper, perceptual diffs, and semantic hooks. Those turn UI behaviour into machine-checkable task-flow evidence ([ui-evidence](ui-evidence.md)).        |
| Port to Rust?                                | **No full port.** Ghidra JVM time and response volume dominate, not Node, and upstream moves too fast to give up merges. Add Rust where it pays: the Windows UIA helper, the image diff, and a Ghidra session client for dcomp ([rust-strategy](rust-strategy.md)).                                      |

## Top recommendations

1. **Add the upstream remote and keep the fork additive** ([rust-strategy](rust-strategy.md#cost-of-diverging)).
2. **Fix bound DOS-extender misclassification** (B1). It's a silent wrong answer on real game binaries.
3. **Add a `raw-image` target that accepts `dcomp.ghidra-profile.v1`** (B2), so rea and dcomp share one profile and one digest.
4. **Shrink responses**: function facets (B13) and queryable managed metadata (B11). Agents can't use 179 KB or 231 MB responses.
5. **Upgrade the native UI lane**: selectors and geometry (B14), and pointer, wait, expect, and checkpoint steps (B15). This immediately benefits revit-bim's M08 on macOS.
6. **Build `rea-uia` in Rust** for the Windows ARM64 guest, with a resident authenticated transport instead of `prlctl exec` (B16).
7. **Add perceptual region diffs and latency** (B17), and **semantic checkpoint hooks** (B18). In revit-bim, add an `automation` interface returning the document semantic hash.
8. **Persistent Ghidra projects plus an annotation ledger** (B5) and richer annotations (B6), the basis of any long-running decomp.
9. **Matching-decomp compare** (B8), FID and signature databases (B7), and Shift-JIS/`.tbl` string search (B9) for dcomp's readable-source and localization goals.
10. **In revit-decomp: run rea only in the restricted room**, treat agent sessions that used it as exposed, and prefer black-box UI and journal evidence over disassembly ([revit](revit.md#room-separation-rules-for-rea)).

## Documents

- [Measured baseline](measurements.md): latencies, output sizes, and what was rejected or misreported.
- [UI/UX observation and validation](ui-evidence.md): gaps U1–U10, the design, and validation loops for revit-bim and dcomp.
- [dcomp integration](dcomp.md)
- [revit-decomp and revit-bim integration](revit.md)
- [Rust strategy](rust-strategy.md)
- [Backlog](backlog.md): B1–B21 with files, estimates, and order.

## Local setup used for this evaluation

```sh
export GHIDRA_INSTALL_DIR=<nix store>/ghidra-12.1.2/lib/ghidra   # rea admits 12.1.x
export JAVA_HOME=<nix store>/zulu-ca-jdk-21.0.11                  # JDK 17 is rejected
npm ci && npm run build:cached
node scripts/rea.mjs doctor --provider ghidra --json
```

Node 24.12.0 worked, although `.nvmrc` pins 24.18.0. Hopper and IDA were not configured, and nothing was installed or changed outside this repository.
