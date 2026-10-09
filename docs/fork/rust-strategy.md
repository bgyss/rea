# Should this fork be ported to Rust?

**Recommendation: no full port. Keep the TypeScript core tracking upstream, and add Rust where measured CPU or OS work dominates, or where dcomp needs the pieces without Node.**

## Size of the port

| Area               | Lines (non-test TS)                       |
| ------------------ | ----------------------------------------- |
| `src/domain/`      | 57,895                                    |
| `src/application/` | 30,278                                    |
| `src/browser/`     | 14,436                                    |
| `src/native/`      | 8,232                                     |
| `src/artifacts/`   | 7,544                                     |
| `src/contracts/`   | 6,697                                     |
| `src/process/`     | 6,339                                     |
| `src/ghidra/`      | 6,107                                     |
| `src/dotnet/`      | 5,962                                     |
| everything else    | ~26,500                                   |
| **Total**          | **~170,000**, plus ~75,000 lines of tests |

There are also 138 MCP tools with generated JSON schemas, the browser and Playwright providers, Node-API Windows controls, and the Java, Python, and Swift bridges. Those bridges would stay in their own languages regardless.

## Where time actually goes

From [measurements](measurements.md):

1. **Ghidra JVM startup, about 3.8 s per process**, and auto-analysis (seconds for small targets, minutes for game or Revit binaries). Node isn't involved. The fixes are keeping the process alive (rea's MCP server already does) and keeping the analyzed project ([B5](backlog.md#b5-persistent-ghidra-projects-and-annotation-ledger)).
2. **Response volume**: 179 KB for one small function, and 231 MB for one managed assembly. Run time grows with output size. A Rust serializer would make 231 MB faster to produce, but it would still be 231 MB that no agent can read. The fix is result design: summary-first output, cursors, and field selection ([B11](backlog.md#b11-queryable-managed-metadata), [B13](backlog.md#b13-compact-function-results)).
3. **Warm queries** take 1–110 ms, with the JVM doing the work. A Node to Rust swap of the client saves microseconds.

So a Rust rewrite targets the part of the system that isn't slow.

## Cost of diverging

Upstream had 17 new commits in about one day, from five or more active authors ([measurements](measurements.md#upstream-velocity)). They're mostly boundary-correctness fixes. A Rust rewrite turns this fork into a separate product that can't merge any of them. Keep the fork **additive**: new providers, new tools, and helper binaries in new directories, with minimal edits to shared files. Then `git fetch upstream && git merge upstream/main` stays routine.

Set up the upstream remote once:

```sh
git remote add upstream https://github.com/morluto/rea.git
git fetch upstream
```

## Targeted Rust components

Each of these is self-contained, sits behind an existing subprocess or helper seam, and is either CPU or OS bound, or reusable from dcomp and revit-bim without Node.

| Component                                 | Why Rust                                                                                                                                                                                                             | Seam in rea                                                                                        | Also used by                                        |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `rea-uia`: Windows UI Automation helper   | COM and UIA bindings through the `windows` crate. Builds for ARM64 and x64. No .NET or Node in the guest                                                                                                             | Same JSON request and response as `bridge/native/ReaNativeUI.swift`                                | revit-decomp oracle capture                         |
| `rea-imgdiff`: perceptual region diff     | SSIM, masks, crops, palette-exact mode, frame-sequence stability. Pure CPU                                                                                                                                           | Replaces `src/browser/PngVisualDiff.ts`'s inner loop. Called as a helper process or Node-API addon | dcomp frame comparison, revit-bim visual regression |
| `ghidra-session` crate                    | A Rust client for `ReaGhidraBridge.java`: the 60-line wire schema, launch arguments, descriptor, and token                                                                                                           | None in rea; it's dcomp's warm Ghidra path                                                         | dcomp workers                                       |
| Managed metadata reader (optional, later) | Only if B11's streaming design is still too slow. Evaluate existing crates first (`object` or `pelite` for PE, and a CLI-metadata crate such as `dotscope`; check that it is maintained) before writing a new reader | `src/dotnet/` behind `ManagedStaticProvider`                                                       | revit-decomp M01 inventory                          |
| LE/LX loader prototype (optional)         | Parse and normalize LE/LX into a raw-image memory map that Ghidra imports through B2's `raw-image` path                                                                                                              | Pre-import transform in `src/ghidra/`                                                              | dcomp DOS-era titles                                |

Build them as a small Cargo workspace inside the fork (`native/rust/`), managed alongside the existing `native/windows` Node-API project. Pin them by digest the way rea already pins its bridge scripts. Ship prebuilt binaries per host target, or build them through dcomp's Nix shell.

## Porting Ghidra itself

Not worthwhile. Ghidra is well over a million lines of Java, plus the C++ decompiler and SLEIGH specs for more than 100 processors. A port would discard its GUI, scripting API, extension ecosystem (including the console and LE/LX loaders dcomp needs), years of per-processor correctness, and its regular upstream releases. dcomp's D15 depends on Ghidra being the qualified tool. The measured costs point elsewhere:

| Cost                            | Measured                                                     | Better fix than a Rust port                                                                                                                                                                     |
| ------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| JVM and Ghidra startup          | ~2.3–2.9 s "headless startup" and ~3.8 s whole-process floor | A persistent session (rea MCP already does this). The AppCDS result is in [measurements](measurements.md#ghidra-startup-and-analysis-experiments)                                               |
| Auto-analysis                   | Dominated by Decompiler Switch Analysis on the DOS targets   | Platform analysis presets ([B23](backlog.md#b23-platform-analysis-profiles-and-analysis-tuning)) and persistent projects ([B5](backlog.md#b5-persistent-ghidra-projects-and-annotation-ledger)) |
| Decompiler                      | Already a native C++ process                                 | Nothing to port                                                                                                                                                                                 |
| Throughput across many binaries | One JVM per target                                           | Parallel headless workers under dcomp's lease model                                                                                                                                             |

Where Rust and Ghidra do belong together is the **SLEIGH/p-code lifter for dcomp's translator** ([B22](backlog.md#b22-rust-sleighp-code-lifter-for-dcomp)). That is the hot, repetitive, factory-scale path, and Ghidra's specs give it one instruction-semantics source for every console, cross-checked against Ghidra itself.

## When a fuller port would make sense

Revisit if all three of these become true:

1. dcomp's factory needs rea's domain logic (evidence, comparison, completion ledgers) inside Rust workers at scale, rather than as imported bundles.
2. Upstream activity slows, or diverges from game and BIM needs, so that merging stops paying for itself.
3. A measured profile shows Node CPU time, rather than JVM or serialization, dominating a real workload.

Even then, port in layers. Start with `src/domain/` evidence, digest, and comparison semantics (pure and well tested, so the tests can be translated as golden fixtures). Bridges and providers come last, if ever.
