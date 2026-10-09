# Measured baseline (2026-10-08)

Everything below was run on this fork at `c3136064`. Unless a row says otherwise, the host was macOS on Apple Silicon (darwin arm64) with Node 24.12.0, Ghidra 12.1.2 from the Nix store, and Zulu JDK 21.0.11. These are single runs with a warm filesystem cache, not statistically controlled benchmarks. Use them to rank work, not as performance claims.

## Ghidra provider latency

| Scenario                                                    | Target                                 | Wall time        | Notes                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------------------------- | -------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One-shot CLI `rea inspect`                                  | 50 KB arm64 Mach-O (authored C sample) | 12.2 s           | New JVM, import, auto-analysis, and teardown on every CLI call                                                                                                                                                                                                                                                                                  |
| One-shot CLI `rea search`                                   | same                                   | 9.7 s            | Same full cold path; the CLI shares nothing between calls                                                                                                                                                                                                                                                                                       |
| MCP `open_binary`                                           | same                                   | 1.9 s            | Admission and snapshot only; Ghidra starts lazily                                                                                                                                                                                                                                                                                               |
| MCP first `list_procedures`                                 | same                                   | 8.3 s            | JVM, import, and auto-analysis are paid here                                                                                                                                                                                                                                                                                                    |
| MCP warm `list_procedures`, `list_strings`, `list_segments` | same                                   | 1–10 ms          | Served by the live bridge                                                                                                                                                                                                                                                                                                                       |
| MCP warm `analyze_function` (63 instructions)               | same                                   | 60–110 ms        | **179 KB** JSON response                                                                                                                                                                                                                                                                                                                        |
| MCP warm `procedure_pseudo_code`                            | same                                   | 10 ms            | 4.7 KB                                                                                                                                                                                                                                                                                                                                          |
| MCP `close_binary`                                          | same                                   | 0.5 s            | Deletes the temporary project                                                                                                                                                                                                                                                                                                                   |
| CLI `inspect`, DOS MZ                                       | SimCity 2000 `INFO.EXE` (17 KB code)   | 12.3 s           | 129 procedures                                                                                                                                                                                                                                                                                                                                  |
| CLI `inspect`, DOS4GW bound LE                              | SimCity 2000 `SC2K.EXE` (1.11 MB)      | 17.6 s           | **Analyzed only the 59,003-byte real-mode stub.** It reported 312 procedures with no limitation. The LE header sits at file offset `0x37c3c`. Fixed in [PR #1](https://github.com/bgyss/rea/pull/1) ([B1](backlog.md#b1-detect-bound-dos-extender-programs)): admission now rejects it in 0.8 s, naming the embedded stub and LE header offsets |
| CLI `inspect`, PE32+ x64 DLL                                | `libsoundio.dll`                       | 23.3 s           | 399 procedures. A macOS host accepts PE DLLs; the Windows P0 boundary rejects them                                                                                                                                                                                                                                                              |
| CLI `inspect`, raw MIPS image                               | dcomp `ps1-mips-mini.bin`              | 0.8 s (rejected) | `unsupported binary format`. No way to supply a language, base address, or entry point                                                                                                                                                                                                                                                          |

### Raw `analyzeHeadless` floor

| Step                                                  | Target     | Wall time |
| ----------------------------------------------------- | ---------- | --------- |
| `-import` with auto-analysis, project kept            | `INFO.EXE` | 7.5 s     |
| `-process -noanalysis -readOnly` on that kept project | `INFO.EXE` | 3.8 s     |
| `-import` with auto-analysis                          | C sample   | 4.6 s     |
| `-process -noanalysis -readOnly`                      | C sample   | 3.9 s     |

About 3.8 s of every Ghidra process is JVM and Ghidra startup that no client language can remove. Auto-analysis is cheap for these small targets. For a 10–100 MB game executable or a large Revit DLL it takes minutes, and that cost is repeated every time rea opens the target, because rea runs `-readOnly -deleteProject` (`src/ghidra/GhidraLauncher.ts`).

## dcomp's Ghidra path, for comparison

| Scenario                                                                                    | Wall time                              |
| ------------------------------------------------------------------------------------------- | -------------------------------------- |
| `nix develop path:./ --command true` (shell evaluation only)                                | 5.8 s                                  |
| `dcomp-cli ghidra probe` on the 12-byte PS1 fixture, warm Cargo build, inside `nix develop` | 11.2 s total, so about 5.4 s of Ghidra |
| Same probe on a cold Cargo build                                                            | 34.6 s                                 |

dcomp starts a fresh PyGhidra JVM for every probe, by design. That is fine for its deterministic fact export, but interactive exploration through it costs about 5 s or more per question.

## Managed (.NET) metadata reader

`Microsoft.CodeAnalysis.CSharp.dll` (Roslyn, 6.5 MB), pure-TypeScript reader, no .NET runtime:

| Command                             | Wall time | Output size |
| ----------------------------------- | --------- | ----------- |
| `inspect-managed-artifact`          | 1.2 s     | 11 MB       |
| `inspect-managed-native-boundaries` | 1.0 s     | 26 KB       |
| `inspect-managed-members`           | 8.7 s     | **231 MB**  |

The 231 MB contains `methods` (88 MB, 41,394 rows), `call_edges` (41 MB, 177,538 rows), `field_accesses`, `fields`, and `member_refs`. Raw and normalized copies are both present. Run time grows with output size, not input size. So the bottleneck is building and serializing the result, not parsing PE/CLI metadata. No agent can consume that response for a large assembly such as `RevitAPI.dll`.

## Ghidra startup and analysis experiments

Question: if Ghidra isn't ported to Rust, how much can be won by tuning analysis or the JVM? Measured with raw `analyzeHeadless` (no rea), using `MzLoader` and `x86:LE:16:Real Mode` on three SimCity 2000 SE DOS executables:

- `INFO.EXE` (29 KB)
- `INSTALL.EXE` (83 KB)
- `SC2K.EXE`, whose 59 KB DOS4GW stub is the only part Ghidra loads. This was the B1 misclassification; the fork now rejects this file.

Hardware was an Apple M1 Max (8 performance and 2 efficiency cores). Each cell is three runs. A post-script counted functions, instructions, computed jumps with more than one resolved flow target ("resolved jump tables"), and defined data.

Modes:

- **base**: Ghidra's default analyzers.
- **t1**: Decompiler Switch Analysis disabled through a pre-script (`setAnalysisOption`).
- **t2**: t1, plus Apply Data Archives, Stack, Embedded Media, Demangler GNU, Function ID, Non-Returning Functions (Discovered) and Shared Return Calls disabled.
- **floor**: `-noanalysis` (JVM, import, and teardown only).
- **cds-jdk**: re-enable the JDK's default class-data sharing. Ghidra's `launch.properties` sets `-Xshare:off`; passed `-Xshare:auto` through `GHIDRA_HEADLESS_JAVA_OPTIONS`.
- **cds-app**: a dynamic AppCDS archive from a full analysis run.
- **jit**: override the launcher's `-XX:ParallelGCThreads=2 -XX:CICompilerCount=2` with 10 and 5.

| Mode    | Target    | Wall median (min–max) | vs base | Functions | Instructions | Resolved jump tables | Defined data |
| ------- | --------- | --------------------- | ------- | --------- | ------------ | -------------------- | ------------ |
| base    | INFO      | 6.57 s (6.52–6.73)    | —       | 129       | 5,516        | 4 of 7               | 204          |
| base    | INSTALL   | 10.15 s (10.09–10.79) | —       | 486       | 20,654       | 3 of 16              | 1,531        |
| base    | SC2K stub | 11.86 s (11.85–12.13) | —       | 311       | 13,886       | 5 of 22              | 291          |
| t1      | INFO      | 5.89 s (5.22–6.22)    | −10%    | 123       | 5,058        | 0 of 6               | 158          |
| t1      | INSTALL   | 6.79 s (6.76–6.93)    | −33%    | 473       | 19,769       | 0 of 11              | 1,471        |
| t1      | SC2K stub | 6.27 s (6.20–6.40)    | −47%    | 306       | 12,644       | 0 of 19              | 181          |
| t2      | INFO      | 4.85 s (4.67–4.94)    | −26%    | 121       | 5,058        | 0 of 6               | 158          |
| t2      | INSTALL   | 5.82 s (5.79–5.92)    | −43%    | 469       | 19,769       | 0 of 11              | 1,471        |
| t2      | SC2K stub | 5.32 s (5.27–5.47)    | −55%    | 302       | 12,689       | 0 of 19              | 180          |
| floor   | INFO      | 3.85 s (3.84–3.99)    | −41%    | 0         | 0            | —                    | 4            |
| floor   | INSTALL   | 3.91 s (3.56–3.95)    | −61%    | 0         | 0            | —                    | 1,008        |
| floor   | SC2K stub | 3.65 s (3.46–3.70)    | −69%    | 0         | 0            | —                    | 79           |
| cds-jdk | INFO      | 6.22 s (6.14–6.37)    | −5%*    | 129       | 5,516        | 4 of 7               | 204          |
| cds-jdk | INSTALL   | 9.65 s (9.45–9.76)    | −5%*    | 486       | 20,654       | 3 of 16              | 1,531        |
| cds-jdk | SC2K stub | 11.04 s (10.95–11.16) | −7%*    | 311       | 13,886       | 5 of 22              | 291          |
| cds-app | INFO      | 6.17 s (6.07–6.27)    | −6%*    | 129       | 5,516        | 4 of 7               | 204          |
| cds-app | INSTALL   | 9.66 s (9.65–10.40)   | −5%*    | 486       | 20,654       | 3 of 16              | 1,531        |
| cds-app | SC2K stub | 10.60 s (10.44–11.55) | −11%*   | 311       | 13,886       | 5 of 22              | 291          |
| jit     | INFO      | 6.23 s (6.11–6.26)    | −5%*    | 129       | 5,516        | 4 of 7               | 204          |
| jit     | INSTALL   | 9.92 s (9.43–9.93)    | −2%*    | 486       | 20,654       | 3 of 16              | 1,531        |
| jit     | SC2K stub | 11.09 s (10.99–11.47) | −6%*    | 311       | 13,886       | 5 of 22              | 291          |

\* **Run-order artifact, not a real gain.** The base cells ran first. Rerunning base and cds-app back to back gave base 6.15 / 9.61 / 11.19 s and cds-app 6.39 / 10.12 / 11.18 s. Headless startup was 1.9–2.5 s in every mode.

Findings:

1. **JVM tuning does nothing measurable here.** Re-enabling class-data sharing, an AppCDS archive, and more GC and JIT threads all stay within run-to-run noise. Building the dynamic archive skipped 5,813 classes as `Unsupported location`. Ghidra loads them through `ghidra.GhidraClassLoader` from module jars, so the archive mostly holds JDK classes that were never the bottleneck. Don't adopt AppCDS for Ghidra.
2. **Decompiler Switch Analysis is the dominant analyzer**: 1.0, 3.2–3.3, and 5.0–5.7 s of the three runs. Turning it off cuts wall time 10–47%, but loses **every** resolved jump table and the code reachable only through them: 6, 13, and 5 functions, and 458, 885, and 1,242 instructions. For decomp work that is a correctness loss, not a tuning win. Keep it on by default and offer a labelled `fast-triage` preset ([B23](backlog.md#b23-platform-analysis-profiles-and-analysis-tuning)).
3. **The remaining analyzers cost about 1 s** (t1 to t2), with small further losses (2–4 functions, and at most 1 defined-data item). These are the right targets for per-platform presets where an analyzer can't apply, such as GNU demangling or Function ID with no FID database for 16-bit x86.
4. **The floor is about 3.5–3.9 s per process** with no analysis. Only a persistent process avoids it (rea's MCP session), and only a persistent project ([B5](backlog.md#b5-persistent-ghidra-projects-and-annotation-ledger)) avoids repeating analysis.
5. **Ghidra 12.1.2 decompiler bug.** On `INSTALL.EXE` and the SC2K stub, switch analysis throws `AddressOutOfBoundsException` from `SegmentedAddressSpace.getAddress` (for example, offset `0x1b02668c` beyond `0x10ffef`). The count of these exceptions varied between otherwise identical runs (4 vs 6), while every quality counter stayed the same. Report it upstream with a public fixture, not these files.

Scripts and raw per-run results are in [`experiments/ghidra-analysis/`](experiments/ghidra-analysis/):

- `matrix.py`: the driver.
- `ExpDisableAnalyzers.java`: the pre-script.
- `ExpQualityCounts.java`: the post-script.
- `results.jsonl`: the main matrix.
- `results-rerun.jsonl`: the order-controlled rerun.

```sh
export GHIDRA_INSTALL_DIR=... JAVA_HOME=...   # Ghidra 12.1.x, JDK 21
EXP_OUT_DIR=/private/scratch/dir python3 -I docs/fork/experiments/ghidra-analysis/matrix.py base t1 t2 floor
```

The driver reads the targets in place and writes Ghidra projects, logs, and archives only under `EXP_OUT_DIR`.

## Upstream velocity

`morluto/rea` `main` was 17 commits ahead of this fork's `main` one day after the fork's last sync. The project has 1,505 commits and five or more active authors. That rate matters to [the Rust port decision](rust-strategy.md).

## Reproduce

Scratch scripts (not committed) lived in the session scratchpad. The equivalent steps are:

```sh
export GHIDRA_INSTALL_DIR=/nix/store/<hash>-ghidra-12.1.2/lib/ghidra
export JAVA_HOME=/nix/store/<hash>-zulu-ca-jdk-21.0.11
npm ci && npm run build:cached
node scripts/rea.mjs doctor --provider ghidra --json
node scripts/rea.mjs inspect /abs/target --provider ghidra --json
```

For the MCP timings, drive `node scripts/rea.mjs mcp` with `@modelcontextprotocol/client` over stdio. `scripts/verify-real-ghidra-com.mjs` shows the client setup. Call `open_binary`, then the listing and analysis tools, timing each call.
