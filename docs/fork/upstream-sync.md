# Syncing with upstream

`bgyss/rea` is a fork of `morluto/rea`. The `upstream` remote points at `https://github.com/morluto/rea.git`. Sync with a merge commit on a `sync/upstream-YYYY-MM-DD` branch, never a rebase: the fork's history is public and each backlog item landed through its own pull request. GitHub's "Sync fork" pull request cannot be merged once the histories diverge and does not let you push conflict resolutions, so close it and open the sync branch instead.

```sh
git fetch upstream
git checkout -b sync/upstream-YYYY-MM-DD origin/main
git merge --no-ff upstream/main
```

After resolving, run `npm ci`, `npm run build:cached`, `npm run check:fast`, the `domain`, `services`, `adapters`, `composition`, `conformance`, `boundary` and `mcp-boundary` test projects, and every real-Ghidra lane listed in `mise.toml` (`mise run verify-ghidra`).

## 2026-10-11: 867 upstream commits, 42 fork commits

The merge-base was upstream's `fix(cli): accept exact native names through explicit selectors`. 54 files conflicted. Decisions that future syncs should keep:

- **Two headerless formats.** Upstream's `raw-binary` (architecture plus entry point, flat image) and the fork's `raw-image` (full `dcomp.ghidra-profile` with memory map) are separate `--target-format` values. `ExecutableFormatHint` is `"dos-com" | "raw-binary" | { format: "raw-image", profile }`. Each has its own preparation script (`ReaGhidraPrepareRaw.java` for `raw-binary`, `ReaGhidraPrepareRawImage.java` for `raw-image`) and its own real-Ghidra lane (`verify:ghidra:raw`, `verify:ghidra:raw-image`). `architecture` and `entry_point` are rejected with any format other than `raw-binary`.
- **CLI options.** Upstream's `nativeOpenOptionFields` and `directAnalysisOptionsFromCli` are the shared option bundle. The fork's `--raw-image-profile` and `--annotation-ledger` live in that bundle, and `directAnalysisOptions` takes the parsed flags as its fourth argument.
- **Dependency injection.** Native CLI commands receive `runDirectAnalysis` as a parameter. Fork commands do the same; do not import the composition module directly.
- **Analysis profile.** Upstream removed `compatibility` from `AnalysisProfileResolution`, and the profile now carries `language_selection`. A `raw-image` import rejects `REA_GHIDRA_LANGUAGE_ID` the way a DOS import does, because the profile declares the processor.
- **Launcher.** The fork's project cache (`#sessionArguments`, `#projectCacheEntry`, `#importPass`) sits on top of upstream's launcher. The cache's import pass runs every pre- and post-analysis script except the bridge, so the no-return repair is saved in the cached project.
- **Mutating operations.** `GHIDRA_MUTATING_OPERATIONS` is the union of the annotation operations and upstream's naming operations (`set_address_name`, `set_addresses_names`).
- **Server.** Session tools go through upstream's admission wrappers (`runAdmittedToolOperation`, `server.delivery`). The annotation ledger binding is threaded through `createServer`, `registerOfficialTools`, `registerSessionTools` and `registerCloseLifecycleTool`.
- **Paths.** Authored skills moved from `skill-src/` to `.agents/skills/reverse-engineer-anything/`. `isAbsoluteLocalPath` was removed upstream; use `localPathStringSchema.refine(isAbsolute, ...)`.
- **Tests.** Upstream deleted `src/contracts/toolContracts.test.ts`. The fork's tests were adapted to `parseBinaryTarget(path, options)`, `createServer({ kind: "session", session })`, required `environment` arguments and `Promise<Result>` client closes.

Not covered by this sync's verification: see the pull request description.
