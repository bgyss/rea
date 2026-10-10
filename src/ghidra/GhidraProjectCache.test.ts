import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import {
  createGhidraProjectCacheStaging,
  ghidraProjectCacheEntryRoot,
  promoteGhidraProjectCacheStaging,
  readGhidraProjectCacheEntry,
} from "./GhidraProjectCache.js";

const key = {
  targetSha256: "b".repeat(64),
  profileDigest: "a".repeat(64),
  providerVersion: "12.1.2",
};

// Stands in for analyzeHeadless: an import pass logs Ghidra's save reports
// (or an error) and exits; a -process session records its argv and idles.
const fakeHeadless = `#!/usr/bin/env node
const { appendFileSync, mkdirSync, writeFileSync } = require("node:fs");
const { dirname, join } = require("node:path");
const args = process.argv.slice(2);
const log = args[args.indexOf("-log") + 1];
if (args.includes("-import")) {
  appendFileSync(join(dirname(dirname(log)), "imports.txt"), JSON.stringify(args) + "\\n");
  if (process.env.FAKE_IMPORT_FAIL === "1") {
    writeFileSync(log, "ERROR (HeadlessAnalyzer) Abort due to Headless analyzer error: fake\\n");
    process.exit(1);
  }
  mkdirSync(args[0], { recursive: true });
  writeFileSync(join(args[0], "rea-project.gpr"), "");
  writeFileSync(log, "REPORT: Save succeeded for: /t (rea-project:/t)\\nREPORT: Import succeeded\\n");
  process.exit(0);
}
const runtime = dirname(args.at(-1));
writeFileSync(join(runtime, "session-args.json"), JSON.stringify(args));
writeFileSync(join(runtime, "session-args.json.ready"), "");
setInterval(() => undefined, 1000);
`;

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

const setup = async () => {
  const parent = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-"));
  const headless = join(parent, "analyzeHeadless.cjs");
  await writeFile(headless, fakeHeadless);
  await chmod(headless, 0o700);
  const cacheRoot = join(parent, "cache");
  const launcher = new GhidraHeadlessLauncher({
    analyzeHeadlessPath: headless,
    platform: "linux",
    javaHome: "/opt/jdk-21",
    bridgeScriptPath: "/package/bridge/ReaGhidraBridge.java",
    rawImage: {
      mode: "flat",
      languageId: "6502:LE:16:default",
      compilerSpecId: "default",
      baseAddress: "0x8000",
      entryAddress: "0x8000",
    },
    projectCache: { root: cacheRoot },
  });
  let runs = 0;
  const launch = async () => {
    runs += 1;
    const runtimeRoot = join(parent, `runtime-${runs}`);
    await mkdir(runtimeRoot, { mode: 0o700 });
    const launched = await launcher.launch({
      runtimeRoot,
      transport: "unix-socket",
      endpointPath: join(runtimeRoot, "bridge.sock"),
      token: "token",
      runId: `00000000-0000-4000-8000-00000000000${runs}`,
      targetPath: "/tmp/target-bbbbbbbbbbbb.bin",
      targetSha256: key.targetSha256,
      providerVersion: key.providerVersion,
      profileDigest: key.profileDigest,
    });
    if (launched.ok) cleanups.push(launched.value.cleanup ?? (async () => {}));
    return { launched, runtimeRoot };
  };
  const imports = async () =>
    (await readFile(join(parent, "imports.txt"), "utf8").catch(() => ""))
      .split("\n")
      .filter((line) => line.length > 0);
  return { parent, cacheRoot, launch, imports };
};

describe.skipIf(process.platform === "win32")("Ghidra project cache", () => {
  it("imports once, promotes the entry, then reopens it with -process -noanalysis", async () => {
    const { cacheRoot, launch, imports } = await setup();
    const first = await launch();
    if (!first.launched.ok) throw first.launched.error;
    expect(first.launched.value.projectCache?.status).toBe("created");
    const second = await launch();
    if (!second.launched.ok) throw second.launched.error;
    const entry = ghidraProjectCacheEntryRoot(cacheRoot, key);
    expect(second.launched.value.projectCache).toEqual({
      status: "hit",
      entryRoot: entry,
      projectRoot: join(entry, "project"),
      programName: "target-bbbbbbbbbbbb.bin",
    });
    // One import pass, into staging, without the ephemeral flags or bridge.
    const imported = await imports();
    expect(imported).toHaveLength(1);
    const importArgs: unknown = JSON.parse(imported[0] ?? "null");
    expect(importArgs).toEqual([
      expect.stringMatching(/staging-a{64}-.*project$/u),
      "rea-project",
      "-import",
      "/tmp/target-bbbbbbbbbbbb.bin",
      "-loader",
      "BinaryLoader",
      "-loader-baseAddr",
      "0x8000",
      "-processor",
      "6502:LE:16:default",
      "-cspec",
      "default",
      "-log",
      join(first.runtimeRoot, "import-ghidra.log"),
      "-scriptlog",
      join(first.runtimeRoot, "import-script.log"),
      "-scriptPath",
      "/package/bridge",
      "-preScript",
      join("/package/bridge", "ReaGhidraPrepareRaw.java"),
      "0x8000",
    ]);
    expect(await readdir(join(cacheRoot, key.targetSha256))).toEqual([
      key.profileDigest,
    ]);
    const ready = join(second.runtimeRoot, "session-args.json");
    await vi.waitFor(() => access(`${ready}.ready`), { timeout: 10_000 });
    const args: unknown = JSON.parse(await readFile(ready, "utf8"));
    expect(args).toEqual([
      join(entry, "project"),
      "rea-project",
      "-process",
      "target-bbbbbbbbbbbb.bin",
      "-noanalysis",
      "-log",
      join(second.runtimeRoot, "ghidra.log"),
      "-scriptlog",
      join(second.runtimeRoot, "script.log"),
      "-scriptPath",
      "/package/bridge",
      "-postScript",
      "/package/bridge/ReaGhidraBridge.java",
      join(second.runtimeRoot, "session.json"),
    ]);
  });

  it("reports Ghidra's error and leaves no entry or staging when the import fails", async () => {
    vi.stubEnv("FAKE_IMPORT_FAIL", "1");
    const { cacheRoot, launch } = await setup();
    const { launched } = await launch();
    if (launched.ok) throw new Error("Expected the import pass to fail");
    expect(launched.error.message).toMatch(
      /did not save an analysed program \(exit 1\): .*Abort due to Headless analyzer error: fake/u,
    );
    expect(await readdir(join(cacheRoot, key.targetSha256))).toEqual([]);
  });

  it("refuses an entry whose manifest names another identity", async () => {
    const { cacheRoot } = await setup();
    const entry = ghidraProjectCacheEntryRoot(cacheRoot, key);
    await mkdir(entry, { recursive: true });
    await writeFile(
      join(entry, "cache.json"),
      JSON.stringify({
        schema_version: "rea.ghidra-project-cache.v1",
        target_sha256: key.targetSha256,
        profile_digest: key.profileDigest,
        provider_version: "11.0",
        program_name: "t",
        created_at: "2026-10-10T00:00:00.000Z",
      }),
    );
    await expect(readGhidraProjectCacheEntry(entry, key)).rejects.toThrow(
      /does not match this target, profile, and Ghidra version/u,
    );
  });

  it("keeps the first promoted import when two sessions race", async () => {
    const { cacheRoot } = await setup();
    const staged = await Promise.all(
      ["run-a", "run-b"].map(async (run) => {
        const staging = await createGhidraProjectCacheStaging(
          cacheRoot,
          key,
          run,
        );
        await writeFile(join(staging.projectRoot, "rea-project.gpr"), run);
        return staging;
      }),
    );
    const [winner, loser] = staged;
    if (winner === undefined || loser === undefined)
      throw new Error("Expected two staged imports");
    const first = await promoteGhidraProjectCacheStaging(
      winner.stagingRoot,
      cacheRoot,
      key,
      "a",
    );
    const second = await promoteGhidraProjectCacheStaging(
      loser.stagingRoot,
      cacheRoot,
      key,
      "b",
    );
    expect(first.status).toBe("created");
    expect(second).toMatchObject({ status: "hit", programName: "a" });
    expect(await readdir(join(cacheRoot, key.targetSha256))).toEqual([
      key.profileDigest,
    ]);
  });
});
