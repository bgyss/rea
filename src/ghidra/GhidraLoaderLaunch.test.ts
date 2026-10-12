import { createHash } from "node:crypto";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { spawnOwnedProviderProcess } from "../process/ProviderProcess.js";
import { GhidraHeadlessLauncher } from "./GhidraLauncher.js";

const jarBytes = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from("loader"),
]);
const digest = createHash("sha256").update(jarBytes).digest("hex");
const committed = {
  id: "switch-nxo",
  sha256: digest,
  loader_name: "ReaSwitchLoader",
};

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((cleanup) => cleanup()));
});

// A Ghidra root with just enough for the launcher: support/, Ghidra/ and a JDK
// whose java prints no LaunchSupport configuration.
const setup = async (options: { loaderBytes?: Buffer } = {}) => {
  const parent = await mkdtemp(join(tmpdir(), "rea-ghidra-loader-launch-"));
  const installRoot = join(parent, "ghidra");
  await mkdir(join(installRoot, "support"), { recursive: true });
  await mkdir(join(installRoot, "Ghidra"), { recursive: true });
  await writeFile(
    join(installRoot, "Ghidra", "application.properties"),
    "application.name=Ghidra\napplication.version=12.1.4\napplication.release.name=PUBLIC\n",
  );
  const headless = join(installRoot, "support", "analyzeHeadless");
  await writeFile(headless, "#!/bin/sh\nexit 0\n");
  await chmod(headless, 0o700);
  const javaHome = join(parent, "jdk");
  await mkdir(join(javaHome, "bin"), { recursive: true });
  await writeFile(join(javaHome, "bin", "java"), "#!/bin/sh\nexit 0\n");
  await chmod(join(javaHome, "bin", "java"), 0o700);
  const jarPath = join(parent, "rea-switch-loader.jar");
  await writeFile(jarPath, options.loaderBytes ?? jarBytes);

  const spawned: (readonly string[])[] = [];
  const launcher = (withLoader: boolean) =>
    new GhidraHeadlessLauncher({
      environment: {},
      analyzeHeadlessPath: headless,
      // Record the invocation and stand in for the JVM with an idle Node process.
      spawnProcess: (launch) => {
        spawned.push(launch.arguments);
        return spawnOwnedProviderProcess({
          ...launch,
          command: process.execPath,
          arguments: ["-e", "setInterval(() => undefined, 1000)"],
          expectedCommand: process.execPath,
        });
      },
      platform: "linux",
      javaHome,
      bridgeScriptPath: "/package/bridge/ReaGhidraBridge.java",
      ...(withLoader
        ? {
            loaderImport: {
              name: "ReaSwitchLoader",
              languageId: "AARCH64:LE:64:v8A",
              compilerSpecId: "default",
              extensions: [{ extension: committed, path: jarPath }],
            },
          }
        : {}),
    });
  const launch = async (instance: GhidraHeadlessLauncher) => {
    const runtimeRoot = join(parent, "runtime");
    await mkdir(runtimeRoot, { mode: 0o700 });
    const launched = await instance.launch({
      runtimeRoot,
      transport: "unix-socket",
      endpointPath: join(runtimeRoot, "bridge.sock"),
      token: "token",
      runId: "00000000-0000-4000-8000-000000000001",
      targetPath: "/tmp/main",
      targetSha256: "b".repeat(64),
      providerVersion: "12.1.4",
      profileDigest: "a".repeat(64),
    });
    if (launched.ok) cleanups.push(launched.value.cleanup ?? (async () => {}));
    return { launched, runtimeRoot };
  };
  return { launcher, launch, spawned, jarPath };
};

const extensionJar = (runtimeRoot: string) =>
  join(
    runtimeRoot,
    "home",
    "ghidra-settings",
    "ghidra",
    "ghidra_12.1.4_PUBLIC",
    "Extensions",
    "switch-nxo",
    "lib",
    "switch-nxo.jar",
  );

describe.skipIf(process.platform === "win32")(
  "Ghidra pinned loader launch",
  () => {
    it("installs the verified loader privately and imports through it", async () => {
      const { launcher, launch, spawned } = await setup();
      const { launched, runtimeRoot } = await launch(launcher(true));
      if (!launched.ok) throw launched.error;
      expect(await readFile(extensionJar(runtimeRoot))).toEqual(jarBytes);
      const [invocation] = spawned;
      expect(invocation).toContain(
        `-Dapplication.settingsdir=${join(runtimeRoot, "home", "ghidra-settings")}`,
      );
      expect(invocation).toContain(`-Duser.home=${join(runtimeRoot, "home")}`);
      const importAt = invocation?.indexOf("-import") ?? -1;
      expect(invocation?.slice(importAt, importAt + 8)).toEqual([
        "-import",
        "/tmp/main",
        "-loader",
        "ReaSwitchLoader",
        "-processor",
        "AARCH64:LE:64:v8A",
        "-cspec",
        "default",
      ]);
    });

    it("refuses bytes that changed after profile resolution before any process starts", async () => {
      const { launcher, launch, spawned, jarPath } = await setup();
      await writeFile(jarPath, Buffer.concat([jarBytes, Buffer.from("x")]));
      const { launched, runtimeRoot } = await launch(launcher(true));
      expect(launched.ok).toBe(false);
      expect(spawned).toHaveLength(0);
      await expect(access(extensionJar(runtimeRoot))).rejects.toThrow();
    });

    it("leaves other launches without a settings override or extension", async () => {
      const { launcher, launch, spawned } = await setup();
      const { launched, runtimeRoot } = await launch(launcher(false));
      if (!launched.ok) throw launched.error;
      expect(
        spawned[0]?.some((value) =>
          value.startsWith("-Dapplication.settingsdir"),
        ),
      ).toBe(false);
      await expect(
        access(join(runtimeRoot, "home", "ghidra-settings")),
      ).rejects.toThrow();
    });
  },
);
