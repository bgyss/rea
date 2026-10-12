import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import type { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";
import { GhidraProvider } from "./GhidraProvider.js";
import type { GhidraProviderClientFactory } from "./GhidraProviderClient.js";
import { GHIDRA_SESSION_CAPABILITIES } from "./GhidraSessionValues.js";

const INSTALL = "/opt/ghidra_12.1.4_PUBLIC";
const host = (platform: NodeJS.Platform = "linux"): GhidraInstallationHost => ({
  platform,
  architecture: "x64",
  readText: () => "application.version=12.1.4\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/usr/lib/jvm/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
});

const jarBytes = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from("loader"),
]);
const digest = createHash("sha256").update(jarBytes).digest("hex");

const pinnedJar = async (sha256 = digest) => {
  const directory = await mkdtemp(join(tmpdir(), "rea-loader-profile-"));
  const path = join(directory, "rea-switch-loader.jar");
  await writeFile(path, jarBytes);
  return {
    path,
    json: JSON.stringify([
      { id: "switch-nxo", path, sha256, loader_name: "ReaSwitchLoader" },
    ]),
  };
};

const providerWith = (
  environment: Record<string, string>,
  platform: NodeJS.Platform = "linux",
  clientFactory?: GhidraProviderClientFactory,
) => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: INSTALL, ...environment });
  if (!config.ok) throw config.error;
  return new GhidraProvider(
    config.value,
    silentLogger,
    {},
    host(platform),
    clientFactory,
  );
};

const switchTarget = (
  format: "switch-nso" | "switch-nro" = "switch-nso",
): BinaryTarget => ({
  path: "/tmp/main",
  sha256: "a".repeat(64),
  kind: "executable",
  format,
  architecture: "arm64",
  availableArchitectures: ["arm64"],
});
const elfTarget: BinaryTarget = {
  path: "/tmp/fixture",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};

describe("Ghidra Switch profile", () => {
  it("commits the loader, its language and the pinned jar identity", async () => {
    const { json } = await pinnedJar();
    const resolved = await providerWith({
      REA_GHIDRA_LOADER_EXTENSIONS_JSON: json,
    }).resolveAnalysisProfile(switchTarget());
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.parameters).toMatchObject({
      target_format: "switch-nso",
      architecture: "arm64",
      loader: "ReaSwitchLoader",
      language_id: "AARCH64:LE:64:v8A",
      compiler_spec_id: "default",
      language_selection: "loader-declared-v1",
      image_base: "0x7100000000",
      loader_extensions: [
        { id: "switch-nxo", sha256: digest, loader_name: "ReaSwitchLoader" },
      ],
    });
    // The path is operator-local state and never enters the profile.
    expect(JSON.stringify(resolved.value.profile)).not.toContain(
      "rea-switch-loader.jar",
    );
  });

  it("changes the profile digest when the pinned jar changes", async () => {
    const first = await pinnedJar();
    const other = Buffer.concat([jarBytes, Buffer.from("v2")]);
    const second = await pinnedJar();
    await writeFile(second.path, other);
    const otherDigest = createHash("sha256").update(other).digest("hex");
    const resolve = async (path: string, sha256: string) => {
      const resolved = await providerWith({
        REA_GHIDRA_LOADER_EXTENSIONS_JSON: JSON.stringify([
          { id: "switch-nxo", path, sha256, loader_name: "ReaSwitchLoader" },
        ]),
      }).resolveAnalysisProfile(switchTarget());
      if (!resolved.ok) throw resolved.error;
      return resolved.value.profile?.digest;
    };
    expect(await resolve(first.path, digest)).not.toBe(
      await resolve(second.path, otherDigest),
    );
  });

  it("leaves a non-Switch profile untouched when a loader is configured but unused", async () => {
    const { json } = await pinnedJar();
    const configured = await providerWith({
      REA_GHIDRA_LOADER_EXTENSIONS_JSON: json,
    }).resolveAnalysisProfile(elfTarget);
    const plain = await providerWith({}).resolveAnalysisProfile(elfTarget);
    if (!configured.ok) throw configured.error;
    if (!plain.ok) throw plain.error;
    expect(configured.value.profile?.parameters).not.toHaveProperty(
      "loader_extensions",
    );
    expect(configured.value.profile?.digest).toBe(plain.value.profile?.digest);
  });

  it("refuses without a configured loader, naming the setting", async () => {
    const resolved = await providerWith({}).resolveAnalysisProfile(
      switchTarget("switch-nro"),
    );
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(
      "REA_GHIDRA_LOADER_EXTENSIONS_JSON",
    );
  });

  it("refuses a jar that does not match its pin, naming both digests", async () => {
    const { json } = await pinnedJar("0".repeat(64));
    const resolved = await providerWith({
      REA_GHIDRA_LOADER_EXTENSIONS_JSON: json,
    }).resolveAnalysisProfile(switchTarget());
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(digest);
  });

  it("refuses a configured language override", async () => {
    const { json } = await pinnedJar();
    const resolved = await providerWith({
      REA_GHIDRA_LOADER_EXTENSIONS_JSON: json,
      REA_GHIDRA_LANGUAGE_ID: "x86:LE:32:default",
    }).resolveAnalysisProfile(switchTarget());
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(
      "REA_GHIDRA_LANGUAGE_ID cannot override the Switch loader",
    );
  });

  it("supports Switch formats on POSIX hosts and declines them on Windows", () => {
    expect(providerWith({}).inspectTargetSupport(switchTarget())).toMatchObject(
      { status: "supported" },
    );
    expect(
      providerWith({}, "win32").inspectTargetSupport(switchTarget()),
    ).toMatchObject({ status: "unsupported" });
  });
});

describe("Ghidra Switch client", () => {
  const sessionInfo = () => ({
    name: "REA Ghidra bridge" as const,
    run_id: "11111111-1111-4111-8111-111111111111",
    profile_digest: "a".repeat(64),
    provider: { id: "ghidra" as const, version: "12.1.4" },
    read_only: false as const,
    analysis_complete: true,
    analysis_timed_out: false,
    capabilities: [...GHIDRA_SESSION_CAPABILITIES],
    target: {
      name: "main",
      language_id: "AARCH64:LE:64:v8A",
      compiler_spec_id: "default",
      image_base: "0x7100000000",
      default_address_space: "ram",
      sha256: "a".repeat(64),
    },
  });

  it("hands the pinned loader and its local path to the launcher", async () => {
    const { path, json } = await pinnedJar();
    const launchers: GhidraHeadlessLauncher[] = [];
    const ghidra = providerWith(
      { REA_GHIDRA_LOADER_EXTENSIONS_JSON: json },
      "linux",
      (options) => {
        launchers.push(options.launcher as GhidraHeadlessLauncher);
        return {
          start: () => Promise.resolve(ok(sessionInfo())),
          callTool: () => Promise.resolve(ok(null)),
          close: () => Promise.resolve(ok(null)),
        };
      },
    );
    const target = switchTarget();
    const resolved = await ghidra.resolveAnalysisProfile(target);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected a bound Ghidra profile");
    const client = ghidra.createClient(target, resolved.value.profile);
    await client.execute("health", {});
    expect(launchers).toHaveLength(1);
    expect(launchers[0]?.options.loaderImport).toEqual({
      name: "ReaSwitchLoader",
      languageId: "AARCH64:LE:64:v8A",
      compilerSpecId: "default",
      extensions: [
        {
          extension: {
            id: "switch-nxo",
            sha256: digest,
            loader_name: "ReaSwitchLoader",
          },
          path,
        },
      ],
    });
  });

  it("refuses to open a Switch target with a profile that lacks the loader", async () => {
    const { json } = await pinnedJar();
    let starts = 0;
    const ghidra = providerWith(
      { REA_GHIDRA_LOADER_EXTENSIONS_JSON: json },
      "linux",
      () => {
        starts += 1;
        return {
          start: () => Promise.resolve(ok(sessionInfo())),
          callTool: () => Promise.resolve(ok(null)),
          close: () => Promise.resolve(ok(null)),
        };
      },
    );
    const target = switchTarget();
    const resolved = await ghidra.resolveAnalysisProfile(target);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected a bound Ghidra profile");
    const { loader_extensions: _dropped, ...rest } = resolved.value.profile
      .parameters as Record<string, unknown>;
    const stripped = {
      ...resolved.value.profile,
      parameters: rest,
    } as typeof resolved.value.profile;
    const client = ghidra.createClient(target, stripped);
    const health = await client.execute("health", {});
    expect(health.ok).toBe(false);
    expect(starts).toBe(0);
  });
});
