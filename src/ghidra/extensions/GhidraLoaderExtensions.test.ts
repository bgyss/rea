import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { AppConfig } from "../../config/types.js";
import {
  ghidraApplicationVersionedName,
  ghidraUserExtensionsDirectory,
  installGhidraLoaderExtensions,
  resolveGhidraLoaderExtension,
} from "./GhidraLoaderExtensions.js";

// A ZIP local-file-header magic is all the bounded reader requires of a "jar".
const jarBytes = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from("loader"),
]);
const digest = createHash("sha256").update(jarBytes).digest("hex");
const configFor = (path: string, sha256 = digest): AppConfig =>
  ({
    ghidraLoaderExtensions: [
      { id: "switch-nxo", path, sha256, loader_name: "ReaSwitchLoader" },
    ],
  }) as unknown as AppConfig;

const jar = async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-loader-ext-"));
  const path = join(directory, "loader.jar");
  await writeFile(path, jarBytes);
  return { directory, path };
};

describe("resolveGhidraLoaderExtension", () => {
  it("commits the pinned digest and loader name, not the path", async () => {
    const { path } = await jar();
    const resolved = await resolveGhidraLoaderExtension(
      configFor(path),
      "ReaSwitchLoader",
      "darwin",
    );
    expect(resolved).toEqual({
      ok: true,
      value: {
        id: "switch-nxo",
        sha256: digest,
        loader_name: "ReaSwitchLoader",
      },
    });
  });

  it("refuses a jar whose bytes differ from the pin, naming both digests", async () => {
    const { path } = await jar();
    const resolved = await resolveGhidraLoaderExtension(
      configFor(path, "0".repeat(64)),
      "ReaSwitchLoader",
      "darwin",
    );
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(digest);
    expect(JSON.stringify(resolved)).toContain("0".repeat(64));
  });

  it("refuses when no loader of that name is configured, naming the remedy", async () => {
    const resolved = await resolveGhidraLoaderExtension(
      {} as AppConfig,
      "ReaSwitchLoader",
      "darwin",
    );
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(
      "REA_GHIDRA_LOADER_EXTENSIONS_JSON",
    );
  });

  it("refuses a missing jar with the path it looked at", async () => {
    const { directory } = await jar();
    const missing = join(directory, "absent.jar");
    const resolved = await resolveGhidraLoaderExtension(
      configFor(missing),
      "ReaSwitchLoader",
      "darwin",
    );
    expect(resolved.ok).toBe(false);
    expect(JSON.stringify(resolved)).toContain(missing);
  });

  it("refuses on Windows hosts", async () => {
    const { path } = await jar();
    const resolved = await resolveGhidraLoaderExtension(
      configFor(path),
      "ReaSwitchLoader",
      "win32",
    );
    expect(resolved.ok).toBe(false);
  });
});

describe("installGhidraLoaderExtensions", () => {
  const committed = {
    id: "switch-nxo",
    sha256: digest,
    loader_name: "ReaSwitchLoader",
  };

  it("lays the jar out as a Ghidra extension whose jar is named after its module", async () => {
    const { directory, path } = await jar();
    const extensionsDirectory = join(directory, "Extensions");
    await installGhidraLoaderExtensions({
      extensions: [{ extension: committed, path }],
      extensionsDirectory,
      ghidraVersion: "12.1.4",
    });
    const root = join(extensionsDirectory, "switch-nxo");
    expect((await readdir(root)).sort()).toEqual([
      "Module.manifest",
      "extension.properties",
      "lib",
    ]);
    // Ghidra's production class search skips a module jar that does not start
    // with the module directory's name.
    expect(await readdir(join(root, "lib"))).toEqual(["switch-nxo.jar"]);
    expect(await readFile(join(root, "lib", "switch-nxo.jar"))).toEqual(
      jarBytes,
    );
    expect(
      await readFile(join(root, "extension.properties"), "utf8"),
    ).toContain("version=12.1.4");
  });

  it("refuses bytes that changed after the profile was resolved and writes nothing", async () => {
    const { directory, path } = await jar();
    await writeFile(path, Buffer.concat([jarBytes, Buffer.from("tampered")]));
    await expect(
      installGhidraLoaderExtensions({
        extensions: [{ extension: committed, path }],
        extensionsDirectory: join(directory, "Extensions"),
        ghidraVersion: "12.1.4",
      }),
    ).rejects.toThrow(/digest/u);
    expect(await readdir(directory)).not.toContain("Extensions");
  });
});

describe("Ghidra settings layout", () => {
  it("places extensions under the versioned settings directory", () => {
    expect(
      ghidraUserExtensionsDirectory(
        "/run/home/ghidra-settings",
        "ghidra_12.1.4_PUBLIC",
      ),
    ).toBe("/run/home/ghidra-settings/ghidra/ghidra_12.1.4_PUBLIC/Extensions");
  });

  it("derives the versioned name from application.properties", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ghidra-root-"));
    await mkdir(join(root, "Ghidra"));
    await writeFile(
      join(root, "Ghidra", "application.properties"),
      "application.name=Ghidra\napplication.version=12.1.4\napplication.release.name=PUBLIC\n",
    );
    expect(await ghidraApplicationVersionedName(root)).toBe(
      "ghidra_12.1.4_PUBLIC",
    );
  });

  it("rejects an application.properties without a version", async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-ghidra-root-"));
    await mkdir(join(root, "Ghidra"));
    await writeFile(
      join(root, "Ghidra", "application.properties"),
      "application.name=Ghidra\n",
    );
    await expect(ghidraApplicationVersionedName(root)).rejects.toThrow(
      /application\.version/u,
    );
  });
});
