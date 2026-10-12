#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const root = fileURLToPath(
  new URL("../bridge/ghidra-loaders/switch/", import.meta.url),
);
const args = process.argv.slice(2);
const selfTest = args.includes("--self-test");
const outIndex = args.indexOf("--out");
const install = process.env.GHIDRA_INSTALL_DIR;
const javaHome = process.env.JAVA_HOME;
if (install === undefined || javaHome === undefined)
  throw new Error(
    "build:ghidra-switch-loader requires GHIDRA_INSTALL_DIR and JAVA_HOME (run inside `nix develop`).",
  );

const jars = async (directory) =>
  (await readdir(directory, { recursive: true }))
    .filter((name) => name.endsWith(".jar") && !name.endsWith("-src.jar"))
    .sort()
    .map((name) => join(directory, name));
const classpath = [
  ...(await jars(join(install, "Ghidra", "Framework"))),
  ...(await jars(join(install, "Ghidra", "Features", "Base"))),
].join(":");
const sources = async (directory) =>
  (await readdir(directory, { recursive: true }))
    .filter((name) => name.endsWith(".java"))
    .sort()
    .map((name) => join(directory, name));

const out =
  outIndex >= 0
    ? args[outIndex + 1]
    : await mkdtemp(join(tmpdir(), "rea-switch-loader-"));
const classes = join(out, "classes");
await mkdir(classes, { recursive: true });
// Ghidra's own jar manifests name class-path entries that are not shipped, so
// the [path] lint category would fail every build regardless of this code.
try {
  await run(join(javaHome, "bin", "javac"), [
    "--release",
    "21",
    "-proc:none",
    "-Xlint:all,-path",
    "-Werror",
    "-cp",
    classpath,
    "-d",
    classes,
    ...(await sources(join(root, "src"))),
    ...(await sources(join(root, "test"))),
  ]);
} catch (failure) {
  process.stderr.write(`${failure.stderr ?? failure}\n`);
  process.exit(1);
}
if (selfTest) {
  const { stdout } = await run(join(javaHome, "bin", "java"), [
    "-cp",
    classes,
    "rea.switchloader.NxoSelfTest",
  ]);
  process.stdout.write(stdout);
  process.exit(0);
}
const jar = join(out, "rea-switch-loader.jar");
// Only the loader's own classes ship; the self-test stays out of the artifact.
await run(join(javaHome, "bin", "jar"), [
  "--create",
  "--file",
  jar,
  "--date",
  "2026-01-01T00:00:00Z",
  "-C",
  classes,
  "rea/switchloader/Lz4Block.class",
  "-C",
  classes,
  "rea/switchloader/NxoImage.class",
  "-C",
  classes,
  "rea/switchloader/NxoImage$Kind.class",
  "-C",
  classes,
  "rea/switchloader/NxoImage$Segment.class",
  "-C",
  classes,
  "rea/switchloader/ReaSwitchLoader.class",
]);
const sha256 = createHash("sha256")
  .update(await readFile(jar))
  .digest("hex");
process.stdout.write(`${JSON.stringify({ jar, sha256 })}\n`);
