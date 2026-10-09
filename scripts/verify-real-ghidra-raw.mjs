#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Authored raw-image fixtures: no game media, ROMs or cross-compilers.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-raw.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:raw supports Linux/macOS hosts only; Windows P0 is PE only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:raw prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:raw prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const packageRoot = process.env.REA_RAW_PROOF_PACKAGE_ROOT;
if (packageRoot !== undefined && !isAbsolute(packageRoot))
  throw new Error("REA_RAW_PROOF_PACKAGE_ROOT must be absolute");
const entrypoint =
  packageRoot === undefined
    ? fileURLToPath(new URL("./rea.mjs", import.meta.url))
    : join(packageRoot, "scripts", "rea.mjs");

const profile = (id, platform, language, base, entry = base) => ({
  schema_version: "dcomp.ghidra-profile.v1",
  profile_id: id,
  platform,
  processor_language_id: language,
  compiler_spec_id: "default",
  loader: "BinaryLoader",
  load_address: base,
  entry_address: entry,
  analysis_timeout_seconds: 120,
  max_instruction_facts: 256,
});
const fixtures = [
  {
    name: "6502",
    // LDA #$01; STA $0200; LDA #$00; BEQ +2; LDA #$FF; RTS
    bytes: Buffer.from([
      0xa9, 0x01, 0x8d, 0x00, 0x02, 0xa9, 0x00, 0xf0, 0x02, 0xa9, 0xff, 0x60,
    ]),
    profile: profile("authored-6502-v1", "nes", "6502:LE:16:default", 0x8000),
    firstInstruction: /^0x8000: LDA #0x1$/iu,
    pseudocode: /0x?200/iu,
  },
  {
    name: "mips",
    // li v0, 1; jr ra; nop
    bytes: Buffer.from([
      0x01, 0x00, 0x02, 0x24, 0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00,
    ]),
    profile: profile(
      "authored-r3000-v1",
      "ps1",
      "MIPS:LE:32:default",
      0x80010000,
    ),
    firstInstruction: /^0x80010000: li v0,\s*0x1$/iu,
    pseudocode: /return 1;/u,
  },
];

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-raw-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
for (const fixture of fixtures) {
  fixture.path = join(workspace, `${fixture.name}.bin`);
  fixture.profilePath = join(workspace, `${fixture.name}.profile.json`);
  fixture.sha256 = digest(fixture.bytes);
  await writeFile(fixture.path, fixture.bytes, { mode: 0o600 });
  await writeFile(fixture.profilePath, JSON.stringify(fixture.profile), {
    mode: 0o600,
  });
}
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-raw-proof", version: "1" });
let opened = false;
let stderr = "";
const report = { fixtures: {} };
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
try {
  await client.connect(transport);
  const [first] = fixtures;
  const missing = await client.callTool({
    name: "open_binary",
    arguments: { path: first.path, format: "raw-image", provider_id: "ghidra" },
  });
  assert.equal(missing.isError, true, "raw-image opened without a profile");
  const stray = await client.callTool({
    name: "open_binary",
    arguments: {
      path: first.path,
      raw_image_profile: first.profile,
      provider_id: "ghidra",
    },
  });
  assert.equal(stray.isError, true, "a profile was ignored without raw-image");
  const outside = await client.callTool({
    name: "open_binary",
    arguments: {
      path: first.path,
      format: "raw-image",
      raw_image_profile: { ...first.profile, entry_address: 0x9000 },
      provider_id: "ghidra",
    },
  });
  assert.equal(outside.isError, true, "an entry outside the image opened");

  for (const fixture of fixtures) {
    const evidence = await cli(fixture, "function", "entry");
    const pseudocode = JSON.stringify(evidence.normalized_result);
    assert.match(pseudocode, fixture.pseudocode);
    assert.ok(
      evidence.limitations.some((line) =>
        line.includes(`caller profile ${fixture.profile.profile_id}`),
      ),
      "raw-image declaration limitation is missing",
    );

    const target = await call("open_binary", {
      path: fixture.path,
      format: "raw-image",
      raw_image_profile: fixture.profile,
      provider_id: "ghidra",
    });
    opened = true;
    assert.equal(target.format, "raw-image");
    assert.equal(target.architecture, null);
    assert.equal(target.sha256, fixture.sha256);
    const procedures = await call("list_procedures");
    const base = `0x${fixture.profile.load_address.toString(16)}`;
    assert.ok(
      procedures.some((row) => row.address === base && row.value === "entry"),
      `entry procedure missing at ${base}`,
    );
    const instructions = await call("read_function_instructions", {
      procedure: "entry",
    });
    assert.match(instructions.instructions[0], fixture.firstInstruction);
    await call("close_binary");
    opened = false;
    assert.equal(digest(await readFile(fixture.path)), fixture.sha256);
    report.fixtures[fixture.name] = {
      language_id: fixture.profile.processor_language_id,
      entry: base,
      first_instruction: instructions.instructions[0],
      cli_mcp_parity: true,
      original_unchanged: true,
    };
  }
  report.rejections = {
    missing_profile: true,
    stray_profile: true,
    entry_outside_image: true,
  };
} catch (error) {
  if (stderr.trim()) process.stderr.write(stderr);
  throw error;
} finally {
  if (opened)
    await call("close_binary").catch((error) =>
      process.stderr.write(String(error)),
    );
  await client.close();
  await transport.close();
  await rm(workspace, { recursive: true, force: true });
}
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
process.stdout.write(
  JSON.stringify({
    verifier_run: verifierRun,
    ghidra_version: installation.providerVersion,
    ...report,
    cleanup: "complete",
  }) + "\n",
);

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
async function call(name, args = {}) {
  const value = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(value.isError, true, JSON.stringify(value));
  if (name === "open_binary") return value.structuredContent.result;
  if (name === "close_binary") return value.structuredContent;
  const evidence = parseEvidence(value.structuredContent.evidence);
  assert.equal(evidence.subject.format, "raw-image");
  assert.deepEqual(evidence.normalized_result, value.structuredContent.result);
  return value.structuredContent.result;
}
async function cli(fixture, command, procedure) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      fixture.path,
      procedure,
      "--target-format",
      "raw-image",
      "--raw-image-profile",
      fixture.profilePath,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, fixture.sha256);
  assert.equal(evidence.subject.format, "raw-image");
  assert.equal(evidence.subject.architecture, null);
  const parameters = evidence.analysis_profile.parameters;
  assert.equal(parameters.loader, "BinaryLoader");
  assert.equal(parameters.language_id, fixture.profile.processor_language_id);
  assert.equal(
    parameters.base_address,
    `0x${fixture.profile.load_address.toString(16)}`,
  );
  assert.deepEqual(parameters.raw_image_profile, fixture.profile);
  return evidence;
}
