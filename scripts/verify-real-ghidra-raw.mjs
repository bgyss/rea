#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
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
    // LDA #$01; STA $0200; LDA #$00; BEQ +2; LDA #$FF; RTS; then two
    // undefined bytes at 0x800c for typed-data ledger entries.
    bytes: Buffer.from([
      0xa9, 0x01, 0x8d, 0x00, 0x02, 0xa9, 0x00, 0xf0, 0x02, 0xa9, 0xff, 0x60,
      0x00, 0x00,
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
  {
    name: "nes-mmio",
    // LDA #$80; STA $2000 (PPUCTRL); RTS. Nothing maps $2000 until the
    // nes-registers pack adds its PPU block.
    bytes: Buffer.from([0xa9, 0x80, 0x8d, 0x00, 0x20, 0x60]),
    profile: profile(
      "authored-nes-mmio-v1",
      "nes",
      "6502:LE:16:default",
      0x8000,
    ),
    firstInstruction: /^0x8000: LDA #0x80$/iu,
    pseudocode: /2000/u,
  },
  {
    name: "ps1-mmio",
    // lui v0, 0x1f80; sw zero, 0x1070(v0) (I_STAT); jr ra; nop.
    bytes: Buffer.from([
      0x80, 0x1f, 0x02, 0x3c, 0x70, 0x10, 0x40, 0xac, 0x08, 0x00, 0xe0, 0x03,
      0x00, 0x00, 0x00, 0x00,
    ]),
    profile: profile(
      "authored-ps1-mmio-v1",
      "ps1",
      "MIPS:LE:32:default",
      0x80010000,
    ),
    firstInstruction: /^0x80010000: lui v0,\s*0x1f80$/iu,
    pseudocode: /1f801070/iu,
  },
];

// Two switchable banks share $8000 as overlays; a fixed bank sits at $C000.
const bankSize = 0x100;
const bankBytes = [
  [0xa9, 0x01, 0x8d, 0x00, 0x02, 0x60], // LDA #1; STA $0200; RTS
  [0xa9, 0x02, 0x8d, 0x01, 0x02, 0x60], // LDA #2; STA $0201; RTS
  [0x20, 0x00, 0x80, 0x60], // JSR $8000; RTS
];
const banked = {
  name: "banked",
  bytes: Buffer.concat(
    bankBytes.map((code) =>
      Buffer.concat([Buffer.from(code), Buffer.alloc(bankSize - code.length)]),
    ),
  ),
  profile: {
    schema_version: "dcomp.ghidra-profile.v2",
    profile_id: "authored-banked-6502-v2",
    platform: "nes",
    processor_language_id: "6502:LE:16:default",
    compiler_spec_id: "default",
    blocks: [
      ["bank0", 0, 0x8000, true],
      ["bank1", bankSize, 0x8000, true],
      ["fixed", 2 * bankSize, 0xc000, false],
    ].map(([name, offset, address, overlay]) => ({
      name,
      file_offset: offset,
      length: bankSize,
      load_address: address,
      overlay,
      permissions: "rx",
      entry_addresses: [address],
    })),
    analysis_timeout_seconds: 120,
    max_instruction_facts: 256,
  },
};

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-raw-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
for (const fixture of [...fixtures, banked]) {
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
  // Banked v2: distinct overlay identities at one CPU address, exact file offsets.
  const bankedCli = await cli(banked, "instructions", "bank1:0x8000");
  assert.match(
    JSON.stringify(bankedCli.normalized_result),
    /bank1:0x8000: LDA #0x2/u,
  );
  const bankedTarget = await call("open_binary", {
    path: banked.path,
    format: "raw-image",
    raw_image_profile: banked.profile,
    provider_id: "ghidra",
  });
  opened = true;
  assert.equal(bankedTarget.format, "raw-image");
  const bankedProcedures = await call("list_procedures");
  for (const [address, name] of [
    ["bank0:0x8000", "bank0_entry"],
    ["bank1:0x8000", "bank1_entry"],
    ["0xc000", "fixed_entry"],
  ])
    assert.ok(
      bankedProcedures.some(
        (row) => row.address === address && row.value === name,
      ),
      `banked procedure ${name} missing at ${address}`,
    );
  const bank0 = await call("read_function_instructions", {
    procedure: "bank0:0x8000",
  });
  const bank1 = await call("read_function_instructions", {
    procedure: "bank1:0x8000",
  });
  assert.match(bank0.instructions[0], /^bank0:0x8000: LDA #0x1$/iu);
  assert.match(bank1.instructions[0], /^bank1:0x8000: LDA #0x2$/iu);
  const offset = await call("address_to_file_offset", {
    address: "bank1:0x8002",
  });
  assert.equal(offset.file_offset, bankSize + 2);
  await call("close_binary");
  opened = false;
  assert.equal(digest(await readFile(banked.path)), banked.sha256);
  report.fixtures.banked = {
    profile: "dcomp.ghidra-profile.v2",
    overlays_distinct: true,
    bank1_file_offset: offset.file_offset,
    cli_mcp_parity: true,
  };

  // Annotation ledger: record over MCP, replay on reopen and through the CLI.
  const ledger = join(workspace, "annotations.jsonl");
  const ledgerOpen = async (profileOverride = {}) =>
    call("open_binary", {
      path: first.path,
      format: "raw-image",
      raw_image_profile: { ...first.profile, ...profileOverride },
      provider_id: "ghidra",
      annotation_ledger_path: ledger,
    });
  const initial = await ledgerOpen();
  opened = true;
  assert.equal(initial.annotation_ledger.entries, 0);
  await call("annotate_native_function", {
    procedure: "entry",
    name: "reset_handler",
    comment: "Writes 1 to $0200",
  });
  // Types replay before the data edit that names them.
  const defined = await call("define_native_types", {
    declarations:
      "typedef struct ppu_latch { unsigned char ctrl; unsigned char mask; } ppu_latch;",
  });
  assert.deepEqual(
    defined.types.map((type) => [type.id, type.size_bytes]),
    [["/rea/ppu_latch", 2]],
  );
  await call("annotate_native_data", {
    address: "0x800c",
    label: "ppu_shadow",
    data_type: "ppu_latch",
  });
  await call("close_binary");
  opened = false;
  const ledgerLines = (await readFile(ledger, "utf8")).trim().split("\n");
  assert.deepEqual(
    ledgerLines.map((line) => Object.keys(JSON.parse(line))[3]),
    ["procedure", "declarations", "address"],
  );
  const replayed = await ledgerOpen();
  opened = true;
  assert.deepEqual(
    {
      entries: replayed.annotation_ledger.entries,
      applied: replayed.annotation_ledger.applied,
      failed: replayed.annotation_ledger.failed,
    },
    { entries: 3, applied: 3, failed: [] },
  );
  const renamed = await call("list_procedures");
  assert.ok(
    renamed.some((row) => row.value === "reset_handler"),
    "replayed annotation is missing",
  );
  const replayedData = await call("inspect_native_data_type", {
    address: "0x800c",
  });
  assert.equal(replayedData.id, "/rea/ppu_latch");
  assert.deepEqual(
    replayedData.fields.map((field) => [field.name, field.offset_bytes]),
    [
      ["ctrl", 0],
      ["mask", 1],
    ],
  );
  assert.equal(await call("address_name", { address: "0x800c" }), "ppu_shadow");
  await call("close_binary");
  opened = false;
  const otherProfile = await ledgerOpen({ profile_id: "other-profile" });
  opened = true;
  assert.equal(otherProfile.annotation_ledger.skipped_other_profile, 3);
  assert.equal(otherProfile.annotation_ledger.applied, 0);
  await call("close_binary");
  opened = false;
  const cliReplay = await cli(first, "function", "0x8000", [
    "--annotation-ledger",
    ledger,
  ]);
  assert.equal(cliReplay.normalized_result.procedure.name, "reset_handler");
  report.annotation_ledger = {
    recorded: ledgerLines.length,
    kinds: ["function", "types", "data"],
    mcp_replayed: true,
    other_profile_skipped: true,
    cli_replayed: true,
  };

  // Label packs and annotation sets: MMIO blocks, register labels, and the
  // decompiler naming the registers; atomic rejection; CLI; ledger replay.
  const packFixture = (name) => fixtures.find((item) => item.name === name);
  const packLedger = join(workspace, "pack-annotations.jsonl");
  const packOpen = (fixture, ledgerPath) =>
    call("open_binary", {
      path: fixture.path,
      format: "raw-image",
      raw_image_profile: fixture.profile,
      provider_id: "ghidra",
      ...(ledgerPath === undefined
        ? {}
        : { annotation_ledger_path: ledgerPath }),
    });
  const packReject = async (args, diagnostic) => {
    const reply = await client.callTool({
      name: "apply_native_annotations",
      arguments: args,
    });
    assert.equal(reply.isError, true, `accepted ${JSON.stringify(args)}`);
    const error = reply.structuredContent?.error;
    assert.equal(error?.code, "invalid_request");
    assert.match(JSON.stringify(error.details.issues), diagnostic);
  };
  const packReport = {};
  for (const [fixtureName, packId, register, statement] of [
    ["nes-mmio", "nes-registers", ["0x2000", "PPUCTRL"], /PPUCTRL = 0x80;/u],
    ["ps1-mmio", "ps1-registers", ["0x1f801070", "I_STAT"], /I_STAT = 0;/u],
  ]) {
    const fixture = packFixture(fixtureName);
    await packOpen(
      fixture,
      fixtureName === "nes-mmio" ? packLedger : undefined,
    );
    opened = true;
    // The other platform's pack names a different processor.
    await packReject(
      { pack: packId === "nes-registers" ? "ps1-registers" : "nes-registers" },
      /The set applies to .*this program's processor is/u,
    );
    // A rejected item rolls back the block created before it.
    await packReject(
      {
        annotations: {
          memory_blocks: [
            {
              name: "REA_ROLLBACK",
              address: register[0],
              size_bytes: 4,
              volatile: true,
            },
          ],
          data: [{ address: register[0], data_type: "struct rea_missing" }],
        },
      },
      /data\[0\]: Unknown or variable-length data type struct rea_missing/u,
    );
    const applied = await call("apply_native_annotations", { pack: packId });
    assert.equal(applied.pack.id, packId);
    assert.ok(
      applied.memory_blocks.every((block) => block.outcome === "created"),
      `blocks not created: ${JSON.stringify(applied.memory_blocks)}`,
    );
    const labelled = applied.data.find((item) => item.address === register[0]);
    assert.equal(labelled?.label, register[1]);
    assert.equal(
      await call("address_name", { address: register[0] }),
      register[1],
    );
    const { pseudocode } = await call("analyze_function", {
      procedure: "entry",
    });
    assert.match(pseudocode, statement);
    // Applying again keeps the blocks and changes nothing else.
    const again = await call("apply_native_annotations", { pack: packId });
    assert.ok(
      again.memory_blocks.every((block) => block.outcome === "existing"),
    );
    await call("close_binary");
    opened = false;
    assert.equal(digest(await readFile(fixture.path)), fixture.sha256);
    packReport[packId] = {
      blocks: applied.memory_blocks.length,
      registers: applied.data.length,
      decompiler_named_register: register[1],
    };
  }
  const nes = packFixture("nes-mmio");
  const replayedPack = await packOpen(nes, packLedger);
  opened = true;
  assert.deepEqual(
    {
      entries: replayedPack.annotation_ledger.entries,
      applied: replayedPack.annotation_ledger.applied,
      failed: replayedPack.annotation_ledger.failed,
    },
    { entries: 2, applied: 2, failed: [] },
  );
  const replayedCode = await call("analyze_function", { procedure: "entry" });
  assert.match(replayedCode.pseudocode, /PPUCTRL = 0x80;/u);
  await call("close_binary");
  opened = false;
  const cliPack = await cli(nes, "apply-native-annotations", null, [
    "--pack",
    "nes-registers",
  ]);
  assert.equal(cliPack.normalized_result.pack.id, "nes-registers");
  const customPack = join(workspace, "custom-pack.json");
  await writeFile(
    customPack,
    JSON.stringify({
      schema_version: "rea.label-pack.v1",
      id: "rea-custom",
      version: 1,
      title: "Custom",
      platform: "nes",
      sources: ["authored"],
      limitations: [],
      annotations: {
        memory_blocks: [
          {
            name: "WRAM",
            address: "0x6000",
            size_bytes: 0x2000,
            volatile: false,
          },
        ],
        data: [{ address: "0x6000", label: "save_magic", data_type: "word" }],
      },
    }),
    { mode: 0o600 },
  );
  const cliFile = await cli(nes, "apply-native-annotations", null, [
    "--file",
    customPack,
  ]);
  assert.equal(cliFile.normalized_result.pack, null);
  assert.deepEqual(
    cliFile.normalized_result.data.map(({ label, size_bytes }) => [
      label,
      size_bytes,
    ]),
    [["save_magic", 2]],
  );
  report.label_packs = {
    ...packReport,
    processor_mismatch_rejected: true,
    item_rejection_rolled_back: true,
    reapplied_unchanged: true,
    ledger_replayed: true,
    cli_pack: true,
    cli_file: true,
  };

  // Persistent project cache: analyse once, keep CLI annotations across runs.
  const projects = join(workspace, "projects");
  const cacheEnv = { ...env, REA_GHIDRA_PROJECT_CACHE_DIR: projects };
  const cachedAnnotate = await cli(
    first,
    "annotate-native-function",
    "0x8000",
    ["--name", "cached_reset"],
    cacheEnv,
  );
  assert.deepEqual(cachedAnnotate.normalized_result.effects, {
    scope: "persistent-analysis-database",
    source_bytes_modified: false,
    persists_after_close: true,
  });
  const entries = await readdir(join(projects, first.sha256));
  assert.equal(entries.length, 1, "expected one promoted cache entry");
  const cachedStart = Date.now();
  const cachedFunction = await cli(first, "function", "0x8000", [], cacheEnv);
  const warmMs = Date.now() - cachedStart;
  assert.equal(cachedFunction.normalized_result.procedure.name, "cached_reset");
  const ephemeralFunction = await cli(first, "function", "0x8000");
  assert.notEqual(
    ephemeralFunction.normalized_result.procedure.name,
    "cached_reset",
  );
  report.project_cache = {
    entries: entries.length,
    annotation_persisted: true,
    warm_function_ms: warmMs,
    ephemeral_unaffected: true,
  };

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
async function cli(fixture, command, procedure, extra = [], cliEnv = env) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      fixture.path,
      ...(procedure === null ? [] : [procedure]),
      "--target-format",
      "raw-image",
      "--raw-image-profile",
      fixture.profilePath,
      "--provider",
      "ghidra",
      "--json",
      ...extra,
    ],
    { env: cliEnv, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(stdout));
  assert.equal(evidence.subject.digest.sha256, fixture.sha256);
  assert.equal(evidence.subject.format, "raw-image");
  assert.equal(evidence.subject.architecture, null);
  const parameters = evidence.analysis_profile.parameters;
  assert.equal(parameters.loader, "BinaryLoader");
  assert.equal(parameters.language_id, fixture.profile.processor_language_id);
  if (fixture.profile.schema_version === "dcomp.ghidra-profile.v1")
    assert.equal(
      parameters.base_address,
      `0x${fixture.profile.load_address.toString(16)}`,
    );
  else
    assert.equal(
      parameters.memory_map,
      "file-bytes-blocks-overlay-space-per-bank-v1",
    );
  assert.deepEqual(parameters.raw_image_profile, fixture.profile);
  return evidence;
}
