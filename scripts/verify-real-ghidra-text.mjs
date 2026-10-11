#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Authored raw-image fixture: Japanese text in several encodings and a table of
// 16-bit pointers to it. No game media and no compiler.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-text.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:text supports Linux/macOS hosts only; Windows P0 is PE only.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:text prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:text prerequisite unavailable: ${JSON.stringify(installation)}`,
  );

const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const base = 0x8000;
const hex = (text) => Buffer.from(text.replaceAll(" ", ""), "hex");

// Shift-JIS strings, each terminated by 00, starting at base + 0x100.
const strings = [
  hex("83 51 81 5b 83 80"), // ゲーム
  hex("83 58 83 5e 81 5b 83 67"), // スタート
  hex("82 cd 82 b6 82 df 82 a9 82 e7"), // はじめから
  hex("82 c2 82 c3 82 ab 82 a9 82 e7"), // つづきから
  hex("8f 49 97 b9"), // 終了
  hex("90 dd 92 e8"), // 設定
  hex("89 b9 97 ca"), // 音量
  hex("96 df 82 e9"), // 戻る
  hex("82 cd 82 a2"), // はい
  hex("82 a2 82 a2 82 a6"), // いいえ
];
const image = Buffer.alloc(0x300);
// LDA #1; RTS gives the raw image an entry.
hex("a9 01 60").copy(image, 0);
const stringAddresses = [];
let cursor = 0x100;
for (const bytes of strings) {
  stringAddresses.push(base + cursor);
  bytes.copy(image, cursor);
  cursor += bytes.length + 1;
}
// Ten little-endian 16-bit pointers at base + 0x10.
const tableOffset = 0x10;
stringAddresses.forEach((address, index) =>
  image.writeUInt16LE(address, tableOffset + index * 2),
);
hex("a5 b2 a1 bc a5 e0").copy(image, 0x200); // EUC-JP ゲーム
Buffer.from("Game", "utf16le").copy(image, 0x220);
hex("80 81 82 83 84 85").copy(image, 0x240); // character-table text

const profile = {
  schema_version: "dcomp.ghidra-profile.v1",
  profile_id: "authored-text-v1",
  platform: "nes",
  processor_language_id: "6502:LE:16:default",
  compiler_spec_id: "default",
  loader: "BinaryLoader",
  load_address: base,
  entry_address: base,
  analysis_timeout_seconds: 120,
  max_instruction_facts: 256,
};
const tableText = "80=こ\n81=ん\n82=に\n83=ち\n84=は\n85=です\n";

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-text-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const imagePath = join(workspace, "text.bin");
const profilePath = join(workspace, "text.profile.json");
const tablePath = join(workspace, "text.tbl");
await writeFile(imagePath, image, { mode: 0o600 });
await writeFile(profilePath, JSON.stringify(profile), { mode: 0o600 });
await writeFile(tablePath, tableText, { mode: 0o600 });
const imageDigest = digest(image);
const tableDigest = digest(Buffer.from(tableText));

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
const client = new Client({ name: "rea-real-text-proof", version: "1" });
let opened = false;
const report = {};
try {
  await client.connect(transport);
  await call("open_binary", {
    path: imagePath,
    format: "raw-image",
    raw_image_profile: profile,
    provider_id: "ghidra",
  });
  opened = true;
  const at = (offset) => `0x${(base + offset).toString(16)}`;

  // Shift-JIS: the exact bytes, address and file offset of the first string.
  const sjis = (
    await call("search_native_encoded_text", {
      pattern: "ゲーム",
      encoding: "shift_jis",
    })
  ).result;
  assert.equal(sjis.needle_hex, "8351815b8380");
  assert.equal(sjis.total_matches, 1);
  assert.equal(sjis.truncated, false);
  assert.equal(sjis.matches[0].address, at(0x100));
  assert.equal(sjis.matches[0].file_offset, 0x100);
  assert.equal(sjis.matches[0].bytes_hex, "8351815b8380");
  assert.ok(sjis.matches[0].text_from_match.startsWith("ゲーム"));
  assert.equal(sjis.regions.length, 1);

  // EUC-JP and UTF-16 find their own encodings of the same text, not each other's.
  const euc = (
    await call("search_native_encoded_text", {
      pattern: "ゲーム",
      encoding: "euc_jp",
    })
  ).result;
  assert.deepEqual(
    euc.matches.map((match) => match.address),
    [at(0x200)],
  );
  const wide = (
    await call("search_native_encoded_text", {
      pattern: "Game",
      encoding: "utf16le",
    })
  ).result;
  assert.deepEqual(
    wide.matches.map((match) => match.address),
    [at(0x220)],
  );

  // A pinned character table, longest entry first ("です" is one code).
  const tbl = (
    await call("search_native_encoded_text", {
      pattern: "こんにちはです",
      encoding: "table",
      table: { path: tablePath, sha256: tableDigest },
    })
  ).result;
  assert.equal(tbl.needle_hex, "808182838485");
  assert.deepEqual(tbl.table, { path: tablePath, sha256: tableDigest });
  assert.deepEqual(
    tbl.matches.map((match) => match.address),
    [at(0x240)],
  );
  assert.ok(tbl.matches[0].text_from_match.startsWith("こんにちはです"));
  await refused(
    "search_native_encoded_text",
    {
      pattern: "こんにちは",
      encoding: "table",
      table: { path: tablePath, sha256: "0".repeat(64) },
    },
    new RegExp(tableDigest),
  );
  await refused(
    "search_native_encoded_text",
    {
      pattern: "漢",
      encoding: "table",
      table: { path: tablePath, sha256: tableDigest },
    },
    /no entry/u,
  );
  await refused(
    "search_native_encoded_text",
    {
      pattern: "漢",
      encoding: "ascii",
    },
    /./u,
  );
  await refused(
    "search_native_encoded_text",
    {
      pattern: "x",
      encoding: "table",
    },
    /table/u,
  );

  // A window excludes matches outside it; a limit truncates but keeps the exact total.
  const windowed = (
    await call("search_native_encoded_text", {
      pattern: "ゲーム",
      encoding: "shift_jis",
      start: at(0x180),
      end: at(0x2ff),
    })
  ).result;
  assert.equal(windowed.total_matches, 0);
  assert.equal(windowed.regions[0].start, at(0x180));
  const limited = (
    await call("search_native_encoded_text", {
      pattern: "から",
      encoding: "shift_jis",
      limit: 1,
    })
  ).result;
  assert.equal(limited.total_matches, 2);
  assert.equal(limited.matches.length, 1);
  assert.equal(limited.truncated, true);

  // Pointer tables: the authored table is found with every target, and nothing else.
  const scan = (
    await call("scan_native_pointer_tables", {
      entry_size: 2,
      endianness: "little",
    })
  ).result;
  assert.equal(scan.total_candidates, 1);
  const [candidate] = scan.candidates;
  assert.equal(candidate.address, at(tableOffset));
  assert.equal(candidate.file_offset, tableOffset);
  assert.equal(candidate.entry_count, strings.length);
  assert.equal(candidate.strictly_ascending, true);
  assert.deepEqual(
    candidate.targets,
    stringAddresses.map((address) => `0x${address.toString(16)}`),
  );
  const tooLong = (
    await call("scan_native_pointer_tables", {
      entry_size: 2,
      endianness: "little",
      min_entries: strings.length + 1,
    })
  ).result;
  assert.equal(tooLong.total_candidates, 0);
  const bigEndian = (
    await call("scan_native_pointer_tables", {
      entry_size: 2,
      endianness: "big",
    })
  ).result;
  assert.ok(
    bigEndian.candidates.every((entry) => entry.address !== at(tableOffset)),
  );
  const window = (
    await call("scan_native_pointer_tables", {
      entry_size: 2,
      endianness: "little",
      target_start: at(0x100),
      target_end: at(0x105),
      min_entries: 2,
    })
  ).result;
  assert.equal(window.total_candidates, 0);
  const based = (
    await call("scan_native_pointer_tables", {
      entry_size: 2,
      endianness: "little",
      target_base: "0x10",
      min_entries: strings.length,
    })
  ).result;
  assert.equal(based.candidates[0]?.targets[0], at(0x110));

  // The CLI reports the same results the MCP tool returned.
  await call("close_binary");
  opened = false;
  const cliText = await cliEvidence("search-native-encoded-text", [
    "--pattern",
    "こんにちはです",
    "--encoding",
    "table",
    "--table",
    `${tableDigest}=${tablePath}`,
  ]);
  assert.deepEqual(cliText.normalized_result, tbl);
  const cliScan = await cliEvidence("scan-native-pointer-tables", [
    "--entry-size",
    "2",
    "--endianness",
    "little",
  ]);
  assert.deepEqual(cliScan.normalized_result, scan);
  assert.equal(digest(await readFile(imagePath)), imageDigest);

  report.text = {
    shift_jis: sjis.matches[0].address,
    euc_jp: euc.matches[0].address,
    utf16le: wide.matches[0].address,
    table: tbl.matches[0].address,
    pointer_table: {
      address: candidate.address,
      entries: candidate.entry_count,
    },
    cli_mcp_parity: true,
    original_unchanged: true,
  };
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
  return value.structuredContent;
}
async function refused(name, args, message) {
  const value = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.equal(value.isError, true, `${name} accepted ${JSON.stringify(args)}`);
  assert.match(JSON.stringify(value), message);
}
async function cliEvidence(command, options) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      command,
      imagePath,
      ...options,
      "--target-format",
      "raw-image",
      "--raw-image-profile",
      profilePath,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  return parseEvidence(JSON.parse(stdout));
}
