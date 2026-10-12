#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import {
  FIXTURE_IMAGE_BASE,
  RODATA_TEXT,
  buildNro,
  buildNso,
} from "./lib/switch-fixture.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Authored Switch fixtures: no game data. The NSO/NRO loader is built from this
// repository and pinned by digest, exactly as an operator would configure it.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-nxo.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:nxo supports Linux/macOS hosts only; pinned loaders are not supported on Windows.",
  );
for (const name of ["GHIDRA_INSTALL_DIR", "JAVA_HOME"])
  if (process.env[name] === undefined)
    throw new Error(
      `verify:ghidra:nxo prerequisite missing: ${name} (run inside \`nix develop\`).`,
    );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:nxo prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const compiler = process.env.CC ?? "cc";
try {
  await promisify(execFile)(compiler, ["--version"]);
} catch (cause) {
  throw new Error(
    `verify:ghidra:nxo prerequisite missing: C compiler ${compiler} (set CC); it must also assemble for aarch64.`,
    { cause },
  );
}

const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const buildScript = fileURLToPath(
  new URL("./build-ghidra-switch-loader.mjs", import.meta.url),
);
const hex = (value) => `0x${value.toString(16)}`;
const at = (offset) => hex(FIXTURE_IMAGE_BASE + BigInt(offset));

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-nxo-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const baseEnv = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  JAVA_HOME: process.env.JAVA_HOME,
};

const opened = [];
const connections = [];
const report = {};
try {
  const built = JSON.parse(
    (
      await promisify(execFile)(process.execPath, [
        buildScript,
        "--out",
        join(workspace, "loader"),
      ])
    ).stdout,
  );
  const pin = (sha256 = built.sha256) =>
    JSON.stringify([
      {
        id: "switch-nxo",
        path: built.jar,
        sha256,
        loader_name: "ReaSwitchLoader",
      },
    ]);
  const pinnedEnv = { ...baseEnv, REA_GHIDRA_LOADER_EXTENSIONS_JSON: pin() };

  const fixtures = {
    "nso-compressed": {
      bytes: buildNso({ compressRodata: true }),
      format: "switch-nso",
    },
    "nso-plain": {
      bytes: buildNso({ compressRodata: false }),
      format: "switch-nso",
    },
    "app.nro": { bytes: buildNro(), format: "switch-nro" },
  };
  for (const [name, { bytes }] of Object.entries(fixtures))
    await writeFile(join(workspace, name), bytes);

  const connect = async (env) => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env,
      stderr: "pipe",
    });
    transport.stderr?.on("data", () => undefined);
    const client = new Client({ name: "rea-real-nxo-proof", version: "1" });
    await client.connect(transport);
    connections.push({ client, transport });
    return client;
  };
  const client = await connect(pinnedEnv);

  const expected = {
    nso: [
      [".text", at(0), at(8), "r-x", true],
      [".rodata", at(0x1000), at(0x1011), "r--", true],
      [".data", at(0x2000), at(0x2004), "rw-", true],
      [".bss", at(0x2004), at(0x2104), "rw-", false],
    ],
    nro: [
      [".text", at(0), at(0x200), "r-x", true],
      [".rodata", at(0x200), at(0x280), "r--", true],
      [".data", at(0x280), at(0x300), "rw-", true],
      // MOD0 bss_end - bss_start overrides the header's 0x40.
      [".bss", at(0x300), at(0x3c0), "rw-", false],
    ],
  };
  const permissions = (s) =>
    `${s.readable ? "r" : "-"}${s.writable ? "w" : "-"}${s.executable ? "x" : "-"}`;

  const inspect = async (name) => {
    const { format } = fixtures[name];
    const path = join(workspace, name);
    await call(client, "open_binary", { path, format, provider_id: "ghidra" });
    opened.push(client);
    const segments = (await call(client, "list_segments")).result.map((s) => [
      s.name,
      s.start,
      s.end,
      permissions(s),
      s.initialized,
    ]);
    assert.deepEqual(
      segments,
      expected[format === "switch-nso" ? "nso" : "nro"],
      `${name}: memory map`,
    );
    const procedures = (await call(client, "list_procedures")).result;
    assert.equal(procedures[0].address, at(0));
    assert.equal(procedures[0].value, "entry");
    const code = format === "switch-nso" ? at(0) : at(0x100);
    if (format === "switch-nro") {
      assert.equal(procedures[0].procedure.thunk_target, at(0x100));
    }
    const listing = await call(client, "inspect_native_function_instructions", {
      procedure: code,
    });
    assert.deepEqual(
      listing.result.instructions.map((item) => item.mnemonic),
      ["nop", "ret"],
      `${name}: entry code`,
    );
    let rodata = null;
    if (format === "switch-nso") {
      rodata = await call(client, "read_bytes", {
        address: at(0x1000),
        length: RODATA_TEXT.length,
      });
      assert.equal(
        Buffer.from(rodata.result.bytes_hex, "hex").toString("ascii"),
        RODATA_TEXT,
        `${name}: rodata decodes`,
      );
      assert.equal(rodata.result.complete, true);
    }
    const evidence = { listing: listing.evidence };
    await call(client, "close_binary");
    opened.pop();
    return { segments, rodata, ...evidence };
  };

  const compressed = await inspect("nso-compressed");
  const plain = await inspect("nso-plain");
  // LZ4 and stored segments describe the same image.
  assert.deepEqual(compressed.segments, plain.segments);
  assert.deepEqual(compressed.rodata.result, plain.rodata.result);
  const nro = await inspect("app.nro");

  // The NSO entry compares against an object built from the same instructions.
  await writeFile(
    join(workspace, "fn.s"),
    ".text\n.globl fn\nfn:\n  nop\n  ret\n",
  );
  await promisify(execFile)(
    compiler,
    ["--target=aarch64-linux-gnu", "-c", "fn.s", "-o", "fn.o"],
    { cwd: workspace },
  );
  const objectClient = client;
  await call(objectClient, "open_binary", {
    path: join(workspace, "fn.o"),
    provider_id: "ghidra",
  });
  opened.push(objectClient);
  const right = await call(
    objectClient,
    "inspect_native_function_instructions",
    {
      procedure: "fn",
    },
  );
  await call(objectClient, "close_binary");
  opened.pop();
  const comparison = await call(client, "compare_compiled_function", {
    left: compressed.listing,
    right: right.evidence,
  });
  assert.equal(comparison.operation, "compare_compiled_function");
  assert.ok(
    ["identical", "equivalent_masked"].includes(comparison.result.verdict),
    JSON.stringify(comparison.result),
  );
  assert.equal(comparison.result.score, 1);
  assert.equal(comparison.result.first_divergence, null);

  // A hint that disagrees with the header is refused before Ghidra starts.
  const wrongHint = await client.callTool({
    name: "open_binary",
    arguments: {
      path: join(workspace, "nso-plain"),
      format: "switch-nro",
      provider_id: "ghidra",
    },
  });
  assert.equal(wrongHint.isError, true);
  assert.match(JSON.stringify(wrongHint.content), /NRO0/u);

  // No pinned loader, or one that does not match its digest, never falls back.
  const bare = await connect(baseEnv);
  const missing = await bare.callTool({
    name: "open_binary",
    arguments: {
      path: join(workspace, "nso-plain"),
      format: "switch-nso",
      provider_id: "ghidra",
    },
  });
  assert.equal(missing.isError, true);
  assert.match(
    JSON.stringify(missing.content),
    /REA_GHIDRA_LOADER_EXTENSIONS_JSON/u,
  );
  const mismatched = await connect({
    ...baseEnv,
    REA_GHIDRA_LOADER_EXTENSIONS_JSON: pin("0".repeat(64)),
  });
  const wrongDigest = await mismatched.callTool({
    name: "open_binary",
    arguments: {
      path: join(workspace, "nso-plain"),
      format: "switch-nso",
      provider_id: "ghidra",
    },
  });
  assert.equal(wrongDigest.isError, true);
  assert.match(JSON.stringify(wrongDigest.content), new RegExp(built.sha256));

  // The CLI reports the same bytes the MCP tool returned.
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "read-bytes",
      join(workspace, "nso-compressed"),
      at(0x1000),
      "--length",
      String(RODATA_TEXT.length),
      "--target-format",
      "switch-nso",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env: pinnedEnv, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  assert.deepEqual(
    parseEvidence(JSON.parse(stdout)).normalized_result,
    compressed.rodata.result,
  );

  report.nxo = {
    loader_sha256: built.sha256,
    nso_segments: compressed.segments,
    nro_segments: nro.segments,
    compare: {
      verdict: comparison.result.verdict,
      score: comparison.result.score,
    },
  };
} finally {
  for (const client of opened.splice(0))
    await call(client, "close_binary").catch((error) =>
      process.stderr.write(String(error)),
    );
  for (const { client, transport } of connections.splice(0)) {
    await client.close();
    await transport.close();
  }
  await rm(workspace, { recursive: true, force: true });
}
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
process.stdout.write(
  `${JSON.stringify({
    verifier_run: verifierRun,
    ghidra_version: installation.providerVersion,
    ...report,
    cleanup: "complete",
  })}\n`,
);

/** Evidence carries its operation result as normalized_result. */
function withResult(content) {
  return "normalized_result" in content
    ? { ...content, result: content.normalized_result, evidence: content }
    : content;
}
async function call(client, name, args = {}) {
  const value = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(value.isError, true, JSON.stringify(value));
  return withResult(value.structuredContent);
}
