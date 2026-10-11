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
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Host-native fixtures: the same C function built into a linked executable
// (the "original") and into relocatable objects (the "candidates").
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-compare.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:compare supports Linux/macOS hosts only; it builds with the host cc.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:compare prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:compare prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const compiler = process.env.CC ?? "cc";
try {
  await promisify(execFile)(compiler, ["--version"]);
} catch (cause) {
  throw new Error(
    `verify:ghidra:compare prerequisite missing: C compiler ${compiler} (set CC).`,
    { cause },
  );
}

const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
// Mach-O prefixes C symbols with an underscore; ELF does not.
const prefix = process.platform === "darwin" ? "_" : "";

const helperSource = "int helper(int v) { return v * 3 + 1; }\n";
const targetSource = (adjust) => `extern int helper(int v);
int counter = 4;
int target(int v) { return ${adjust}; }
int main(void) { return target(2); }
`;
const original = targetSource("helper(v) + counter + 7");
const candidates = {
  matching: original,
  "wrong-constant": targetSource("helper(v) + counter + 8"),
  "missing-term": targetSource("helper(v) + 7"),
};

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-compare-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
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
const client = new Client({ name: "rea-real-compare-proof", version: "1" });
let opened = false;
let stderr = "";
const report = {};
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
try {
  await writeFile(join(workspace, "helper.c"), helperSource);
  await compile(["-O1", "-c", "helper.c", "-o", "helper.o"]);
  const objects = {};
  for (const [name, source] of Object.entries({
    original,
    ...candidates,
  })) {
    await writeFile(join(workspace, `${name}.c`), source);
    await compile(["-O1", "-c", `${name}.c`, "-o", `${name}.o`]);
    objects[name] = join(workspace, `${name}.o`);
  }
  const executable = join(workspace, "original");
  await compile(["-O1", "original.o", "helper.o", "-o", "original"]);

  await client.connect(transport);
  const left = await listing(executable, `${prefix}target`);
  const entries = left.result.instructions;
  assert.ok(entries.length >= 5, "original listing is unexpectedly short");
  assert.ok(
    entries.every((item) => item.relocations.length === 0),
    "a linked executable must not carry object relocations",
  );

  // The same function, compared with itself, is identical.
  const same = await compare(left, left);
  assert.equal(same.verdict, "identical");
  assert.equal(same.score, 1);
  assert.equal(same.first_divergence, null);

  // Object candidates are addressed by their first (and only) function.
  const matching = await listing(objects.matching, "0x0");
  const relocated = matching.result.instructions.filter(
    (item) => item.relocations.length > 0,
  );
  assert.ok(relocated.length >= 2, "the object lists no relocations");
  const symbols = relocated.flatMap((item) =>
    item.relocations.map(({ symbol }) => symbol),
  );
  assert.ok(symbols.includes(`${prefix}helper`), `no helper in ${symbols}`);
  assert.ok(symbols.includes(`${prefix}counter`), `no counter in ${symbols}`);
  const equivalent = await compare(left, matching);
  assert.equal(equivalent.verdict, "equivalent_masked");
  assert.equal(equivalent.score, 1);
  assert.equal(equivalent.first_divergence, null);
  assert.deepEqual(
    [
      equivalent.counts.replaced,
      equivalent.counts.left_only,
      equivalent.counts.right_only,
    ],
    [0, 0, 0],
  );
  assert.ok(equivalent.counts.masked >= 2);
  assert.equal(
    equivalent.counts.matched + equivalent.counts.masked,
    entries.length,
  );
  assert.deepEqual(
    equivalent.right_relocations.map(({ symbol }) => symbol).sort(),
    symbols.slice().sort(),
  );

  // A wrong constant is not hidden by relocation masking.
  const wrong = await listing(objects["wrong-constant"], "0x0");
  const different = await compare(left, wrong);
  assert.equal(different.verdict, "different");
  assert.equal(different.first_divergence.kind, "replace");
  assert.equal(different.first_divergence.differences[0].kind, "operand");
  assert.match(different.first_divergence.differences[0].left, /7/u);
  assert.match(different.first_divergence.differences[0].right, /8/u);
  assert.ok(different.score < 1 && different.score > 0.7);

  // Masking immediates by policy deliberately ignores that same constant.
  const masked = await compare(left, wrong, { immediates: "mask" });
  assert.equal(masked.verdict, "equivalent_masked");
  assert.ok(
    masked.rows.some(
      (row) =>
        row.kind === "masked" &&
        row.masked.some(({ reason }) => reason === "immediate_policy"),
    ),
  );

  // A missing term shows up as unmatched original instructions.
  const missing = await listing(objects["missing-term"], "0x0");
  const shorter = await compare(left, missing);
  assert.equal(shorter.verdict, "different");
  assert.ok(
    shorter.counts.left_only + shorter.counts.replaced > 0,
    "the removed term was not reported",
  );
  assert.ok(shorter.first_divergence !== null);

  // The CLI reports the same listing the MCP tool returned.
  const cliListing = await cliListingEvidence(objects.matching, "0x0");
  assert.deepEqual(cliListing.normalized_result, matching.result);

  report.compare = {
    architecture: equivalent.architecture,
    original_instructions: entries.length,
    relocation_symbols: symbols,
    equivalent: equivalent.counts,
    wrong_constant: {
      verdict: different.verdict,
      score: different.score,
      first: different.first_divergence.differences[0],
    },
    missing_term: shorter.counts,
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

async function compile(args) {
  await promisify(execFile)(compiler, args, { cwd: workspace });
}
async function call(name, args = {}) {
  const value = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(value.isError, true, JSON.stringify(value));
  return value.structuredContent;
}
async function listing(path, procedure) {
  await call("open_binary", { path, provider_id: "ghidra" });
  opened = true;
  const reply = await call("inspect_native_function_instructions", {
    procedure,
  });
  const evidence = parseEvidence(reply.evidence);
  assert.deepEqual(evidence.normalized_result, reply.result);
  await call("close_binary");
  opened = false;
  return { evidence: reply.evidence, result: reply.result };
}
async function compare(left, right, masking) {
  // A comparison reads only the Evidence passed in; it needs no open session.
  const reply = await call("compare_compiled_function", {
    left: left.evidence,
    right: right.evidence,
    ...(masking === undefined ? {} : { masking }),
  });
  const evidence = parseEvidence(reply.evidence);
  assert.equal(evidence.operation, "compare_compiled_function");
  assert.deepEqual(evidence.normalized_result, reply.result);
  assert.deepEqual(evidence.evidence_links, [
    left.evidence.evidence_id,
    right.evidence.evidence_id,
  ]);
  return reply.result;
}
async function cliListingEvidence(path, procedure) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "inspect-native-function-instructions",
      path,
      procedure,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  return parseEvidence(JSON.parse(stdout));
}
