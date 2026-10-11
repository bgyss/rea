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

// Host-native fixtures: a "library" object linked into a reference executable
// (from which the Function ID database is built) and, under other names, into
// an application (which is then matched against that database).
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-signatures.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "verify:ghidra:signatures supports Linux/macOS hosts only; it builds with the host cc.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "verify:ghidra:signatures prerequisite missing: GHIDRA_INSTALL_DIR (bring your own Ghidra).",
  );
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `verify:ghidra:signatures prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const compiler = process.env.CC ?? "cc";
try {
  await promisify(execFile)(compiler, ["--version"]);
} catch (cause) {
  throw new Error(
    `verify:ghidra:signatures prerequisite missing: C compiler ${compiler} (set CC).`,
    { cause },
  );
}

const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const fixtureScripts = fileURLToPath(
  new URL("./verify/ghidra/", import.meta.url),
);
const headless = join(
  process.env.GHIDRA_INSTALL_DIR,
  "support",
  "analyzeHeadless",
);
// Mach-O prefixes C symbols with an underscore; ELF does not.
const prefix = process.platform === "darwin" ? "_" : "";

const sources = {
  "lib.c": `int lib_checksum(const unsigned char *p, int n) {
  int h = 17;
  for (int i = 0; i < n; i++) h = h * 31 + p[i];
  return h ^ (h >> 7);
}
int lib_scale(const int *v, int n, int lo, int hi) {
  int total = 0;
  for (int i = 0; i < n; i++) {
    int x = v[i] * 3 - (v[i] >> 2);
    if (x < lo) x = lo;
    else if (x > hi) x = hi;
    total += x ^ (i << 1);
  }
  return total - (total >> 5);
}
`,
  "libmain.c": `extern int lib_checksum(const unsigned char *, int);
extern int lib_scale(const int *, int, int, int);
int main(void) { unsigned char d[4] = {1,2,3,4}; int v[2] = {1, 2}; return lib_scale(v, 2, 0, 100) + lib_checksum(d, 4); }
`,
  "appmain.c": `extern int sub_a(const unsigned char *, int);
extern int sub_b(const int *, int, int, int);
static int app_only(int a) { int s = 0; for (int i = 0; i < a; i++) s += i * i - a; return s; }
int main(int argc, char **argv) { unsigned char d[8] = {9,8,7,6,5,4,3,2}; int v[3] = {argc, 7, 9}; return sub_b(v, 3, -5, 50) + sub_a(d, argc + 7) + app_only(argc) + (int)argv[0][0]; }
`,
};
const libraryFunctions = [`${prefix}lib_checksum`, `${prefix}lib_scale`];

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-signatures-proof-"));
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
const client = new Client({ name: "rea-real-signatures-proof", version: "1" });
let opened = false;
const report = {};
transport.stderr?.on("data", () => undefined);
try {
  for (const [name, text] of Object.entries(sources))
    await writeFile(join(workspace, name), text);
  await compile(["-O1", "-c", "lib.c", "-o", "lib.o"]);
  await compile(["-O1", "lib.o", "libmain.c", "-o", "library"]);
  // The application carries the same code under other names, so a match names
  // what the binary does not.
  await compile([
    "-O1",
    "-Dlib_checksum=sub_a",
    "-Dlib_scale=sub_b",
    "-c",
    "lib.c",
    "-o",
    "libapp.o",
  ]);
  await compile(["-O1", "libapp.o", "appmain.c", "-o", "app"]);

  const database = join(workspace, "libfixture.fidbf");
  await mkdir(join(workspace, "project"));
  // Ghidra saves attached Function ID databases in the user's preferences; a
  // private home keeps this build out of the real ones.
  const home = join(workspace, "home");
  await mkdir(home);
  await promisify(execFile)(
    headless,
    [
      join(workspace, "project"),
      "fid",
      "-import",
      join(workspace, "library"),
      "-scriptPath",
      fixtureScripts,
      "-postScript",
      "PopulateFixtureFid.java",
      database,
      "libfixture",
      "1.0",
      "release",
    ],
    {
      cwd: workspace,
      env: { ...env, HOME: home, TMPDIR: workspace },
      timeout: 240000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  const pinned = createHash("sha256")
    .update(await readFile(database))
    .digest("hex");

  await client.connect(transport);
  await call("open_binary", {
    path: join(workspace, "app"),
    provider_id: "ghidra",
  });
  opened = true;
  const before = JSON.stringify((await call("list_procedures")).result);
  assert.ok(
    !before.includes("lib_checksum"),
    `the application is not anonymous: ${before}`,
  );
  const reply = await call("match_native_function_signatures", {
    databases: [{ path: database, sha256: pinned }],
  });
  const evidence = parseEvidence(reply.evidence);
  assert.equal(evidence.operation, "match_native_function_signatures");
  assert.deepEqual(evidence.normalized_result, reply.result);
  const result = reply.result;

  assert.equal(result.databases.length, 1);
  assert.equal(result.databases[0].sha256, pinned);
  assert.equal(result.databases[0].path, database);
  assert.equal(result.databases[0].applies_to_target, true);
  assert.deepEqual(
    result.databases[0].libraries.map(({ family, version, variant }) => [
      family,
      version,
      variant,
    ]),
    [["libfixture", "1.0", "release"]],
  );
  const named = result.matches.flatMap(({ function: identity, candidates }) =>
    candidates.map((candidate) => ({ identity, candidate })),
  );
  const found = new Set(named.map(({ candidate }) => candidate.name));
  for (const name of libraryFunctions)
    assert.ok(found.has(name), `no ${name} among ${[...found]}`);
  for (const { identity, candidate } of named) {
    assert.equal(candidate.evidence_kind, "inferred");
    assert.equal(candidate.database_index, 0);
    assert.equal(candidate.library.family, "libfixture");
    // The application uses other names: the match names what the binary does not.
    assert.notEqual(identity.name, candidate.name, JSON.stringify(identity));
  }
  // Application code is not in the database and so is not named.
  assert.ok(
    result.matches.every(({ candidates }) =>
      candidates.every(({ name }) => name !== `${prefix}app_only`),
    ),
  );
  assert.ok(result.functions_examined >= 3);

  // Narrowing to one function reports exactly that function.
  const target = named.find(
    ({ candidate }) => candidate.name === `${prefix}lib_checksum`,
  );
  const narrowed = await call("match_native_function_signatures", {
    databases: [{ path: database, sha256: pinned }],
    procedure: target.identity.address,
  });
  assert.equal(narrowed.result.functions_examined, 1);
  assert.deepEqual(
    narrowed.result.matches.map(({ function: identity }) => identity.address),
    [target.identity.address],
  );

  // A database that does not match its pinned digest is refused before use.
  const refused = await client.callTool(
    {
      name: "match_native_function_signatures",
      arguments: { databases: [{ path: database, sha256: "0".repeat(64) }] },
    },
    { timeout: 240000 },
  );
  assert.equal(refused.isError, true);
  assert.match(JSON.stringify(refused.structuredContent), new RegExp(pinned));

  // The CLI reports the same matches the MCP tool returned.
  await call("close_binary");
  opened = false;
  const cli = await cliEvidence(join(workspace, "app"), database, pinned);
  assert.deepEqual(cli.normalized_result, result);

  report.signatures = {
    functions_examined: result.functions_examined,
    functions_too_short: result.functions_too_short,
    matched: named.map(({ identity, candidate }) => ({
      function: identity.name,
      candidate: candidate.name,
      library: candidate.library,
      match_mode: candidate.match_mode,
      overall: candidate.scores.overall,
    })),
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
async function cliEvidence(path, database, sha256) {
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "match-native-function-signatures",
      path,
      "--database",
      `${sha256}=${database}`,
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  return parseEvidence(JSON.parse(stdout));
}
