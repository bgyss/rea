import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  appendAnnotationLedger,
  readAnnotationLedger,
  replayAnnotationLedger,
} from "./AnnotationLedger.js";
import {
  createAnalysisExecution,
  type AnalysisOperationPort,
} from "./AnalysisProvider.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type { FunctionAnnotationLedgerEntry } from "../domain/annotationLedger.js";
import { err, ok } from "../domain/result.js";

const sha = "a".repeat(64);
const profile = "b".repeat(64);
const entry = (
  fields: Partial<FunctionAnnotationLedgerEntry> = {},
): FunctionAnnotationLedgerEntry => ({
  schema_version: "rea.annotation-ledger.v1",
  target_sha256: sha,
  analysis_profile_digest: profile,
  procedure: "0x8000",
  name: "reset_handler",
  evidence_id: `ev_${"c".repeat(64)}`,
  recorded_at: "2026-10-10T00:00:00.000Z",
  ...fields,
});

const ledgerPath = async (name = "ledger.jsonl") =>
  join(await mkdtemp(join(tmpdir(), "rea-ledger-")), "nested", name);

describe("annotation ledger files", () => {
  it("treats a missing file as an empty ledger", async () => {
    expect(
      await readAnnotationLedger(await ledgerPath(), "open_binary"),
    ).toEqual(ok([]));
  });

  it("appends synced lines that read back in order, creating the directory", async () => {
    const path = await ledgerPath();
    expect(await appendAnnotationLedger(path, entry())).toEqual(ok(null));
    expect(
      await appendAnnotationLedger(
        path,
        entry({ procedure: "0x8010", name: "nmi" }),
      ),
    ).toEqual(ok(null));
    const read = await readAnnotationLedger(path, "open_binary");
    if (!read.ok) throw read.error;
    expect(
      read.value.map((item) => ("procedure" in item ? item.procedure : null)),
    ).toEqual(["0x8000", "0x8010"]);
    expect((await readFile(path, "utf8")).split("\n")).toHaveLength(3);
  });

  it.each([
    ["not JSON", "{oops", "line 2 is not JSON"],
    [
      "an unknown field",
      JSON.stringify({ ...entry(), verified: true }),
      "line 2 is not a rea.annotation-ledger.v1 entry",
    ],
  ])("fails the whole read on %s", async (_name, bad, message) => {
    const path = await ledgerPath();
    await appendAnnotationLedger(path, entry());
    await writeFile(path, `${bad}\n`, { flag: "a" });
    const read = await readAnnotationLedger(path, "open_binary");
    if (read.ok) throw new Error("Expected a malformed-ledger failure");
    if (!(read.error instanceof AnalysisInputError))
      throw new Error("Expected a typed input error");
    expect(JSON.stringify(read.error.issues)).toContain(message);
  });
});

describe("annotation ledger replay", () => {
  it("applies only this target and profile, in order, and lists failures", async () => {
    const path = await ledgerPath();
    const { name: _name, ...unnamed } = entry();
    const commentOnly = { ...unnamed, comment: "Resets RAM" };
    for (const item of [
      entry(),
      entry({ target_sha256: "d".repeat(64) }),
      entry({ analysis_profile_digest: null }),
      entry({ procedure: "0x9999", name: "missing" }),
      commentOnly,
    ])
      expect(await appendAnnotationLedger(path, item)).toEqual(ok(null));
    const requests: Readonly<Record<string, unknown>>[] = [];
    const analysis: AnalysisOperationPort = {
      execute: (_operation, parameters) => {
        requests.push(parameters);
        return Promise.resolve(
          parameters["procedure"] === "0x9999"
            ? err(new AnalysisInputError("annotate_native_function"))
            : ok(
                createAnalysisExecution(
                  {},
                  { id: "fake", name: "Fake", version: "1" },
                ),
              ),
        );
      },
    };
    const replay = await replayAnnotationLedger(analysis, {
      path,
      targetSha256: sha,
      profileDigest: profile,
    });
    if (!replay.ok) throw replay.error;
    expect(requests).toEqual([
      { procedure: "0x8000", name: "reset_handler" },
      { procedure: "0x9999", name: "missing" },
      { procedure: "0x8000", comment: "Resets RAM" },
    ]);
    expect(replay.value).toMatchObject({
      entries: 5,
      applied: 2,
      skipped_other_target: 1,
      skipped_other_profile: 1,
      failed: [{ line: 4, procedure: "0x9999" }],
    });
  });

  it("replays address entries through annotate_native_data and reports their address", async () => {
    const path = await ledgerPath();
    const { procedure: _procedure, name: _name, ...identity } = entry();
    for (const item of [
      {
        ...identity,
        address: "0x2000",
        label: "ppu_ctrl",
        data_type: "uint8_t",
      },
      { ...identity, address: "0x9999", comment: "missing" },
    ])
      expect(await appendAnnotationLedger(path, item)).toEqual(ok(null));
    const calls: unknown[] = [];
    const replay = await replayAnnotationLedger(
      {
        execute: (operation, parameters) => {
          calls.push([operation, parameters]);
          return Promise.resolve(
            parameters["address"] === "0x9999"
              ? err(new AnalysisInputError("annotate_native_data"))
              : ok(
                  createAnalysisExecution(
                    {},
                    { id: "fake", name: "Fake", version: "1" },
                  ),
                ),
          );
        },
      },
      { path, targetSha256: sha, profileDigest: profile },
    );
    if (!replay.ok) throw replay.error;
    expect(calls).toEqual([
      [
        "annotate_native_data",
        { address: "0x2000", label: "ppu_ctrl", data_type: "uint8_t" },
      ],
      ["annotate_native_data", { address: "0x9999", comment: "missing" }],
    ]);
    expect(replay.value).toMatchObject({
      applied: 1,
      failed: [{ line: 2, address: "0x9999" }],
    });
  });

  it("replays signature, convention, and variable edits exactly as recorded", async () => {
    const path = await ledgerPath();
    const typed = entry({
      signature: "void reset_handler(uint8_t mode)",
      calling_convention: "__stdcall",
      variables: [
        { name: "uVar1", new_name: "counter", data_type: "uint16_t" },
        { name: "param_1", new_name: "mode" },
      ],
    });
    expect(await appendAnnotationLedger(path, typed)).toEqual(ok(null));
    const requests: Readonly<Record<string, unknown>>[] = [];
    const replay = await replayAnnotationLedger(
      {
        execute: (_operation, parameters) => {
          requests.push(parameters);
          return Promise.resolve(
            ok(
              createAnalysisExecution(
                {},
                { id: "fake", name: "Fake", version: "1" },
              ),
            ),
          );
        },
      },
      { path, targetSha256: sha, profileDigest: profile },
    );
    if (!replay.ok) throw replay.error;
    expect(requests).toEqual([
      {
        procedure: "0x8000",
        name: "reset_handler",
        signature: "void reset_handler(uint8_t mode)",
        calling_convention: "__stdcall",
        variables: [
          { name: "uVar1", new_name: "counter", data_type: "uint16_t" },
          { name: "param_1", new_name: "mode" },
        ],
      },
    ]);
  });
});
