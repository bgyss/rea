import { mkdir, open, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";

import type { AnalysisOperationPort } from "./AnalysisProvider.js";
import { z } from "zod";

import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { Evidence } from "../domain/evidence.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  annotationLedgerEntrySchema,
  dataAnnotationLedgerEntrySchema,
  functionAnnotationLedgerEntrySchema,
  typeDefinitionLedgerEntrySchema,
  type AnnotationLedgerEntry,
  type AnnotationLedgerReplay,
} from "../domain/annotationLedger.js";
import type { AnnotationOperation } from "../domain/native/nativeDataAnnotations.js";
import { err, ok, type Result } from "../domain/result.js";

/** Ledgers are text journals; anything larger is not one. */
const MAX_LEDGER_BYTES = 64 * 1024 * 1024;

// The request fields each kind of ledger line records and replays; other
// request and entry keys (location, identity, provenance) are stripped.
const functionChangesSchema = z.object(
  functionAnnotationLedgerEntrySchema.pick({
    name: true,
    comment: true,
    inline_comment: true,
    signature: true,
    calling_convention: true,
    variables: true,
  }).shape,
);
const dataChangesSchema = z.object(
  dataAnnotationLedgerEntrySchema.pick({
    label: true,
    data_type: true,
    comment: true,
    inline_comment: true,
  }).shape,
);
const typeChangesSchema = z.object(
  typeDefinitionLedgerEntrySchema.pick({ declarations: true }).shape,
);

const changes = (
  schema:
    | typeof functionChangesSchema
    | typeof dataChangesSchema
    | typeof typeChangesSchema,
  value: unknown,
): Result<Record<string, JsonValue>, string> => {
  const parsed = schema.safeParse(value);
  return parsed.success
    ? ok(jsonObjectSchema.parse(parsed.data))
    : err(parsed.error.message);
};

// The request that re-applies one entry and what identifies it in a replay
// report. A parsed entry always carries its kind's change fields, so the
// projection is total.
const replayRequest = (
  entry: AnnotationLedgerEntry,
): {
  readonly operation: AnnotationOperation;
  readonly location:
    | { procedure: string }
    | { address: string }
    | { types: string[] };
  readonly arguments: Readonly<Record<string, JsonValue>>;
} => {
  if ("declarations" in entry)
    return {
      operation: "define_native_types",
      location: { types: entry.types },
      arguments: jsonObjectSchema.parse(typeChangesSchema.parse(entry)),
    };
  const [operation, location, schema] =
    "procedure" in entry
      ? ([
          "annotate_native_function",
          { procedure: entry.procedure },
          functionChangesSchema,
        ] as const)
      : ([
          "annotate_native_data",
          { address: entry.address },
          dataChangesSchema,
        ] as const);
  return {
    operation,
    location,
    arguments: {
      ...location,
      ...jsonObjectSchema.parse(schema.parse(entry)),
    },
  };
};

// Where an applied edit's ledger entry says it applied, from its readback:
// the canonical address, or the ids of the types it defined.
const recordedLocation = (
  operation: AnnotationOperation,
  readback: unknown,
): Result<
  { procedure: string } | { address: string } | { types: string[] },
  string
> => {
  if (operation === "define_native_types") {
    const parsed = z
      .object({ types: z.array(z.object({ id: z.string().min(1) })).min(1) })
      .safeParse(readback);
    return parsed.success
      ? ok({ types: parsed.data.types.map((type) => type.id) })
      : err("its readback lacks the defined type ids the ledger needs");
  }
  const parsed = z
    .object({ annotations: z.object({ address: z.string().min(1) }) })
    .safeParse(readback);
  if (!parsed.success)
    return err("its readback lacks the canonical address the ledger needs");
  const address = parsed.data.annotations.address;
  return ok(
    operation === "annotate_native_function"
      ? { procedure: address }
      : { address },
  );
};

const CHANGE_SCHEMAS = {
  annotate_native_function: functionChangesSchema,
  annotate_native_data: dataChangesSchema,
  define_native_types: typeChangesSchema,
} as const satisfies Record<AnnotationOperation, unknown>;

/** The ledger an open target records into, with the identity it was opened under. */
export interface AnnotationLedgerTarget {
  readonly path: string;
  readonly targetSha256: string;
  readonly profileDigest: string | null;
}

/** Session-scoped ledger selection shared by open/close and annotation tools. */
export class AnnotationLedgerBinding {
  #bound: AnnotationLedgerTarget | undefined;

  bind(target: AnnotationLedgerTarget): void {
    this.#bound = target;
  }

  clear(): void {
    this.#bound = undefined;
  }

  current(): AnnotationLedgerTarget | undefined {
    return this.#bound;
  }
}

const ledgerError = (
  operation: string,
  message: string,
  cause?: unknown,
): AnalysisError =>
  new AnalysisInputError(
    operation,
    cause === undefined ? undefined : { cause },
    [{ path: ["annotation_ledger_path"], reason: "invalid_value", message }],
  );

/**
 * Read every entry. A missing file is an empty ledger; a malformed line fails
 * the whole read so a damaged ledger is never applied partially.
 */
export const readAnnotationLedger = async (
  path: string,
  operation: string,
): Promise<Result<AnnotationLedgerEntry[], AnalysisError>> => {
  let text: string;
  try {
    const size = (await stat(path)).size;
    if (size > MAX_LEDGER_BYTES)
      return err(
        ledgerError(
          operation,
          `Annotation ledger exceeds ${MAX_LEDGER_BYTES} bytes`,
        ),
      );
    text = await readFile(path, "utf8");
  } catch (cause: unknown) {
    if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
      return ok([]);
    return err(
      ledgerError(operation, `Cannot read annotation ledger ${path}`, cause),
    );
  }
  const entries: AnnotationLedgerEntry[] = [];
  for (const [index, line] of text.split("\n").entries()) {
    if (line.trim() === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch (cause: unknown) {
      return err(
        ledgerError(
          operation,
          `Annotation ledger line ${index + 1} is not JSON`,
          cause,
        ),
      );
    }
    const entry = annotationLedgerEntrySchema.safeParse(parsed);
    if (!entry.success)
      return err(
        ledgerError(
          operation,
          `Annotation ledger line ${index + 1} is not a rea.annotation-ledger.v1 entry`,
          entry.error,
        ),
      );
    entries.push(entry.data);
  }
  return ok(entries);
};

/** Append one entry as a single synced line, creating the file and parent directory. */
export const appendAnnotationLedger = async (
  path: string,
  entry: AnnotationLedgerEntry,
): Promise<Result<null, string>> => {
  try {
    await mkdir(dirname(path), { recursive: true });
    const handle = await open(path, "a", 0o600);
    try {
      await handle.write(
        `${JSON.stringify(annotationLedgerEntrySchema.parse(entry))}\n`,
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    return ok(null);
  } catch (cause: unknown) {
    return err(cause instanceof Error ? cause.message : String(cause));
  }
};

/**
 * Re-apply entries recorded for exactly this target and analysis profile, in
 * order. Matching digests guarantee identical bytes and address meaning; other
 * entries are counted, not guessed onto different code.
 */
export const replayAnnotationLedger = async (
  analysis: AnalysisOperationPort,
  target: AnnotationLedgerTarget,
  options: { readonly signal?: AbortSignal } = {},
): Promise<Result<AnnotationLedgerReplay, AnalysisError>> => {
  const entries = await readAnnotationLedger(target.path, "open_binary");
  if (!entries.ok) return entries;
  const report: AnnotationLedgerReplay = {
    path: target.path,
    entries: entries.value.length,
    applied: 0,
    skipped_other_target: 0,
    skipped_other_profile: 0,
    failed: [],
  };
  for (const [index, entry] of entries.value.entries()) {
    if (entry.target_sha256 !== target.targetSha256) {
      report.skipped_other_target += 1;
      continue;
    }
    if (entry.analysis_profile_digest !== target.profileDigest) {
      report.skipped_other_profile += 1;
      continue;
    }
    const request = replayRequest(entry);
    const applied = await analysis.execute(
      request.operation,
      request.arguments,
      options.signal === undefined ? {} : { signal: options.signal },
    );
    if (applied.ok) report.applied += 1;
    else
      report.failed.push({
        line: index + 1,
        ...request.location,
        reason: applied.error.message,
      });
  }
  return ok(report);
};

/**
 * Append an applied annotation, taking its canonical address (or defined type
 * ids) from the readback. The edit already happened, so a failed append says
 * exactly that.
 */
export const appendAnnotationFromEvidence = async (
  bound: AnnotationLedgerTarget,
  operation: AnnotationOperation,
  arguments_: Readonly<Record<string, JsonValue>>,
  evidence: Evidence,
): Promise<Result<null, AnalysisError>> => {
  const notRecorded = (reason: string) =>
    err(
      new AnalysisOutputError(
        operation,
        `The annotation was applied in this session but ${reason}`,
      ),
    );
  const location = recordedLocation(operation, evidence.normalized_result);
  if (!location.ok) return notRecorded(location.error);
  const recorded = changes(CHANGE_SCHEMAS[operation], arguments_);
  if (!recorded.ok)
    return notRecorded(
      `its request could not be recorded in the ledger: ${recorded.error}`,
    );
  const entry = annotationLedgerEntrySchema.safeParse({
    schema_version: "rea.annotation-ledger.v1",
    target_sha256: bound.targetSha256,
    analysis_profile_digest: bound.profileDigest,
    ...location.value,
    ...recorded.value,
    evidence_id: evidence.evidence_id,
    recorded_at: new Date().toISOString(),
  });
  if (!entry.success)
    return notRecorded(`its ledger entry is malformed: ${entry.error.message}`);
  const appended = await appendAnnotationLedger(bound.path, entry.data);
  return appended.ok
    ? ok(null)
    : notRecorded(`could not be appended to ${bound.path}: ${appended.error}`);
};
