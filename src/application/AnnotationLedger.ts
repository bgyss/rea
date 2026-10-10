import { mkdir, open, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";

import type { AnalysisOperationPort } from "./AnalysisProvider.js";
import { z } from "zod";

import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { Evidence } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  annotationLedgerEntrySchema,
  type AnnotationLedgerEntry,
  type AnnotationLedgerReplay,
} from "../domain/annotationLedger.js";
import { err, ok, type Result } from "../domain/result.js";

/** Ledgers are text journals; anything larger is not one. */
const MAX_LEDGER_BYTES = 64 * 1024 * 1024;

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
    const applied = await analysis.execute(
      "annotate_native_function",
      {
        procedure: entry.procedure,
        ...(entry.name === undefined ? {} : { name: entry.name }),
        ...(entry.comment === undefined ? {} : { comment: entry.comment }),
        ...(entry.inline_comment === undefined
          ? {}
          : { inline_comment: entry.inline_comment }),
      },
      options.signal === undefined ? {} : { signal: options.signal },
    );
    if (applied.ok) report.applied += 1;
    else
      report.failed.push({
        line: index + 1,
        procedure: entry.procedure,
        reason: applied.error.message,
      });
  }
  return ok(report);
};

/**
 * Append an applied annotation, taking the entry address from the refreshed
 * readback. The edit already happened, so a failed append says exactly that.
 */
export const appendAnnotationFromEvidence = async (
  bound: AnnotationLedgerTarget,
  arguments_: Readonly<Record<string, JsonValue>>,
  evidence: Evidence,
): Promise<Result<null, AnalysisError>> => {
  const readback = z
    .object({ annotations: z.object({ address: z.string().min(1) }) })
    .safeParse(evidence.normalized_result);
  if (!readback.success)
    return err(
      new AnalysisOutputError(
        "annotate_native_function",
        "annotation readback lacks the function entry address needed for the ledger",
      ),
    );
  const text = (key: string) => {
    const value = arguments_[key];
    return typeof value === "string" ? { [key]: value } : {};
  };
  const appended = await appendAnnotationLedger(bound.path, {
    schema_version: "rea.annotation-ledger.v1",
    target_sha256: bound.targetSha256,
    analysis_profile_digest: bound.profileDigest,
    procedure: readback.data.annotations.address,
    ...text("name"),
    ...text("comment"),
    ...text("inline_comment"),
    evidence_id: evidence.evidence_id,
    recorded_at: new Date().toISOString(),
  });
  return appended.ok
    ? ok(null)
    : err(
        new AnalysisOutputError(
          "annotate_native_function",
          `The annotation was applied in this session but could not be appended to ${bound.path}: ${appended.error}`,
        ),
      );
};
