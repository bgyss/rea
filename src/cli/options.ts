import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import {
  executableFormatHintSchema,
  resolveExecutableFormatHint,
  type ExecutableFormatSelector,
} from "../domain/dosCom.js";
import {
  rawImageProfileSchema,
  type RawImageProfile,
} from "../domain/rawImage.js";
import { analysisProviderSelectorSchema } from "../contracts/providerSelection.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";
import type { Logger } from "../logger.js";
import { err, ok, type Result } from "../domain/result.js";

export const providerSelectionOption = analysisProviderSelectorSchema
  .optional()
  .describe(
    "Bind deep analysis to a provider ID or use deterministic auto selection",
  );

/** Profile JSON is small; anything larger is not a profile. */
const MAX_RAW_IMAGE_PROFILE_BYTES = 64 * 1024;

/** Read and validate one raw-image profile file named on the command line. */
const readRawImageProfile = (path: string): Result<RawImageProfile, string> => {
  let parsed: unknown;
  try {
    const text = readFileSync(path, "utf8");
    if (Buffer.byteLength(text) > MAX_RAW_IMAGE_PROFILE_BYTES)
      throw new Error(`profile exceeds ${MAX_RAW_IMAGE_PROFILE_BYTES} bytes`);
    parsed = JSON.parse(text);
  } catch (cause: unknown) {
    return err(
      `Cannot read raw image profile ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const profile = rawImageProfileSchema.safeParse(parsed);
  return profile.success
    ? ok(profile.data)
    : err(
        profile.error.issues
          .map(
            (issue) =>
              `Invalid raw image profile ${path} at ${issue.path.join(".") || "(root)"}: ${issue.message}`,
          )
          .join("; "),
      );
};

// A plain path: the CLI catalog renders options as JSON Schema, which cannot
// represent a parsing transform, so the file is read in directAnalysisOptions.
const rawImageProfileOption = z
  .string()
  .min(1)
  .optional()
  .describe(
    "Path to a dcomp.ghidra-profile.v1 (flat: load_address, entry_address) or v2 (blocks) JSON file with processor_language_id and compiler_spec_id; required with --target-format raw-image",
  );

/** Explicit interpretation for headerless executable bytes, shared by analysis commands. */
export const formatSelectionOptions = {
  "target-format": executableFormatHintSchema
    .optional()
    .describe(
      "Explicit headerless interpretation: dos-com, or raw-image with --raw-image-profile",
    ),
  "raw-image-profile": rawImageProfileOption,
};

/** Annotation ledger replayed after opening; the annotate commands also append. */
export const annotationLedgerOptions = {
  "annotation-ledger": z
    .string()
    .min(1)
    .optional()
    .describe(
      "JSON Lines annotation ledger: replay entries recorded for this exact target and profile after opening; annotate-native-function and annotate-native-data also append their edit",
    ),
};

/** Parsed values of {@link formatSelectionOptions} and {@link annotationLedgerOptions}. */
export interface FormatSelection {
  readonly "target-format"?: ExecutableFormatSelector | undefined;
  readonly "raw-image-profile"?: string | undefined;
  readonly "annotation-ledger"?: string | undefined;
}

/**
 * Shared direct-analysis options. An inconsistent format selection is carried
 * to the analysis entry point, which reports it as a typed input error.
 */
export const directAnalysisOptions = (
  logger: Logger,
  snapshotPath: string | undefined,
  providerId: AnalysisProviderSelector | undefined,
  selection: FormatSelection = {},
) => {
  const profilePath = selection["raw-image-profile"];
  const profile =
    profilePath === undefined
      ? ok(undefined)
      : readRawImageProfile(profilePath);
  const formatHint = profile.ok
    ? resolveExecutableFormatHint(selection["target-format"], profile.value)
    : profile;
  return {
    logger,
    snapshotPath,
    ...(!formatHint.ok
      ? { formatHintError: formatHint.error }
      : formatHint.value === undefined
        ? {}
        : { formatHint: formatHint.value }),
    ...(providerId === undefined ? {} : { providerId }),
    ...(selection["annotation-ledger"] === undefined
      ? {}
      : { annotationLedgerPath: resolve(selection["annotation-ledger"]) }),
  };
};
