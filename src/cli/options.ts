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

export const providerSelectionOption = analysisProviderSelectorSchema
  .optional()
  .describe(
    "Bind deep analysis to a provider ID or use deterministic auto selection",
  );

/** Profile JSON is small; anything larger is not a profile. */
const MAX_RAW_IMAGE_PROFILE_BYTES = 64 * 1024;

/** Read and validate one raw-image profile file named on the command line. */
const rawImageProfileOption = z
  .string()
  .min(1)
  .transform((path, context): RawImageProfile => {
    let parsed: unknown;
    try {
      const text = readFileSync(path, "utf8");
      if (Buffer.byteLength(text) > MAX_RAW_IMAGE_PROFILE_BYTES)
        throw new Error(`profile exceeds ${MAX_RAW_IMAGE_PROFILE_BYTES} bytes`);
      parsed = JSON.parse(text);
    } catch (cause: unknown) {
      context.addIssue({
        code: "custom",
        message: `Cannot read raw image profile ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
      return z.NEVER;
    }
    const profile = rawImageProfileSchema.safeParse(parsed);
    if (profile.success) return profile.data;
    for (const issue of profile.error.issues)
      context.addIssue({
        code: "custom",
        message: `Invalid raw image profile ${path} at ${issue.path.join(".") || "(root)"}: ${issue.message}`,
      });
    return z.NEVER;
  })
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

/** Annotation ledger replayed after opening; annotate-native-function also appends. */
export const annotationLedgerOptions = {
  "annotation-ledger": z
    .string()
    .min(1)
    .optional()
    .describe(
      "JSON Lines annotation ledger: replay entries recorded for this exact target and profile after opening; annotate-native-function also appends its edit",
    ),
};

/** Parsed values of {@link formatSelectionOptions} and {@link annotationLedgerOptions}. */
export interface FormatSelection {
  readonly "target-format"?: ExecutableFormatSelector | undefined;
  readonly "raw-image-profile"?: RawImageProfile | undefined;
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
  const formatHint = resolveExecutableFormatHint(
    selection["target-format"],
    selection["raw-image-profile"],
  );
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
