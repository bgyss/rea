import { executableFormatHintSchema } from "../domain/dosCom.js";
import { rawImageProfileSchema } from "../domain/rawImage.js";
import { isAbsoluteLocalPath } from "../domain/localPath.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "./providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = z
  .string()
  .min(1)
  .refine(isAbsoluteLocalPath, {
    message:
      "snapshot_path must be an absolute local filesystem path (for example /tmp/rea/analysis.json or C:\\rea\\analysis.json)",
  })
  .describe(
    "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
  );

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = z
  .string()
  .min(1)
  .refine(isAbsoluteLocalPath, {
    message:
      "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
  })
  .describe(
    "Absolute local filesystem path for the analysis target; relative paths are rejected.",
  );

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z.strictObject({
  path: binaryTargetPathSchema,
  format: executableFormatHintSchema
    .optional()
    .describe(
      "Explicit interpretation for headerless bytes: dos-com, or raw-image with raw_image_profile; omission preserves header-based detection",
    ),
  raw_image_profile: rawImageProfileSchema
    .optional()
    .describe(
      "Required with format=raw-image: dcomp.ghidra-profile.v1 (one flat block: load_address, entry_address) or dcomp.ghidra-profile.v2 (blocks of file slices mapped to CPU addresses, with overlay banks as separate address spaces and per-block entries), declaring the Ghidra processor_language_id and compiler_spec_id",
    ),
  provider_id: analysisProviderSelectorSchema.optional(),
  snapshot_path: snapshotPathSchema.optional(),
  annotation_ledger_path: z
    .string()
    .min(1)
    .refine(isAbsoluteLocalPath, {
      message:
        "annotation_ledger_path must be an absolute local filesystem path (for example /tmp/rea/annotations.jsonl)",
    })
    .optional()
    .describe(
      "JSON Lines annotation ledger: entries recorded for this exact target and analysis profile are replayed after opening, and later annotate_native_function and annotate_native_data edits are appended. A missing file starts an empty ledger.",
    ),
});

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
});
