import { isAbsolute } from "node:path";
import { executableFormatHintSchema } from "../domain/dosCom.js";
import { rawImageProfileSchema } from "../domain/rawImage.js";
import { localPathStringSchema } from "../domain/localPath.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
  rawBinarySelectionError,
} from "../domain/rawBinary.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "./providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "snapshot_path must be an absolute local filesystem path (for example /tmp/rea/analysis.json or C:\\rea\\analysis.json)",
  })
  .describe(
    "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
  );

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
  })
  .describe(
    "Absolute local filesystem path for the analysis target; relative paths are rejected.",
  );

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z
  .strictObject({
    path: binaryTargetPathSchema,
    format: executableFormatHintSchema
      .optional()
      .describe(
        "Explicit headerless interpretation: dos-com; raw-binary with architecture and entry_point; or raw-image with raw_image_profile. Omission preserves header-based detection.",
      ),
    architecture: binaryArchitectureSchema
      .optional()
      .describe(
        "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise.",
      ),
    entry_point: rawBinaryEntryPointSchema
      .optional()
      .describe(
        "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise.",
      ),
    raw_image_profile: rawImageProfileSchema
      .optional()
      .describe(
        "Required with format=raw-image: dcomp.ghidra-profile.v1 (one flat block: load_address, entry_address) or dcomp.ghidra-profile.v2 (blocks of file slices mapped to CPU addresses, with overlay banks as separate address spaces and per-block entries), declaring the Ghidra processor_language_id and compiler_spec_id",
      ),
    provider_id: analysisProviderSelectorSchema.optional(),
    snapshot_path: snapshotPathSchema.optional(),
    annotation_ledger_path: localPathStringSchema
      .refine(isAbsolute, {
        message:
          "annotation_ledger_path must be an absolute local filesystem path (for example /tmp/rea/annotations.jsonl)",
      })
      .optional()
      .describe(
        "JSON Lines annotation ledger: entries recorded for this exact target and analysis profile are replayed after opening, and later annotate_native_function, annotate_native_data, define_native_types and apply_native_annotations edits are appended. A missing file starts an empty ledger.",
      ),
  })
  .superRefine((value, context) => {
    const pairing = rawBinarySelectionError({
      ...(value.format === undefined ? {} : { format: value.format }),
      ...(value.architecture === undefined
        ? {}
        : { architecture: value.architecture }),
      ...(value.entry_point === undefined
        ? {}
        : { entryPoint: value.entry_point }),
    });
    if (pairing === undefined) return;
    context.addIssue({
      code: "custom",
      path:
        value.format === "raw-binary"
          ? value.architecture === undefined
            ? ["architecture"]
            : ["entry_point"]
          : value.architecture === undefined
            ? ["entry_point"]
            : ["architecture"],
      message: pairing,
    });
  });

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
});
