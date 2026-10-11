import { z } from "zod";
import { evidenceSchema } from "./evidence.js";
import { digestSchema } from "./digests.js";

/** How aligned instructions that differ only in constants are treated. */
export const compiledFunctionMaskingSchema = z.strictObject({
  immediates: z
    .enum(["exact", "mask"])
    .default("exact")
    .describe(
      "exact compares immediate values; mask ignores every immediate, for example while constants are still unknown",
    ),
});

/** Original-function listing and a candidate listing built from reconstructed source. */
export const compiledFunctionComparisonInputSchema = z.strictObject({
  left: evidenceSchema.describe(
    "inspect_native_function_instructions Evidence for the original target function",
  ),
  right: evidenceSchema.describe(
    "inspect_native_function_instructions Evidence for the caller-built candidate, typically an object file opened as its own session",
  ),
  masking: compiledFunctionMaskingSchema.default({ immediates: "exact" }),
});

const sideSchema = z.strictObject({
  index: z.number().int().min(0),
  address: z.string(),
  offset: z.number().int(),
  text: z.string(),
  bytes: z.string(),
});

const maskedSchema = z.strictObject({
  operand_index: z.number().int().min(0),
  reason: z.enum([
    "relocation",
    "relocation_unattributed",
    "external_address",
    "immediate_policy",
  ]),
  left: z.string(),
  right: z.string(),
});

const differenceSchema = z.strictObject({
  kind: z.enum(["mnemonic", "operand_count", "operand", "encoding"]),
  operand_index: z.number().int().min(0).nullable(),
  left: z.string(),
  right: z.string(),
});

const rowSchema = z.union([
  z.strictObject({
    kind: z.literal("match"),
    left: sideSchema,
    right: sideSchema,
  }),
  z.strictObject({
    kind: z.literal("masked"),
    left: sideSchema,
    right: sideSchema,
    masked: z.array(maskedSchema).min(1),
  }),
  z.strictObject({
    kind: z.literal("replace"),
    left: sideSchema,
    right: sideSchema,
    differences: z.array(differenceSchema).min(1),
  }),
  z.strictObject({ kind: z.literal("left_only"), left: sideSchema }),
  z.strictObject({ kind: z.literal("right_only"), right: sideSchema }),
]);

const functionSchema = z.strictObject({
  name: z.string(),
  address: z.string(),
  instruction_count: z.number().int().min(0),
  evidence_id: z.string(),
  subject_sha256: digestSchema,
});

/** Instruction-aligned compare of an original and a rebuilt function. */
export const compiledFunctionComparisonResultSchema = z.strictObject({
  verdict: z.enum(["identical", "equivalent_masked", "different"]),
  score: z.number().min(0).max(1),
  architecture: z.string(),
  mode: z.string(),
  left: functionSchema,
  right: functionSchema,
  masking: compiledFunctionMaskingSchema,
  counts: z.strictObject({
    matched: z.number().int().min(0),
    masked: z.number().int().min(0),
    replaced: z.number().int().min(0),
    left_only: z.number().int().min(0),
    right_only: z.number().int().min(0),
  }),
  first_divergence: rowSchema.nullable(),
  rows: z.array(rowSchema),
  right_relocations: z.array(
    z.strictObject({
      right_index: z.number().int().min(0),
      byte_offset: z.number().int().min(0),
      symbol: z.string().nullable(),
      type: z.number().int(),
      status: z.string(),
    }),
  ),
  limitations: z.array(z.string()),
});

export type CompiledFunctionComparisonResult = z.infer<
  typeof compiledFunctionComparisonResultSchema
>;
export type CompiledFunctionRow = z.infer<typeof rowSchema>;
