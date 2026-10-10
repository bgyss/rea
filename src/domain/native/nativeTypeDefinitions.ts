import { z } from "zod";
import { nativeDataTypeSchema } from "./nativeDataType.js";
import { nativeAnnotationEffectsSchema } from "./nativeFunctionAnnotations.js";

/** C type declarations to define in the analysis database. */
export const nativeTypeDefinitionsInputSchema = z.strictObject({
  declarations: z
    .string()
    .min(1)
    .describe(
      "Preprocessed C declarations: struct, union, enum and typedef definitions, optionally with #pragma pack. Macros, #include and conditionals are not expanded; preprocess a header first (for example cc -E -P). Function prototypes are reported as skipped, and variable declarations are ignored.",
    ),
});

const { kind, fields, members } = nativeDataTypeSchema.shape;

/** One type the declarations defined, as the database holds it after the edit. */
export const nativeTypeDefinitionSchema = z.strictObject({
  id: z
    .string()
    .min(1)
    .describe(
      "Exact category path, e.g. /rea/ppu_regs; inspect_native_data_type accepts it as type",
    ),
  name: z.string().min(1),
  kind: kind.exclude(["unavailable"]),
  outcome: z
    .enum(["created", "replaced", "unchanged"])
    .describe(
      "replaced means an earlier definition at this path changed; every use of it now has the new layout",
    ),
  size_bytes: z.number().int().nonnegative().nullable(),
  alignment_bytes: z.number().int().positive().nullable(),
  referenced_type: z.string().nullable(),
  fields,
  members,
  other_ids: z
    .array(z.string().min(1))
    .describe(
      "Other database types with the same name. When they differ from this one, a bare-name data_type reference is ambiguous and is rejected",
    ),
});

/** Readback after one atomic type definition edit. */
export const nativeTypeDefinitionsSchema = z.strictObject({
  types: z.array(nativeTypeDefinitionSchema).min(1),
  skipped: z
    .array(
      z.strictObject({
        name: z.string().min(1),
        kind: z.literal("function"),
      }),
    )
    .describe("Function prototypes that were parsed but not defined as types"),
  parser_messages: z
    .array(z.string())
    .describe("Ghidra C parser warnings for declarations it accepted"),
  effects: nativeAnnotationEffectsSchema,
});
