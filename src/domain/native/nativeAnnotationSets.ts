import { z } from "zod";
import {
  nativeDataAnnotationsInputSchema,
  nativeDataAnnotationsSchema,
} from "./nativeDataAnnotations.js";
import {
  nativeAnnotationEffectsSchema,
  nativeFunctionAnnotationsInputSchema,
  nativeFunctionAnnotationsSchema,
} from "./nativeFunctionAnnotations.js";
import {
  nativeTypeDefinitionSchema,
  nativeTypeDefinitionsSchema,
} from "./nativeTypeDefinitions.js";

/** An address range the analysis database should map, such as an MMIO window. */
export const nativeMemoryBlockSchema = z.strictObject({
  name: z.string().min(1).describe("Memory block name, e.g. PPU_REGS"),
  address: z
    .string()
    .min(1)
    .describe("First address, as REA reports addresses"),
  size_bytes: z.number().int().positive(),
  volatile: z
    .boolean()
    .describe(
      "Hardware registers: true keeps the decompiler from merging or dropping their reads and writes",
    ),
});

/**
 * Edits applied together in one transaction: memory blocks, then C types,
 * then data edits, then function edits, each in order.
 */
export const nativeAnnotationSetSchema = z
  .strictObject({
    processors: z
      .array(z.string().min(1))
      .min(1)
      .optional()
      .describe(
        "Processors the set applies to, e.g. 6502 or MIPS; other targets reject the whole set",
      ),
    memory_blocks: z
      .array(nativeMemoryBlockSchema)
      .min(1)
      .optional()
      .describe(
        "Uninitialized blocks to add where nothing is mapped; a range already fully mapped is kept, and a partial overlap rejects the set",
      ),
    declarations: z
      .string()
      .min(1)
      .optional()
      .describe("Preprocessed C declarations, as define_native_types takes"),
    data: z
      .array(nativeDataAnnotationsInputSchema)
      .min(1)
      .optional()
      .describe("annotate_native_data edits"),
    functions: z
      .array(nativeFunctionAnnotationsInputSchema)
      .min(1)
      .optional()
      .describe("annotate_native_function edits"),
  })
  .refine(
    (value) =>
      value.memory_blocks !== undefined ||
      value.declarations !== undefined ||
      value.data !== undefined ||
      value.functions !== undefined,
    "Supply at least one memory block, declaration, data edit or function edit",
  );
export type NativeAnnotationSet = z.infer<typeof nativeAnnotationSetSchema>;

/** A versioned, attributed annotation set for one platform's hardware. */
export const labelPackSchema = z.strictObject({
  schema_version: z.literal("rea.label-pack.v1"),
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/u),
  version: z.number().int().positive(),
  title: z.string().min(1),
  platform: z.string().min(1),
  sources: z.array(z.string().min(1)).min(1),
  limitations: z.array(z.string().min(1)),
  annotations: nativeAnnotationSetSchema,
});
export type LabelPack = z.infer<typeof labelPackSchema>;

const packIdentitySchema = z.strictObject({
  id: z.string().min(1),
  version: z.number().int().positive(),
});

/** Readback after one atomic annotation set. */
export const nativeAnnotationSetResultSchema = z.strictObject({
  pack: packIdentitySchema
    .nullable()
    .describe("The built-in label pack applied; null for an inline set"),
  memory_blocks: z.array(
    z.strictObject({
      name: z.string().min(1),
      start: z.string().min(1),
      end: z.string().min(1),
      volatile: z.boolean(),
      initialized: z.boolean(),
      outcome: z
        .enum(["created", "existing"])
        .describe("existing: the range was already fully mapped, and is kept"),
    }),
  ),
  types: z.array(nativeTypeDefinitionSchema),
  skipped: nativeTypeDefinitionsSchema.shape.skipped,
  parser_messages: nativeTypeDefinitionsSchema.shape.parser_messages,
  data: z.array(nativeDataAnnotationsSchema.shape.annotations),
  functions: z.array(nativeFunctionAnnotationsSchema.shape.annotations),
  effects: nativeAnnotationEffectsSchema,
});
