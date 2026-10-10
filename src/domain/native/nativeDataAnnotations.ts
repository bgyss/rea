import { z } from "zod";
import { nativeAnnotationEffectsSchema } from "./nativeFunctionAnnotations.js";

/** Analysis-database edits that REA can record in an annotation ledger. */
export const ANNOTATION_OPERATIONS = [
  "annotate_native_function",
  "annotate_native_data",
  "define_native_types",
] as const;

/** One annotation operation. */
export type AnnotationOperation = (typeof ANNOTATION_OPERATIONS)[number];

const annotationOperationSet: ReadonlySet<string> = new Set(
  ANNOTATION_OPERATIONS,
);

/** Narrow a tool or operation name to an annotation edit. */
export const isAnnotationOperation = (
  name: string,
): name is AnnotationOperation => annotationOperationSet.has(name);

/** One explicit address's analyst-authored label, data type, and comments. */
export const nativeDataAnnotationsInputSchema = z
  .strictObject({
    address: z
      .string()
      .min(1)
      .describe("Exact address, as REA reports addresses"),
    label: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Primary label at the address; replaces an existing user label there",
      ),
    data_type: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Fixed-length C type to define at the address, e.g. uint16_t or struct oam_entry[64]; it may replace undefined bytes only, never instructions or other defined data",
      ),
    comment: z
      .string()
      .optional()
      .describe("Regular comment; empty text clears it"),
    inline_comment: z
      .string()
      .optional()
      .describe("Inline comment; empty text clears it"),
  })
  .refine(
    (value) =>
      value.label !== undefined ||
      value.data_type !== undefined ||
      value.comment !== undefined ||
      value.inline_comment !== undefined,
    "Supply at least one annotation change",
  );

/** Readback after one atomic address edit. */
export const nativeDataAnnotationsSchema = z.strictObject({
  annotations: z.strictObject({
    address: z.string().min(1),
    label: z.string().min(1).nullable(),
    data_type: z
      .string()
      .min(1)
      .nullable()
      .describe("Defined data type starting at the address; null when none"),
    size_bytes: z.number().int().positive().nullable(),
    comment: z.string().nullable(),
    inline_comment: z.string().nullable(),
  }),
  effects: nativeAnnotationEffectsSchema,
});
