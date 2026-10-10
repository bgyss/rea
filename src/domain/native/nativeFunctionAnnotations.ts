import { z } from "zod";
import { functionDossierSchema } from "../hopperValues.js";

/** Where an annotation edit landed; source bytes are never modified. */
export const nativeAnnotationEffectsSchema = z.union([
  z.strictObject({
    scope: z.literal("session-analysis-database"),
    source_bytes_modified: z.literal(false),
    persists_after_close: z.literal(false),
  }),
  z.strictObject({
    scope: z.literal("persistent-analysis-database"),
    source_bytes_modified: z.literal(false),
    persists_after_close: z.literal(true),
  }),
]);

/** One decompiler variable (local or parameter) to rename and/or retype. */
export const nativeVariableAnnotationSchema = z
  .strictObject({
    name: z
      .string()
      .min(1)
      .describe("Current variable name as the decompiled pseudocode shows it"),
    new_name: z.string().min(1).optional(),
    data_type: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Fixed-length C type in the analysis database, e.g. uint8_t or struct sprite *; its size must match the variable's storage",
      ),
  })
  .refine(
    (value) => value.new_name !== undefined || value.data_type !== undefined,
    "Supply new_name or data_type",
  );

/** One explicit function's analyst-authored metadata changes. */
export const nativeFunctionAnnotationsInputSchema = z
  .strictObject({
    procedure: z.string().min(1),
    name: z.string().min(1).optional(),
    comment: z
      .string()
      .optional()
      .describe("Regular entry comment; empty text clears it"),
    inline_comment: z
      .string()
      .optional()
      .describe("Inline entry comment; empty text clears it"),
    signature: z
      .string()
      .min(1)
      .optional()
      .describe(
        "C prototype, e.g. int draw_sprite(struct sprite *s, uint8_t x); its function name must match the (requested) name, and a calling-convention keyword in it is applied",
      ),
    calling_convention: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Calling convention defined by the program's compiler spec, e.g. __stdcall, or unknown or default to reset it; other names are rejected with the defined list",
      ),
    variables: z
      .array(nativeVariableAnnotationSchema)
      .min(1)
      .optional()
      .describe(
        "Decompiler local and parameter edits, applied in order after any signature change",
      ),
  })
  .refine(
    (value) =>
      value.name !== undefined ||
      value.comment !== undefined ||
      value.inline_comment !== undefined ||
      value.signature !== undefined ||
      value.calling_convention !== undefined ||
      value.variables !== undefined,
    "Supply at least one annotation change",
  )
  .refine(
    (value) =>
      new Set(value.variables?.map((variable) => variable.name)).size ===
      (value.variables?.length ?? 0),
    { message: "Edit each variable at most once", path: ["variables"] },
  );

/** Readback and refreshed analysis after one atomic metadata edit. */
export const nativeFunctionAnnotationsSchema = z
  .strictObject({
    annotations: z.strictObject({
      address: z.string().min(1),
      name: z.string().min(1),
      comment: z.string().nullable(),
      inline_comment: z.string().nullable(),
      signature: z
        .string()
        .min(1)
        .describe("Function prototype after the edit"),
      calling_convention: z.string().min(1),
      variables: z
        .array(
          z.strictObject({
            variable: z.string().min(1).describe("Requested variable name"),
            name: z.string().min(1),
            data_type: z.string().min(1),
            parameter: z.boolean(),
            storage: z.string(),
          }),
        )
        .exactOptional()
        .describe(
          "Decompiler readback of each edited variable, in request order",
        ),
    }),
    dossier: functionDossierSchema,
    effects: nativeAnnotationEffectsSchema,
  })
  .superRefine((value, context) => {
    if (
      value.annotations.address !== value.dossier.procedure.address ||
      value.annotations.name !== value.dossier.procedure.name
    )
      context.addIssue({
        code: "custom",
        message:
          "Annotation readback disagrees with refreshed function identity",
      });
  });
