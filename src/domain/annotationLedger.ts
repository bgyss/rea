import { z } from "zod";
import { nativeVariableAnnotationSchema } from "./native/nativeFunctionAnnotations.js";

const ledgerIdentity = {
  schema_version: z.literal("rea.annotation-ledger.v1"),
  target_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  analysis_profile_digest: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable()
    .describe(
      "Profile that gave the recorded address its meaning; null when the provider commits none",
    ),
};

const ledgerProvenance = {
  evidence_id: z.string().regex(/^ev_[a-f0-9]{64}$/u),
  recorded_at: z.iso.datetime(),
};

/** JSON Lines record of one applied annotate_native_function edit. */
export const functionAnnotationLedgerEntrySchema = z.strictObject({
  ...ledgerIdentity,
  procedure: z.string().min(1).describe("Canonical function entry address"),
  name: z.string().exactOptional(),
  comment: z.string().exactOptional(),
  inline_comment: z.string().exactOptional(),
  signature: z.string().exactOptional(),
  calling_convention: z.string().exactOptional(),
  variables: z.array(nativeVariableAnnotationSchema).exactOptional(),
  ...ledgerProvenance,
});

/** One recorded annotate_native_function edit. */
export type FunctionAnnotationLedgerEntry = z.infer<
  typeof functionAnnotationLedgerEntrySchema
>;

/** JSON Lines record of one applied annotate_native_data edit. */
export const dataAnnotationLedgerEntrySchema = z.strictObject({
  ...ledgerIdentity,
  address: z.string().min(1).describe("Canonical annotated address"),
  label: z.string().exactOptional(),
  data_type: z.string().exactOptional(),
  comment: z.string().exactOptional(),
  inline_comment: z.string().exactOptional(),
  ...ledgerProvenance,
});

/** JSON Lines record of one applied define_native_types edit. */
export const typeDefinitionLedgerEntrySchema = z.strictObject({
  ...ledgerIdentity,
  declarations: z.string().min(1),
  types: z
    .array(z.string().min(1))
    .min(1)
    .describe("Ids of the types the declarations defined when recorded"),
  ...ledgerProvenance,
});

/** JSON Lines record of one applied annotation: a function, an address, or type definitions. */
export const annotationLedgerEntrySchema = z.union([
  functionAnnotationLedgerEntrySchema,
  dataAnnotationLedgerEntrySchema,
  typeDefinitionLedgerEntrySchema,
]);
export type AnnotationLedgerEntry = z.infer<typeof annotationLedgerEntrySchema>;

/** What replaying a ledger into a fresh session did. */
export const annotationLedgerReplaySchema = z.strictObject({
  path: z.string(),
  entries: z.number().int().nonnegative(),
  applied: z.number().int().nonnegative(),
  skipped_other_target: z.number().int().nonnegative(),
  skipped_other_profile: z.number().int().nonnegative(),
  failed: z.array(
    z.union([
      z.strictObject({
        line: z.number().int().positive(),
        procedure: z.string(),
        reason: z.string(),
      }),
      z.strictObject({
        line: z.number().int().positive(),
        address: z.string(),
        reason: z.string(),
      }),
      z.strictObject({
        line: z.number().int().positive(),
        types: z.array(z.string()),
        reason: z.string(),
      }),
    ]),
  ),
});
export type AnnotationLedgerReplay = z.infer<
  typeof annotationLedgerReplaySchema
>;
