import { z } from "zod";

/** JSON Lines record of one applied function annotation. */
export const annotationLedgerEntrySchema = z.strictObject({
  schema_version: z.literal("rea.annotation-ledger.v1"),
  target_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  analysis_profile_digest: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable()
    .describe(
      "Profile that gave the procedure address its meaning; null when the provider commits none",
    ),
  procedure: z.string().min(1).describe("Canonical function entry address"),
  name: z.string().exactOptional(),
  comment: z.string().exactOptional(),
  inline_comment: z.string().exactOptional(),
  evidence_id: z.string().regex(/^ev_[a-f0-9]{64}$/u),
  recorded_at: z.iso.datetime(),
});
export type AnnotationLedgerEntry = z.infer<typeof annotationLedgerEntrySchema>;

/** What replaying a ledger into a fresh session did. */
export const annotationLedgerReplaySchema = z.strictObject({
  path: z.string(),
  entries: z.number().int().nonnegative(),
  applied: z.number().int().nonnegative(),
  skipped_other_target: z.number().int().nonnegative(),
  skipped_other_profile: z.number().int().nonnegative(),
  failed: z.array(
    z.strictObject({
      line: z.number().int().positive(),
      procedure: z.string(),
      reason: z.string(),
    }),
  ),
});
export type AnnotationLedgerReplay = z.infer<
  typeof annotationLedgerReplaySchema
>;
