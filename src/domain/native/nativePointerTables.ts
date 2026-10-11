import { z } from "zod";

/** Constraints for a scan for runs of consecutive pointers into mapped memory. */
export const nativePointerTableScanInputSchema = z.strictObject({
  entry_size: z.union([z.literal(2), z.literal(4), z.literal(8)]),
  endianness: z.enum(["little", "big"]),
  min_entries: z.number().int().min(2).default(8),
  target_base: z.string().min(1).nullable().default(null),
  target_start: z.string().min(1).nullable().default(null),
  target_end: z.string().min(1).nullable().default(null),
  require_ascending: z.boolean().default(true),
  start: z.string().min(1).nullable().default(null),
  end: z.string().min(1).nullable().default(null),
  limit: z.number().int().min(1).max(100_000).default(1000),
});

const candidateSchema = z.strictObject({
  address: z.string(),
  block: z.string(),
  file_offset: z.number().int().nonnegative().nullable(),
  entry_count: z.number().int().positive(),
  byte_length: z.number().int().positive(),
  strictly_ascending: z.boolean(),
  distinct_targets: z.number().int().positive(),
  targets: z.array(z.string()),
});

/** Candidate pointer tables: runs of values that each resolve to mapped memory. */
export const nativePointerTableScanSchema = z.strictObject({
  entry_size: z.number().int().positive(),
  endianness: z.enum(["little", "big"]),
  target_base: z.string(),
  total_candidates: z.number().int().nonnegative(),
  truncated: z.boolean(),
  candidates: z.array(candidateSchema),
  limitations: z.array(z.string()),
});
