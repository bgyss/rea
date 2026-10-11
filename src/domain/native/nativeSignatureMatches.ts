import { z } from "zod";
import { isAbsoluteLocalPath } from "../localPath.js";

const sha256 = z.string().regex(/^[a-f0-9]{64}$/u);

/** One operator-supplied Function ID database, pinned by content digest. */
export const nativeSignatureDatabaseInputSchema = z.strictObject({
  path: z
    .string()
    .refine(isAbsoluteLocalPath, "Function ID database path must be absolute"),
  sha256,
});

/** Operator-pinned Function ID databases, optionally narrowed to one procedure. */
export const nativeSignatureMatchesInputSchema = z.strictObject({
  databases: z.array(nativeSignatureDatabaseInputSchema).min(1),
  procedure: z.string().min(1).nullable().default(null),
});

const librarySchema = z.strictObject({
  family: z.string(),
  version: z.string(),
  variant: z.string(),
  language_id: z.string(),
  compiler_spec_id: z.string(),
  ghidra_version: z.string(),
});

const databaseSchema = z.strictObject({
  path: z.string(),
  sha256,
  libraries: z.array(librarySchema),
  applies_to_target: z.boolean(),
});

const candidateSchema = z.strictObject({
  evidence_kind: z.literal("inferred"),
  name: z.string(),
  database_index: z.number().int().nonnegative(),
  library: librarySchema,
  entry_point: z.string(),
  code_unit_size: z.number().int().nonnegative(),
  full_hash: z.string(),
  specific_hash: z.string(),
  match_mode: z.string(),
  scores: z.strictObject({
    overall: z.number(),
    function: z.number(),
    children: z.number(),
    parents: z.number(),
  }),
  flags: z.strictObject({
    auto_pass: z.boolean(),
    force_specific: z.boolean(),
    force_relation: z.boolean(),
  }),
});

const functionMatchSchema = z.strictObject({
  function: z.strictObject({ address: z.string(), name: z.string() }),
  code_unit_count: z.number().int().nonnegative(),
  full_hash: z.string(),
  specific_hash: z.string(),
  candidates: z.array(candidateSchema),
});

/** Function ID candidates for the examined functions, with the databases that produced them. */
export const nativeSignatureMatchesSchema = z.strictObject({
  databases: z.array(databaseSchema),
  functions_examined: z.number().int().nonnegative(),
  functions_too_short: z.number().int().nonnegative(),
  matches: z.array(functionMatchSchema),
  limitations: z.array(z.string()),
});
