import { isAbsolute } from "node:path";
import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";

const sha256 = z.string().regex(/^[a-f0-9]{64}$/u);

/** One operator-supplied file-backed BSim database, pinned by content digest. */
export const nativeSimilarityDatabaseInputSchema = z.strictObject({
  path: localPathStringSchema.refine(
    isAbsolute,
    "BSim database path must be absolute",
  ),
  sha256,
});

/** A pinned BSim database, the similarity bounds, and an optional single procedure. */
export const nativeFunctionSimilarityInputSchema = z.strictObject({
  database: nativeSimilarityDatabaseInputSchema,
  procedure: z.string().min(1).nullable().default(null),
  min_similarity: z.number().min(0).max(1).default(0.7),
  min_significance: z.number().min(0).default(0),
  max_matches: z.number().int().min(1).max(1000).default(10),
});

const executableSchema = z.strictObject({
  name: z.string(),
  md5: z.string(),
  architecture: z.string(),
  compiler: z.string(),
  path: z.string().nullable(),
  repository: z.string().nullable(),
  is_library: z.boolean(),
});

const candidateSchema = z.strictObject({
  evidence_kind: z.literal("inferred"),
  name: z.string(),
  address: z.string(),
  similarity: z.number(),
  significance: z.number(),
  executable: executableSchema,
});

const functionMatchSchema = z.strictObject({
  function: z.strictObject({ address: z.string(), name: z.string() }),
  candidates: z.array(candidateSchema),
});

const databaseSchema = z.strictObject({
  path: z.string(),
  sha256,
  name: z.string(),
  owner: z.string(),
  description: z.string(),
  signature_version: z.string(),
  layout_version: z.number().int(),
  tracks_callgraph: z.boolean(),
  executable_count: z.number().int().nonnegative().nullable(),
});

/** BSim candidates for the examined functions, with the database that produced them. */
export const nativeFunctionSimilaritySchema = z.strictObject({
  database: databaseSchema,
  functions_examined: z.number().int().nonnegative(),
  functions_without_signature: z.number().int().nonnegative(),
  min_similarity: z.number(),
  min_significance: z.number(),
  max_matches: z.number().int().positive(),
  matches: z.array(functionMatchSchema),
  limitations: z.array(z.string()),
});
