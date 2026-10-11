import { describe, expect, it } from "vitest";
import { nativeFunctionSimilarityInputSchema } from "./nativeFunctionSimilarity.js";

const database = { path: "/tmp/libs.mv.db", sha256: "a".repeat(64) };

describe("BSim similarity input", () => {
  it("defaults the procedure and the query bounds", () => {
    expect(nativeFunctionSimilarityInputSchema.parse({ database })).toEqual({
      database,
      procedure: null,
      min_similarity: 0.7,
      min_significance: 0,
      max_matches: 10,
    });
  });

  it("rejects a relative path, an unpinned digest, out-of-range bounds and unknown fields", () => {
    for (const bad of [
      { database: { ...database, path: "libs.mv.db" } },
      { database: { ...database, sha256: "A".repeat(64) } },
      { database: { path: database.path } },
      { database, min_similarity: 1.5 },
      { database, min_similarity: -0.1 },
      { database, min_significance: -1 },
      { database, max_matches: 0 },
      { database, extra: true },
      {},
    ])
      expect(nativeFunctionSimilarityInputSchema.safeParse(bad).success).toBe(
        false,
      );
  });
});
