import { describe, expect, it } from "vitest";

import { nativeSignatureMatchesInputSchema } from "./nativeSignatureMatches.js";

const database = { path: "/opt/fid/libc.fidbf", sha256: "a".repeat(64) };

describe("nativeSignatureMatchesInputSchema", () => {
  it("accepts pinned absolute databases and defaults the procedure", () => {
    expect(
      nativeSignatureMatchesInputSchema.parse({ databases: [database] }),
    ).toEqual({ databases: [database], procedure: null });
  });

  it.each([
    ["no database", { databases: [] }],
    ["a relative path", { databases: [{ ...database, path: "libc.fidbf" }] }],
    [
      "an unpinned digest",
      { databases: [{ ...database, sha256: "A".repeat(64) }] },
    ],
    ["an unknown field", { databases: [database], score: 1 }],
  ])("rejects %s", (_name, input) => {
    expect(nativeSignatureMatchesInputSchema.safeParse(input).success).toBe(
      false,
    );
  });
});
