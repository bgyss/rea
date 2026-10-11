import { describe, expect, it } from "vitest";
import { nativeEncodedTextSearchInputSchema } from "./nativeEncodedText.js";
import { nativePointerTableScanInputSchema } from "./nativePointerTables.js";

describe("encoded text search input", () => {
  it("defaults the optional window, table and limit", () => {
    expect(
      nativeEncodedTextSearchInputSchema.parse({
        pattern: "ゲーム",
        encoding: "shift_jis",
      }),
    ).toEqual({
      pattern: "ゲーム",
      encoding: "shift_jis",
      table: null,
      start: null,
      end: null,
      limit: 1000,
    });
  });

  it("rejects an empty pattern, unknown encoding, relative table and bad digest", () => {
    const valid = { pattern: "x", encoding: "table" };
    const table = { path: "/tmp/a.tbl", sha256: "a".repeat(64) };
    expect(
      nativeEncodedTextSearchInputSchema.safeParse({ ...valid, table }).success,
    ).toBe(true);
    for (const bad of [
      { ...valid, pattern: "", table },
      { ...valid, encoding: "ascii", table },
      { ...valid, table: { ...table, path: "a.tbl" } },
      { ...valid, table: { ...table, sha256: "A".repeat(64) } },
      { ...valid, table, extra: 1 },
    ])
      expect(nativeEncodedTextSearchInputSchema.safeParse(bad).success).toBe(
        false,
      );
  });
});

describe("pointer table scan input", () => {
  it("defaults to eight ascending entries", () => {
    expect(
      nativePointerTableScanInputSchema.parse({
        entry_size: 2,
        endianness: "little",
      }),
    ).toMatchObject({ min_entries: 8, require_ascending: true, limit: 1000 });
  });

  it("rejects unsupported widths and short runs", () => {
    for (const bad of [
      { entry_size: 3, endianness: "little" },
      { entry_size: 2, endianness: "middle" },
      { entry_size: 2, endianness: "little", min_entries: 1 },
    ])
      expect(nativePointerTableScanInputSchema.safeParse(bad).success).toBe(
        false,
      );
  });
});
