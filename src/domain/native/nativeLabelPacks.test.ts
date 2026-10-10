import { describe, expect, it } from "vitest";

import { labelPackSchema } from "./nativeAnnotationSets.js";
import {
  LABEL_PACKS,
  nativeAnnotationSetInputSchema,
  resolveAnnotationSet,
} from "./nativeLabelPacks.js";

const WIDTHS: Readonly<Record<string, number>> = { byte: 1, word: 2, dword: 4 };

describe("built-in label packs", () => {
  it.each(Object.values(LABEL_PACKS))(
    "$id is a valid rea.label-pack.v1 with unique, non-overlapping registers inside its blocks",
    (pack) => {
      expect(labelPackSchema.parse(pack)).toEqual(pack);
      const blocks = (pack.annotations.memory_blocks ?? []).map((block) => ({
        start: Number(block.address),
        end: Number(block.address) + block.size_bytes,
      }));
      const data = pack.annotations.data ?? [];
      const labels = data.map((item) => item.label);
      expect(new Set(labels).size).toBe(labels.length);
      const ranges = data
        .map((item) => ({
          label: item.label,
          start: Number(item.address),
          end:
            Number(item.address) +
            (item.data_type === undefined ? 1 : (WIDTHS[item.data_type] ?? 0)),
        }))
        .sort((left, right) => left.start - right.start);
      for (const range of ranges) {
        expect(range.end, `${range.label} type`).toBeGreaterThan(range.start);
        expect(
          blocks.some(
            (block) => block.start <= range.start && range.end <= block.end,
          ),
          `${range.label} lies outside the pack's blocks`,
        ).toBe(true);
      }
      for (const [index, range] of ranges.slice(1).entries())
        expect(
          range.start,
          `${range.label} overlaps ${ranges[index]?.label}`,
        ).toBeGreaterThanOrEqual(ranges[index]?.end ?? 0);
    },
  );

  it("resolves a pack id to its contents and an inline set to itself", () => {
    const pack = LABEL_PACKS["nes-registers"];
    expect(
      resolveAnnotationSet(
        nativeAnnotationSetInputSchema.parse({ pack: "nes-registers" }),
      ),
    ).toEqual({
      annotations: pack?.annotations,
      pack: { id: "nes-registers", version: 1 },
    });
    const annotations = { data: [{ address: "0x10", label: "counter" }] };
    expect(
      resolveAnnotationSet(
        nativeAnnotationSetInputSchema.parse({ annotations }),
      ),
    ).toEqual({ annotations, pack: null });
  });

  it("requires exactly one of pack or annotations, and a non-empty set", () => {
    for (const input of [
      {},
      { pack: "nes-registers", annotations: { declarations: "struct a;" } },
      { pack: "snes-registers" },
      { annotations: {} },
    ])
      expect(nativeAnnotationSetInputSchema.safeParse(input).success).toBe(
        false,
      );
  });
});
