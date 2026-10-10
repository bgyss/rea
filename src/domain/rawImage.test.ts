import { describe, expect, it } from "vitest";

import { resolveExecutableFormatHint } from "./dosCom.js";
import {
  rawImageProfileSchema,
  validateRawImageLayout,
  type RawImageProfile,
} from "./rawImage.js";

/** The shape dcomp writes for its authored NES fixture profile. */
const nesProfile: RawImageProfile = {
  schema_version: "dcomp.ghidra-profile.v1",
  profile_id: "nes-ricoh-2a03-mini-v1",
  platform: "nes",
  processor_language_id: "6502:LE:16:default",
  compiler_spec_id: "default",
  loader: "BinaryLoader",
  load_address: 0x8000,
  entry_address: 0x8000,
  analysis_timeout_seconds: 120,
  max_instruction_facts: 256,
};

describe("raw image profiles", () => {
  it("accepts dcomp's ghidra-profile-v1 shape verbatim and rejects extra fields", () => {
    expect(rawImageProfileSchema.parse(nesProfile)).toEqual(nesProfile);
    expect(
      rawImageProfileSchema.safeParse({ ...nesProfile, memory_map: [] })
        .success,
    ).toBe(false);
  });

  it.each([
    ["a language without endianness", "6502:16:default"],
    ["an unknown address width", "6502:LE:12:default"],
    ["a non-BinaryLoader loader", undefined],
  ])("rejects %s", (_name, language) => {
    const candidate =
      language === undefined
        ? { ...nesProfile, loader: "AutoImporter" }
        : { ...nesProfile, processor_language_id: language };
    expect(rawImageProfileSchema.safeParse(candidate).success).toBe(false);
  });

  it("admits an image ending exactly at the top of a 16-bit space", () => {
    expect(validateRawImageLayout(nesProfile, 0x8000)).toEqual({
      ok: true,
      value: null,
    });
  });

  it.each([
    [
      "overflowing the address space",
      nesProfile,
      0x8001,
      "exceeds the 16-bit address space",
    ],
    [
      "an entry outside the loaded bytes",
      { ...nesProfile, entry_address: 0x8010 },
      16,
      "lies outside the loaded bytes 0x8000..0x800f",
    ],
    [
      "an entry below the load address",
      { ...nesProfile, entry_address: 0x7fff },
      16,
      "lies outside the loaded bytes",
    ],
    ["an empty image", nesProfile, 0, "at least one byte"],
    [
      "segmented real-mode x86",
      { ...nesProfile, processor_language_id: "x86:LE:16:Real Mode" },
      16,
      "use the dos-com or dos-mz interpretation",
    ],
  ])("rejects %s", (_name, profile, size, message) => {
    const result = validateRawImageLayout(profile, size);
    if (result.ok) throw new Error("Expected a layout rejection");
    expect(result.error).toContain(message);
  });

  it("admits a 32-bit MIPS image in KSEG0", () => {
    const mips = {
      ...nesProfile,
      platform: "ps1",
      processor_language_id: "MIPS:LE:32:default",
      load_address: 0x80010000,
      entry_address: 0x80010000,
    };
    expect(validateRawImageLayout(mips, 12)).toEqual({
      ok: true,
      value: null,
    });
  });
});

describe("explicit format selection", () => {
  it("pairs raw-image with its profile and nothing else", () => {
    expect(resolveExecutableFormatHint("raw-image", nesProfile)).toEqual({
      ok: true,
      value: { format: "raw-image", profile: nesProfile },
    });
    expect(resolveExecutableFormatHint("dos-com", undefined)).toEqual({
      ok: true,
      value: "dos-com",
    });
    expect(resolveExecutableFormatHint(undefined, undefined)).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it.each([
    ["raw-image", undefined, "requires a raw image profile"],
    ["dos-com", nesProfile, "accepted only with format raw-image"],
    [undefined, nesProfile, "accepted only with format raw-image"],
  ] as const)(
    "rejects selector %s with an inconsistent profile",
    (selector, profile, message) => {
      const result = resolveExecutableFormatHint(selector, profile);
      if (result.ok) throw new Error("Expected a coupling rejection");
      expect(result.error).toContain(message);
    },
  );
});

describe("mapped raw image profiles (v2)", () => {
  const bank = 0x4000;
  const mapped = {
    schema_version: "dcomp.ghidra-profile.v2",
    profile_id: "mmc1-v2",
    platform: "nes",
    processor_language_id: "6502:LE:16:default",
    compiler_spec_id: "default",
    blocks: [
      {
        name: "bank0",
        file_offset: 0,
        length: bank,
        load_address: 0x8000,
        overlay: true,
        permissions: "rx",
        entry_addresses: [0x8000],
      },
      {
        name: "bank1",
        file_offset: bank,
        length: bank,
        load_address: 0x8000,
        overlay: true,
        permissions: "rx",
        entry_addresses: [],
      },
      {
        name: "fixed",
        file_offset: 2 * bank,
        length: bank,
        load_address: 0xc000,
        overlay: false,
        permissions: "rx",
        entry_addresses: [0xfffc],
      },
    ],
    analysis_timeout_seconds: 120,
    max_instruction_facts: 256,
  } as const;
  type Block = (typeof mapped.blocks)[number];
  const withBlock = (
    index: number,
    change: Partial<Record<keyof Block, unknown>>,
  ) =>
    rawImageProfileSchema.parse({
      ...mapped,
      blocks: mapped.blocks.map((block, at) =>
        at === index ? { ...block, ...change } : block,
      ),
    });

  it("accepts overlay banks that share CPU addresses with a fixed bank", () => {
    const profile = rawImageProfileSchema.parse(mapped);
    expect(validateRawImageLayout(profile, 3 * bank)).toEqual({
      ok: true,
      value: null,
    });
  });

  it.each([
    ["a block past the end of the file", 3 * bank - 1, {}, 0, "beyond the"],
    [
      "overlapping non-overlay blocks",
      3 * bank,
      { overlay: false, load_address: 0xc000 },
      1,
      "non-overlay blocks",
    ],
    [
      "a duplicate block name",
      3 * bank,
      { name: "BANK0" },
      1,
      "used more than once",
    ],
    [
      "an entry outside its block",
      3 * bank,
      { entry_addresses: [0xc000] },
      0,
      "lies outside 0x8000..0xbfff",
    ],
    [
      "a block beyond the address space",
      3 * bank,
      { load_address: 0xe000 },
      2,
      "exceeds the 16-bit address space",
    ],
  ])("rejects %s", (_name, size, change, index, message) => {
    const layout = validateRawImageLayout(withBlock(index, change), size);
    if (layout.ok) throw new Error("Expected a layout rejection");
    expect(layout.error).toContain(message);
  });

  it("requires at least one entry across all blocks", () => {
    const profile = rawImageProfileSchema.parse({
      ...mapped,
      blocks: mapped.blocks.map((block) => ({ ...block, entry_addresses: [] })),
    });
    const layout = validateRawImageLayout(profile, 3 * bank);
    if (layout.ok) throw new Error("Expected a missing-entry rejection");
    expect(layout.error).toContain("at least one entry");
  });

  it("rejects malformed block names and permissions by schema", () => {
    for (const change of [
      { name: "1bank" },
      { name: "bank-1" },
      { permissions: "x" },
    ])
      expect(
        rawImageProfileSchema.safeParse({
          ...mapped,
          blocks: [{ ...mapped.blocks[0], ...change }],
        }).success,
      ).toBe(false);
  });
});
