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
      value: { endAddress: 0xffff },
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
      value: { endAddress: 0x8001000b },
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
