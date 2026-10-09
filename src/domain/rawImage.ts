import { z } from "zod";
import { err, ok, type Result } from "./result.js";

/**
 * Ghidra language ID with processor, endianness, address size and variant,
 * for example `6502:LE:16:default` or `MIPS:LE:32:default`.
 */
const languageIdSchema = z
  .string()
  .regex(
    /^[^:\s][^:]*:(?:LE|BE):(?:8|16|24|32|64):[^:]+$/u,
    "processor_language_id must be PROCESSOR:LE|BE:BITS:VARIANT",
  );

/**
 * Explicit interpretation of a headerless memory image, accepted verbatim in
 * dcomp's `dcomp.ghidra-profile.v1` shape so one profile file and digest serve
 * both tools. Integer addresses are linear byte addresses in the language's
 * default address space.
 */
export const rawImageProfileSchema = z.strictObject({
  schema_version: z.literal("dcomp.ghidra-profile.v1"),
  profile_id: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_.-]+$/u)
    .describe("Caller-assigned profile identity, recorded in Evidence"),
  platform: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9_.-]*$/u)
    .describe("Caller-assigned platform label, for example nes or ps1"),
  processor_language_id: languageIdSchema,
  compiler_spec_id: z.string().min(1).max(64),
  loader: z.literal("BinaryLoader"),
  load_address: z.number().int().nonnegative().safe(),
  entry_address: z.number().int().nonnegative().safe(),
  analysis_timeout_seconds: z
    .number()
    .int()
    .min(1)
    .max(3600)
    .describe("dcomp fact-export bound; recorded for profile identity only"),
  max_instruction_facts: z
    .number()
    .int()
    .min(1)
    .max(1_000_000)
    .describe("dcomp fact-export bound; recorded for profile identity only"),
});
/** Caller-declared processor, compiler, base and entry for a raw image. */
export type RawImageProfile = z.infer<typeof rawImageProfileSchema>;

/** Address width, in bits, declared by a validated Ghidra language ID. */
export const rawImageAddressBits = (profile: RawImageProfile): number =>
  Number(profile.processor_language_id.split(":")[2]);

/**
 * Check that a raw image of `imageBytes` fits the language's address space at
 * its load address and that the entry point lies inside the loaded bytes.
 * Segmented x86 real/protected modes use the explicit DOS formats instead.
 */
export const validateRawImageLayout = (
  profile: RawImageProfile,
  imageBytes: number,
): Result<{ readonly endAddress: number }, string> => {
  if (profile.processor_language_id.startsWith("x86:LE:16:"))
    return err(
      "segmented 16-bit x86 languages are not raw-image profiles; use the dos-com or dos-mz interpretation",
    );
  if (!Number.isSafeInteger(imageBytes) || imageBytes < 1)
    return err("raw image must contain at least one byte");
  const endAddress = profile.load_address + imageBytes - 1;
  const bits = rawImageAddressBits(profile);
  const maximum = bits >= 53 ? Number.MAX_SAFE_INTEGER : 2 ** bits - 1;
  if (!Number.isSafeInteger(endAddress) || endAddress > maximum)
    return err(
      `raw image of ${imageBytes} bytes at 0x${profile.load_address.toString(16)} exceeds the ${bits}-bit address space`,
    );
  if (
    profile.entry_address < profile.load_address ||
    profile.entry_address > endAddress
  )
    return err(
      `raw image entry 0x${profile.entry_address.toString(16)} lies outside the loaded bytes ` +
        `0x${profile.load_address.toString(16)}..0x${endAddress.toString(16)}`,
    );
  return ok({ endAddress });
};
