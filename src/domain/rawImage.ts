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

const addressSchema = z.number().int().nonnegative().safe();

/** Identity and dcomp bounds shared by every profile version. */
const profileFields = {
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
};

/**
 * One flat image: the whole file at one load address with one entry. Accepted
 * verbatim in dcomp's `dcomp.ghidra-profile.v1` shape.
 */
export const rawImageProfileV1Schema = z.strictObject({
  schema_version: z.literal("dcomp.ghidra-profile.v1"),
  ...profileFields,
  loader: z.literal("BinaryLoader"),
  load_address: addressSchema,
  entry_address: addressSchema,
});

/**
 * One file slice mapped at a CPU address. Overlay blocks become separate
 * address spaces named after the block, so banks that share CPU addresses
 * keep distinct identities (`<name>:0x8000`).
 */
export const rawImageBlockSchema = z.strictObject({
  name: z
    .string()
    .regex(
      /^[A-Za-z_][A-Za-z0-9_]{0,31}$/u,
      "block name must be 1..32 letters, digits or underscores, not starting with a digit",
    ),
  file_offset: addressSchema,
  length: z.number().int().positive().safe(),
  load_address: addressSchema,
  overlay: z
    .boolean()
    .describe(
      "true for a switchable bank or overlay that may share CPU addresses with other overlay blocks",
    ),
  permissions: z.enum(["r", "rw", "rx", "rwx"]),
  entry_addresses: z.array(addressSchema).max(64),
});
export type RawImageBlock = z.infer<typeof rawImageBlockSchema>;

/** A memory map of file slices (banks, overlays, fixed regions) and their entries. */
export const rawImageProfileV2Schema = z.strictObject({
  schema_version: z.literal("dcomp.ghidra-profile.v2"),
  ...profileFields,
  blocks: z.array(rawImageBlockSchema).min(1).max(256),
});

/**
 * Explicit interpretation of a headerless memory image, accepted verbatim in
 * dcomp's `dcomp.ghidra-profile.v1` or `.v2` shape so one profile file and
 * digest serve both tools. Integer addresses are linear byte addresses in the
 * language's default address space.
 */
export const rawImageProfileSchema = z.discriminatedUnion("schema_version", [
  rawImageProfileV1Schema,
  rawImageProfileV2Schema,
]);
/** Caller-declared processor, compiler and memory layout for a raw image. */
export type RawImageProfile = z.infer<typeof rawImageProfileSchema>;

/** Address width, in bits, declared by a validated Ghidra language ID. */
export const rawImageAddressBits = (profile: RawImageProfile): number =>
  Number(profile.processor_language_id.split(":")[2]);

const hex = (value: number): string => `0x${value.toString(16)}`;

/**
 * Check a profile against an image of `imageBytes`: every block lies inside
 * the file and the language's address space, non-overlay blocks do not
 * overlap, block names are unique, and every entry lies inside its block.
 * Segmented x86 real/protected modes use the explicit DOS formats instead.
 */
export const validateRawImageLayout = (
  profile: RawImageProfile,
  imageBytes: number,
): Result<null, string> => {
  if (profile.processor_language_id.startsWith("x86:LE:16:"))
    return err(
      "segmented 16-bit x86 languages are not raw-image profiles; use the dos-com or dos-mz interpretation",
    );
  if (!Number.isSafeInteger(imageBytes) || imageBytes < 1)
    return err("raw image must contain at least one byte");
  const bits = rawImageAddressBits(profile);
  const maximum = bits >= 53 ? Number.MAX_SAFE_INTEGER : 2 ** bits - 1;
  return profile.schema_version === "dcomp.ghidra-profile.v1"
    ? validateFlatLayout(profile, imageBytes, bits, maximum)
    : validateMappedLayout(profile, imageBytes, bits, maximum);
};

const validateFlatLayout = (
  profile: z.infer<typeof rawImageProfileV1Schema>,
  imageBytes: number,
  bits: number,
  maximum: number,
): Result<null, string> => {
  const endAddress = profile.load_address + imageBytes - 1;
  if (!Number.isSafeInteger(endAddress) || endAddress > maximum)
    return err(
      `raw image of ${imageBytes} bytes at ${hex(profile.load_address)} exceeds the ${bits}-bit address space`,
    );
  if (
    profile.entry_address < profile.load_address ||
    profile.entry_address > endAddress
  )
    return err(
      `raw image entry ${hex(profile.entry_address)} lies outside the loaded bytes ` +
        `${hex(profile.load_address)}..${hex(endAddress)}`,
    );
  return ok(null);
};

const validateMappedLayout = (
  profile: z.infer<typeof rawImageProfileV2Schema>,
  imageBytes: number,
  bits: number,
  maximum: number,
): Result<null, string> => {
  const names = new Set<string>();
  const fixed: { name: string; start: number; end: number }[] = [];
  let entries = 0;
  for (const block of profile.blocks) {
    if (names.has(block.name.toLowerCase()))
      return err(`block name ${block.name} is used more than once`);
    names.add(block.name.toLowerCase());
    if (block.file_offset + block.length > imageBytes)
      return err(
        `block ${block.name} reads file bytes ${hex(block.file_offset)}..${hex(block.file_offset + block.length - 1)} beyond the ${imageBytes}-byte image`,
      );
    const end = block.load_address + block.length - 1;
    if (!Number.isSafeInteger(end) || end > maximum)
      return err(
        `block ${block.name} at ${hex(block.load_address)} exceeds the ${bits}-bit address space`,
      );
    const outside = block.entry_addresses.find(
      (entry) => entry < block.load_address || entry > end,
    );
    if (outside !== undefined)
      return err(
        `block ${block.name} entry ${hex(outside)} lies outside ${hex(block.load_address)}..${hex(end)}`,
      );
    entries += block.entry_addresses.length;
    if (block.overlay) continue;
    const clash = fixed.find(
      (other) => block.load_address <= other.end && other.start <= end,
    );
    if (clash !== undefined)
      return err(
        `non-overlay blocks ${clash.name} and ${block.name} overlap; mark switchable banks as overlay`,
      );
    fixed.push({ name: block.name, start: block.load_address, end });
  }
  if (entries === 0)
    return err("a mapped raw image needs at least one entry address");
  return ok(null);
};
