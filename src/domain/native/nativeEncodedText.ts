import { z } from "zod";
import { isAbsolute } from "node:path";
import { localPathStringSchema } from "../localPath.js";

const sha256 = z.string().regex(/^[a-f0-9]{64}$/u);

/** Character encodings the bridge can turn a search string into bytes with. */
export const NATIVE_TEXT_ENCODINGS = [
  "shift_jis",
  "cp932",
  "euc_jp",
  "utf16le",
  "utf16be",
  "table",
] as const;

/** One operator-supplied Thingy-format `.tbl` character table, pinned by digest. */
export const nativeTextTableInputSchema = z.strictObject({
  path: localPathStringSchema.refine(
    isAbsolute,
    "Character table path must be absolute",
  ),
  sha256,
});

/** A text pattern, the encoding that turns it into bytes, and an optional address window. */
export const nativeEncodedTextSearchInputSchema = z.strictObject({
  pattern: z.string().min(1),
  encoding: z.enum(NATIVE_TEXT_ENCODINGS),
  table: nativeTextTableInputSchema.nullable().default(null),
  start: z.string().min(1).nullable().default(null),
  end: z.string().min(1).nullable().default(null),
  limit: z.number().int().min(1).max(100_000).default(1000),
});

const tableIdentity = z.strictObject({ path: z.string(), sha256 });

const regionSchema = z.strictObject({
  block: z.string(),
  start: z.string(),
  end: z.string(),
  bytes_scanned: z.number().int().nonnegative(),
});

const matchSchema = z.strictObject({
  address: z.string(),
  block: z.string(),
  file_offset: z.number().int().nonnegative().nullable(),
  bytes_hex: z.string(),
  bytes_before_hex: z.string(),
  bytes_after_hex: z.string(),
  text_from_match: z.string(),
});

/** Exact byte matches of one encoded text pattern, with the bytes that were searched for. */
export const nativeEncodedTextSearchSchema = z.strictObject({
  pattern: z.string(),
  encoding: z.enum(NATIVE_TEXT_ENCODINGS),
  table: tableIdentity.nullable(),
  needle_hex: z.string(),
  regions: z.array(regionSchema),
  total_matches: z.number().int().nonnegative(),
  truncated: z.boolean(),
  matches: z.array(matchSchema),
  limitations: z.array(z.string()),
});
