import { z } from "zod";
import type { RawImageProfile } from "./rawImage.js";
import { err, ok, type Result } from "./result.js";

/** Caller-selected interpretation for executable bytes with no identifying header. */
export const executableFormatHintSchema = z.enum(["dos-com", "raw-image"]);
/** Explicit interpretation selector accepted at the CLI and MCP boundaries. */
export type ExecutableFormatSelector = z.infer<
  typeof executableFormatHintSchema
>;

/**
 * Resolved explicit interpretation: headerless DOS COM, or a raw memory image
 * together with its caller-declared processor, base and entry profile.
 */
export type ExecutableFormatHint =
  | "dos-com"
  | { readonly format: "raw-image"; readonly profile: RawImageProfile };

/**
 * Combine an interpretation selector with its profile. A raw image needs the
 * profile that declares its processor, base and entry; other selections must
 * not carry one, so an unused profile is never silently ignored.
 */
export const resolveExecutableFormatHint = (
  selector: ExecutableFormatSelector | undefined,
  rawImageProfile: RawImageProfile | undefined,
): Result<ExecutableFormatHint | undefined, string> => {
  if (selector === "raw-image")
    return rawImageProfile === undefined
      ? err("format raw-image requires a raw image profile")
      : ok({ format: "raw-image", profile: rawImageProfile });
  if (rawImageProfile !== undefined)
    return err("a raw image profile is accepted only with format raw-image");
  return ok(selector);
};

/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length: number): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err(
        "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)",
      );
