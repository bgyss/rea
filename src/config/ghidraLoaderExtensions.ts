import { isAbsolute } from "node:path";
import { z } from "zod";

/** Ghidra loader class a pinned extension must provide for Switch NSO and NRO targets. */
export const GHIDRA_SWITCH_LOADER_NAME = "ReaSwitchLoader";
export const MAX_GHIDRA_LOADER_EXTENSIONS = 8;

/** One operator-pinned loader: where its jar is, the digest it must have, and the class it provides. */
export const ghidraLoaderExtensionConfigSchema = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9\x2D]*$/u),
  path: z.string().min(1).refine(isAbsolute, "path must be absolute"),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  loader_name: z.string().regex(/^[A-Z][A-Za-z0-9]*$/u),
});
export type GhidraLoaderExtensionConfig = z.infer<
  typeof ghidraLoaderExtensionConfigSchema
>;

const ghidraLoaderExtensionsSchema = z
  .array(ghidraLoaderExtensionConfigSchema)
  .max(MAX_GHIDRA_LOADER_EXTENSIONS)
  .refine(
    (items) => new Set(items.map(({ id }) => id)).size === items.length,
    "ids must be unique",
  )
  .refine(
    (items) =>
      new Set(items.map(({ loader_name }) => loader_name)).size ===
      items.length,
    "loader names must be unique",
  );

/** `REA_GHIDRA_LOADER_EXTENSIONS_JSON`: a JSON array of pinned loaders. */
export const ghidraLoaderExtensionsJsonSchema = z
  .string()
  .transform((text, context) => {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      context.addIssue({ code: "custom", message: "must be valid JSON" });
      return z.NEVER;
    }
  })
  .pipe(ghidraLoaderExtensionsSchema);
