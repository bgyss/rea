import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { GhidraLoaderExtensionConfig } from "../../config/ghidraLoaderExtensions.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import type { AppConfig } from "../../config/types.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import { readGhidraJar } from "./GhidraExtensions.js";

/** Identity of a loader extension committed to the analysis profile; the path stays local. */
export const ghidraLoaderExtensionSchema = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9\x2D]*$/u),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  loader_name: z.string().regex(/^[A-Z][A-Za-z0-9]*$/u),
});
export type GhidraLoaderExtension = z.infer<typeof ghidraLoaderExtensionSchema>;

/** Language, compiler spec and image base the Switch loader declares for NSO and NRO images. */
export const GHIDRA_SWITCH_LANGUAGE_ID = "AARCH64:LE:64:v8A";
export const GHIDRA_SWITCH_COMPILER_SPEC_ID = "default";
export const GHIDRA_SWITCH_IMAGE_BASE = "0x7100000000";

/** Whether the target is opened through the pinned Switch loader. */
export const isGhidraSwitchTarget = (target: BinaryTarget): boolean =>
  target.format === "switch-nso" || target.format === "switch-nro";

const sha256Of = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const unavailable = (reason: string): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    "ghidra",
    "resolve_analysis_profile",
    reason,
    { userMessage: reason },
  );

/** Pin the configured loader that provides `loaderName`, reading its jar once through an open handle. */
export const resolveGhidraLoaderExtension = async (
  config: AppConfig,
  loaderName: string,
  platform: NodeJS.Platform,
): Promise<Result<GhidraLoaderExtension, AnalysisError>> => {
  if (platform === "win32")
    return err(
      unavailable(
        "Pinned Ghidra loader extensions are not supported on Windows hosts.",
      ),
    );
  const configured: GhidraLoaderExtensionConfig | undefined =
    config.ghidraLoaderExtensions?.find(
      (entry) => entry.loader_name === loaderName,
    );
  if (configured === undefined)
    return err(
      unavailable(
        `No pinned Ghidra loader provides ${loaderName}. Build it with \`npm run build:ghidra-switch-loader\` and list it, with the printed sha256, in REA_GHIDRA_LOADER_EXTENSIONS_JSON.`,
      ),
    );
  try {
    const observed = sha256Of(await readGhidraJar(configured.path));
    if (observed !== configured.sha256)
      return err(
        new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
          diagnostics: {
            extension: configured.id,
            path: configured.path,
            expected_sha256: configured.sha256,
            observed_sha256: observed,
            reason: "The loader jar does not match its pinned SHA-256.",
          },
        }),
      );
    return ok({
      id: configured.id,
      sha256: observed,
      loader_name: configured.loader_name,
    });
  } catch (cause: unknown) {
    return err(
      new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
        cause,
        diagnostics: {
          extension: configured.id,
          path: configured.path,
          reason: cause instanceof Error ? cause.message : String(cause),
        },
      }),
    );
  }
};

/** `<settings>/<app>/<versioned>/Extensions`, the first directory Ghidra scans for installed extensions. */
export const ghidraUserExtensionsDirectory = (
  settingsRoot: string,
  versionedName: string,
): string => join(settingsRoot, "ghidra", versionedName, "Extensions");

/** `ghidra_<version>_<release>`, from the installation's own application.properties. */
export const ghidraApplicationVersionedName = async (
  installRoot: string,
): Promise<string> => {
  const text = await readFile(
    join(installRoot, "Ghidra", "application.properties"),
    "utf8",
  );
  const property = (key: string): string => {
    const line = text
      .split(/\r?\n/u)
      .find((candidate) => candidate.startsWith(`${key}=`));
    const value = line?.slice(key.length + 1).trim();
    if (value === undefined || value === "")
      throw new Error(`Ghidra application.properties lacks ${key}`);
    return value;
  };
  return `ghidra_${property("application.version")}_${property("application.release.name")}`;
};

/**
 * Re-verify each committed loader against the bytes now on disk, then write it
 * as a Ghidra extension. Nothing is written when any digest differs. Ghidra's
 * production class search scans a module's `lib` jar only when the jar's file
 * name starts with the module directory's name, so the jar is `<id>/lib/<id>.jar`.
 */
export const installGhidraLoaderExtensions = async (input: {
  readonly extensions: readonly {
    readonly extension: GhidraLoaderExtension;
    readonly path: string;
  }[];
  readonly extensionsDirectory: string;
  readonly ghidraVersion: string;
}): Promise<void> => {
  const verified: { extension: GhidraLoaderExtension; bytes: Buffer }[] = [];
  for (const { extension, path } of input.extensions) {
    ghidraLoaderExtensionSchema.parse(extension);
    const bytes = await readGhidraJar(path);
    if (sha256Of(bytes) !== extension.sha256)
      throw new Error(
        `Ghidra loader digest differs from the committed profile: ${extension.id} (${path})`,
      );
    verified.push({ extension, bytes });
  }
  for (const { extension, bytes } of verified) {
    const root = join(input.extensionsDirectory, extension.id);
    await mkdir(join(root, "lib"), { recursive: true, mode: 0o700 });
    await writeFile(join(root, "Module.manifest"), "", { mode: 0o600 });
    await writeFile(
      join(root, "extension.properties"),
      [
        `name=${extension.id}`,
        "description=Operator-pinned loader installed by REA for this session.",
        "author=REA",
        "createdOn=2026-10-11",
        `version=${input.ghidraVersion}`,
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    await writeFile(join(root, "lib", `${extension.id}.jar`), bytes, {
      mode: 0o600,
    });
  }
};
