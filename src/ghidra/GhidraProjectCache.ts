import { mkdir, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";

import writeFileAtomic from "write-file-atomic";
import { z } from "zod";

import { digestSchema } from "../domain/digests.js";

/** Caller-selected private root holding analysed Ghidra projects. */
export interface GhidraProjectCacheOptions {
  readonly root: string;
}

/** Identity every cached project must match before a session reuses it. */
export interface GhidraProjectCacheKey {
  readonly targetSha256: string;
  readonly profileDigest: string;
  readonly providerVersion: string;
}

/** One analysed project, ready for `-process -noanalysis`. */
export interface GhidraProjectCacheEntry {
  readonly status: "hit" | "created";
  readonly entryRoot: string;
  readonly projectRoot: string;
  readonly programName: string;
}

const MANIFEST = "cache.json";
const PROJECT = "project";

const manifestSchema = z.strictObject({
  schema_version: z.literal("rea.ghidra-project-cache.v1"),
  target_sha256: digestSchema,
  profile_digest: digestSchema,
  provider_version: z.string().min(1),
  program_name: z.string().min(1),
  created_at: z.iso.datetime(),
});

/** Another live session holds Ghidra's lock on this cache entry. */
export class GhidraProjectCacheBusyError extends Error {
  constructor(readonly entryRoot: string) {
    super(
      `Ghidra project cache entry is open in another session: ${entryRoot}`,
    );
    this.name = "GhidraProjectCacheBusyError";
  }
}

/** Entry directory for one target and analysis profile. */
export const ghidraProjectCacheEntryRoot = (
  root: string,
  key: GhidraProjectCacheKey,
): string => join(root, key.targetSha256, key.profileDigest);

/**
 * Read a promoted entry. A missing manifest is a cache miss; a manifest for a
 * different identity is an error, never a silent reuse or overwrite.
 */
export const readGhidraProjectCacheEntry = async (
  entryRoot: string,
  key: GhidraProjectCacheKey,
): Promise<GhidraProjectCacheEntry | undefined> => {
  let text: string;
  try {
    text = await readFile(join(entryRoot, MANIFEST), "utf8");
  } catch (cause: unknown) {
    if (isCode(cause, "ENOENT")) return undefined;
    throw cause;
  }
  const parsed = manifestSchema.safeParse(JSON.parse(text));
  if (
    !parsed.success ||
    parsed.data.target_sha256 !== key.targetSha256 ||
    parsed.data.profile_digest !== key.profileDigest ||
    parsed.data.provider_version !== key.providerVersion
  )
    throw new Error(
      `Ghidra project cache entry does not match this target, profile, and Ghidra version; remove it to rebuild: ${entryRoot}`,
    );
  return {
    status: "hit",
    entryRoot,
    projectRoot: join(entryRoot, PROJECT),
    programName: parsed.data.program_name,
  };
};

/** Private staging directory whose `project` subdirectory receives one import. */
export const createGhidraProjectCacheStaging = async (
  root: string,
  key: GhidraProjectCacheKey,
  runId: string,
): Promise<{ readonly stagingRoot: string; readonly projectRoot: string }> => {
  const stagingRoot = join(
    root,
    key.targetSha256,
    // Ghidra rejects project paths with an element starting with ".".
    `staging-${key.profileDigest}-${runId}`,
  );
  await mkdir(join(stagingRoot, PROJECT), { recursive: true, mode: 0o700 });
  return { stagingRoot, projectRoot: join(stagingRoot, PROJECT) };
};

/**
 * Seal a staged import with its manifest and rename it into place. When a
 * concurrent import won the rename, discard this one and reuse the winner.
 */
export const promoteGhidraProjectCacheStaging = async (
  stagingRoot: string,
  root: string,
  key: GhidraProjectCacheKey,
  programName: string,
): Promise<GhidraProjectCacheEntry> => {
  await writeFileAtomic(
    join(stagingRoot, MANIFEST),
    `${JSON.stringify({
      schema_version: "rea.ghidra-project-cache.v1",
      target_sha256: key.targetSha256,
      profile_digest: key.profileDigest,
      provider_version: key.providerVersion,
      program_name: programName,
      created_at: new Date().toISOString(),
    })}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  const entryRoot = ghidraProjectCacheEntryRoot(root, key);
  try {
    await rename(stagingRoot, entryRoot);
  } catch (cause: unknown) {
    if (!isCode(cause, "EEXIST") && !isCode(cause, "ENOTEMPTY")) throw cause;
    await discardGhidraProjectCacheStaging(stagingRoot);
    const existing = await readGhidraProjectCacheEntry(entryRoot, key);
    if (existing === undefined) throw cause;
    return existing;
  }
  return {
    status: "created",
    entryRoot,
    projectRoot: join(entryRoot, PROJECT),
    programName,
  };
};

/** Remove an unpromoted staging directory. */
export const discardGhidraProjectCacheStaging = (
  stagingRoot: string,
): Promise<void> => rm(stagingRoot, { recursive: true, force: true });

/** Ghidra's headless log lines that prove the import pass saved the program. */
export const ghidraImportPassSaved = (log: string): boolean =>
  /REPORT: Save succeeded for: /u.test(log) &&
  /REPORT: Import succeeded/u.test(log);

const isCode = (cause: unknown, code: string): boolean =>
  cause instanceof Error && "code" in cause && cause.code === code;
