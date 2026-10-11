import {
  GHIDRA_SEED_SCRIPT,
  snapshotGhidraAnalysisSeeds,
  type GhidraSeedCommitment,
} from "./GhidraAnalysisSeeds.js";
import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { mkdir, readFile, realpath } from "node:fs/promises";
import { basename, dirname, join, posix, win32 } from "node:path";

import writeFileAtomic from "write-file-atomic";

import { windowsPrivateRuntime } from "../windows/WindowsPrivateRuntime.js";
import {
  quoteWindowsBatchToken,
  windowsBatchCommand,
  WindowsBatchCommandError,
} from "../process/WindowsBatchCommand.js";

import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type { RawImageBlock } from "../domain/rawImage.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  cleanupOwnedProcessGroup,
  cleanupWindowsProcessTree,
  type ProcessCleanupResult,
} from "../process/ProcessOwnership.js";
import {
  type ProviderProcessLaunch,
  ProviderProcessSupervisor,
  type SpawnedOwnedProviderProcess,
  spawnOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { ghidraJavaEnvironment } from "./GhidraInstallation.js";
import { ghidraJavaLaunch } from "./GhidraJavaLaunch.js";
import {
  createGhidraProjectCacheStaging,
  discardGhidraProjectCacheStaging,
  ghidraImportPassSaved,
  ghidraProjectCacheEntryRoot,
  promoteGhidraProjectCacheStaging,
  readGhidraProjectCacheEntry,
  type GhidraProjectCacheEntry,
  type GhidraProjectCacheKey,
  type GhidraProjectCacheOptions,
} from "./GhidraProjectCache.js";
import type { GhidraTransportKind } from "./GhidraTransport.js";
import {
  snapshotGhidraExtensions,
  type GhidraExtension,
} from "./extensions/GhidraExtensions.js";

import {
  inspectGhidraPspExtension,
  type GhidraPspExtension,
} from "./GhidraPspExtension.js";

/** Private paths and identity material for one headless Ghidra import. */
export interface GhidraLaunchSession {
  readonly runtimeRoot: string;
  readonly transport: GhidraTransportKind;
  readonly endpointPath: string;
  readonly token: string;
  readonly runId: string;
  readonly targetPath: string;
  readonly targetSha256: string;
  readonly providerVersion: string;
  readonly profileDigest: string;
}

/** Process plus private log coordinates returned by a Ghidra launcher. */
export type GhidraLaunch = ProviderProcessLaunch & {
  readonly projectRoot: string;
  readonly ghidraLogPath: string;
  readonly scriptLogPath: string;
  /** Present when the session reopened a persistent analysed project. */
  readonly projectCache?: GhidraProjectCacheEntry;
};

/** Provider-owned capability that starts one isolated headless analysis. */
export interface GhidraLauncher {
  launch(
    session: GhidraLaunchSession,
    options?: { readonly signal?: AbortSignal },
  ): Promise<Result<GhidraLaunch, GhidraLaunchError | AnalysisCancelledError>>;
}

/** Local launch failure retained as the cause of a provider-neutral error. */
export class GhidraLaunchError extends Error {
  readonly #partialLaunch: GhidraLaunch | undefined;

  constructor(
    message: string,
    options?: ErrorOptions & { readonly partialLaunch?: GhidraLaunch },
  ) {
    const { partialLaunch, ...errorOptions } = options ?? {};
    super(message, errorOptions);
    this.name = "GhidraLaunchError";
    this.#partialLaunch = partialLaunch;
  }

  /** Process ownership retained for the client to retry an incomplete rollback. */
  get partialLaunch(): GhidraLaunch | undefined {
    return this.#partialLaunch;
  }
}

/** Static coordinates for an extracted Ghidra release and packaged script. */
export interface GhidraHeadlessLauncherOptions {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly analyzeHeadlessPath: string;
  readonly javaHome?: string;
  readonly bridgeScriptPath: string;
  readonly platform?: NodeJS.Platform;
  readonly comSpec?: string;
  /** Select the admitted 16-bit real-mode MZ import instead of auto-detection. */
  readonly dosMz?: true;
  readonly dosCom?: true;
  readonly rawBinary?: {
    readonly languageId: string;
    readonly compilerSpecId: string;
    readonly baseAddr: string;
  };
  /** Explicit import language committed by the analysis profile. */
  readonly languageOverride?: GhidraLanguageOverride;
  /** Auto-analyzers disabled before default auto-analysis, as configured. */
  readonly disabledAnalyzers?: readonly string[];
  /** Caller seeds committed by the analysis profile, applied before analysis. */
  readonly analysisSeeds?: GhidraSeedCommitment;
  readonly analysisExtensions?: readonly GhidraExtension[];
  readonly pspExtension?: GhidraPspExtension;
  /** Spawn seam for provider-boundary lifecycle tests. */
  readonly spawnProcess?: typeof spawnOwnedProviderProcess;
  /** Import headerless bytes with a caller-declared language, base and entry. */
  readonly rawImage?: GhidraRawImageImport;
  /** Analyse once into a persistent project, then reopen it per session. */
  readonly projectCache?: GhidraProjectCacheOptions;
}

/** Explicit BinaryLoader import for a raw image; addresses are 0x-prefixed hex. */
export type GhidraRawImageImport =
  | {
      readonly mode: "flat";
      readonly languageId: string;
      readonly compilerSpecId: string;
      readonly baseAddress: string;
      readonly entryAddress: string;
    }
  | {
      /** Blocks are rebuilt from verified file bytes by the preparation script. */
      readonly mode: "mapped";
      readonly languageId: string;
      readonly compilerSpecId: string;
      readonly blocks: readonly RawImageBlock[];
    };

/** Launch Ghidra without copying scripts into or modifying its installation. */
export class GhidraHeadlessLauncher implements GhidraLauncher {
  readonly options: GhidraHeadlessLauncherOptions;
  constructor(options: GhidraHeadlessLauncherOptions) {
    this.options = {
      ...options,
      environment: snapshotEnvironment(options.environment, options.platform),
    };
  }

  async launch(
    session: GhidraLaunchSession,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<Result<GhidraLaunch, GhidraLaunchError | AnalysisCancelledError>> {
    if (isAborted(options.signal))
      return err(new AnalysisCancelledError("open_binary"));
    const paths = ghidraRuntimePaths(session.runtimeRoot);
    const platform = this.options.platform ?? process.platform;
    let started: SpawnedOwnedProviderProcess | undefined;
    let projectCache: GhidraProjectCacheEntry | undefined;
    const launchOf = (spawned: SpawnedOwnedProviderProcess): GhidraLaunch => ({
      ...ownedGhidraLaunch(spawned, paths, platform),
      projectRoot: projectCache?.projectRoot ?? paths.projectRoot,
      ...(projectCache === undefined ? {} : { projectCache }),
    });
    try {
      const psp = this.options.pspExtension;
      if (psp !== undefined) {
        const installedRoot = await realpath(
          join(
            dirname(this.options.analyzeHeadlessPath),
            "..",
            "Ghidra",
            "Extensions",
            "ghidra-allegrex",
          ),
        );
        if (installedRoot !== psp.root)
          throw new GhidraLaunchError(
            "Allegrex profile does not belong to the selected Ghidra installation.",
          );
        const inspected = await inspectGhidraPspExtension(
          psp.root,
          psp.ghidra_version,
          options.signal,
        );
        if (inspected.sha256 !== psp.sha256)
          throw new GhidraLaunchError(
            "Installed Allegrex content changed since profile resolution; reopen the target to resolve a fresh profile.",
          );
      }
      await createGhidraRuntimeDirectories(paths, platform);
      const seedPath =
        this.options.analysisSeeds === undefined
          ? undefined
          : await snapshotGhidraAnalysisSeeds(
              this.options.analysisSeeds,
              session.runtimeRoot,
            );
      const extensions = await snapshotGhidraExtensions(
        this.options.analysisExtensions ?? [],
        session.runtimeRoot,
      );
      await writeGhidraRuntimeFile(
        paths.descriptorPath,
        `${JSON.stringify({
          transport: session.transport,
          endpoint_path: session.endpointPath,
          token: session.token,
          run_id: session.runId,
          target_sha256: session.targetSha256,
          provider_version: session.providerVersion,
          profile_digest: session.profileDigest,
          ...(extensions.length === 0
            ? {}
            : { analysis_extensions: extensions }),
          ...(this.options.projectCache === undefined
            ? {}
            : { project_persistence: "persistent" }),
        })}\n`,
        platform,
      );
      if (this.options.rawImage?.mode === "mapped")
        await writeGhidraRuntimeFile(
          paths.rawImageMapPath,
          `${JSON.stringify({ blocks: this.options.rawImage.blocks })}\n`,
          platform,
        );
      if (isAborted(options.signal))
        return err(new AnalysisCancelledError("open_binary"));
      const prepared = await this.#sessionArguments({
        session,
        paths,
        platform,
        signal: options.signal,
        psp: psp !== undefined,
        seedPath,
      });
      if (!prepared.ok) return prepared;
      const headlessArguments = prepared.value.arguments;
      projectCache = prepared.value.projectCache;
      const command = await this.#command(
        paths,
        headlessArguments,
        platform,
        options.signal,
      );
      started = await this.#spawn(
        command,
        session.runId,
        platform,
        options.signal,
      );
      const partialLaunch = launchOf(started);
      await writeGhidraRuntimeFile(
        paths.ownershipPath,
        `${JSON.stringify({
          run_id: session.runId,
          transport: session.transport,
          endpoint_path: session.endpointPath,
          pid: started.ownership.leaderPid,
          process_group_id: started.ownership.processGroupId,
          parent_pid: process.pid,
          ownership_kind:
            platform === "win32" ? "windows-job-object" : "posix-process-group",
          launcher: command.command,
          headless_script: this.options.analyzeHeadlessPath,
          created_at: new Date().toISOString(),
        })}\n`,
        platform,
      );
      if (isAborted(options.signal)) {
        throw new AnalysisCancelledError("open_binary");
      }
      return ok(partialLaunch);
    } catch (cause: unknown) {
      const primary = isAborted(options.signal)
        ? new AnalysisCancelledError("open_binary", { cause })
        : new GhidraLaunchError("Ghidra headless launch failed", { cause });
      if (started === undefined) return err(primary);

      let cleanupFailure: unknown;
      try {
        const cleanup = await cleanupStartedProcess(started, platform);
        if (!cleanup.cleaned)
          cleanupFailure = new Error(
            `Ghidra process cleanup was incomplete: ${cleanup.reason}`,
          );
      } catch (failure: unknown) {
        cleanupFailure = failure;
      }
      if (cleanupFailure !== undefined) {
        const partialLaunch = launchOf(started);
        const primaryMessage = isAborted(options.signal)
          ? primary.message
          : `Ghidra headless launch failed: ${cause instanceof Error ? cause.message : String(cause)}`;
        return err(
          new GhidraLaunchError(
            `${primaryMessage}; process cleanup remains incomplete`,
            {
              cause: new AggregateError(
                [primary, cleanupFailure],
                "Ghidra launch rollback did not release its process",
                { cause: primary },
              ),
              partialLaunch,
            },
          ),
        );
      }
      return err(primary);
    }
  }

  /** Ephemeral import arguments, or a reopen of the cached analysed project. */
  async #sessionArguments(context: LaunchContext): Promise<
    Result<
      {
        readonly arguments: readonly string[];
        readonly projectCache?: GhidraProjectCacheEntry;
      },
      GhidraLaunchError | AnalysisCancelledError
    >
  > {
    const { paths } = context;
    const importOptions = this.#importOptions(context);
    if (this.options.projectCache === undefined)
      return ok({ arguments: ghidraHeadlessArguments(importOptions) });
    const cached = await this.#projectCacheEntry(
      this.options.projectCache,
      context,
      importOptions,
    );
    if (!cached.ok) return cached;
    return ok({
      projectCache: cached.value,
      arguments: ghidraHeadlessProcessArguments({
        projectRoot: cached.value.projectRoot,
        programName: cached.value.programName,
        bridgeScriptPath: this.options.bridgeScriptPath,
        descriptorPath: paths.descriptorPath,
        ghidraLogPath: paths.ghidraLogPath,
        scriptLogPath: paths.scriptLogPath,
      }),
    });
  }

  #importOptions(context: LaunchContext): GhidraHeadlessArgumentOptions {
    const { session, paths, platform } = context;
    return {
      platform,
      ...(context.psp ? { psp: true as const } : {}),
      projectRoot: paths.projectRoot,
      targetPath: session.targetPath,
      bridgeScriptPath: this.options.bridgeScriptPath,
      descriptorPath: paths.descriptorPath,
      ghidraLogPath: paths.ghidraLogPath,
      scriptLogPath: paths.scriptLogPath,
      ...(this.options.dosCom === undefined
        ? {}
        : { dosCom: this.options.dosCom }),
      ...(this.options.dosMz === undefined
        ? {}
        : { dosMz: this.options.dosMz }),
      ...(this.options.rawBinary === undefined
        ? {}
        : { rawBinary: this.options.rawBinary }),
      ...(this.options.rawImage === undefined
        ? {}
        : {
            rawImage: this.options.rawImage,
            rawImageMapPath: paths.rawImageMapPath,
          }),
      ...(this.options.languageOverride === undefined
        ? {}
        : { languageOverride: this.options.languageOverride }),
      ...(context.seedPath === undefined ? {} : { seedPath: context.seedPath }),
      ...(this.options.disabledAnalyzers === undefined
        ? {}
        : { disabledAnalyzers: this.options.disabledAnalyzers }),
    };
  }

  async #command(
    paths: ReturnType<typeof ghidraRuntimePaths>,
    headlessArguments: readonly string[],
    platform: NodeJS.Platform,
    signal: AbortSignal | undefined,
  ): Promise<
    GhidraHeadlessCommand & { readonly environment: NodeJS.ProcessEnv }
  > {
    const scriptCommand = ghidraHeadlessCommand({
      environment: this.options.environment,
      platform,
      analyzeHeadlessPath: this.options.analyzeHeadlessPath,
      arguments: headlessArguments,
      ...(this.options.comSpec === undefined
        ? {}
        : { comSpec: this.options.comSpec }),
    });
    const environment = ghidraLaunchEnvironment(
      paths,
      this.options.javaHome,
      platform,
      scriptCommand.command,
      this.options.environment,
    );
    if (platform !== "win32" && this.options.javaHome === undefined)
      throw new GhidraLaunchError(
        "POSIX Ghidra requires its inspected JDK home",
      );
    return platform !== "win32" && this.options.javaHome !== undefined
      ? ghidraJavaLaunch({
          platform,
          analyzeHeadlessPath: this.options.analyzeHeadlessPath,
          javaHome: this.options.javaHome,
          homeRoot: paths.homeRoot,
          tempRoot: paths.tempRoot,
          arguments: headlessArguments,
          environment,
          ...(signal === undefined ? {} : { signal }),
        })
      : { ...scriptCommand, environment };
  }

  #spawn(
    command: GhidraHeadlessCommand & {
      readonly environment: NodeJS.ProcessEnv;
    },
    runId: string,
    platform: NodeJS.Platform,
    signal: AbortSignal | undefined,
  ): Promise<SpawnedOwnedProviderProcess> {
    return (this.options.spawnProcess ?? spawnOwnedProviderProcess)({
      command: command.command,
      arguments: command.arguments,
      runId,
      // POSIX launches the inspected JVM directly; script wrappers cannot
      // preserve JVM property paths containing spaces as single arguments.
      expectedCommand: platform !== "win32" ? command.command : null,
      windowsVerbatimArguments: platform === "win32",
      platform,
      env: command.environment,
      hostEnvironment: {},
      ...(signal === undefined ? {} : { signal }),
    });
  }

  /** Reuse the promoted project, or import and analyse once into staging. */
  async #projectCacheEntry(
    cache: GhidraProjectCacheOptions,
    context: LaunchContext,
    importOptions: GhidraHeadlessArgumentOptions,
  ): Promise<
    Result<GhidraProjectCacheEntry, GhidraLaunchError | AnalysisCancelledError>
  > {
    const { session } = context;
    const key: GhidraProjectCacheKey = {
      targetSha256: session.targetSha256,
      profileDigest: session.profileDigest,
      providerVersion: session.providerVersion,
    };
    const existing = await readGhidraProjectCacheEntry(
      ghidraProjectCacheEntryRoot(cache.root, key),
      key,
    );
    if (existing !== undefined) return ok(existing);
    const staging = await createGhidraProjectCacheStaging(
      cache.root,
      key,
      session.runId,
    );
    let promoted = false;
    try {
      const saved = await this.#importPass(
        { ...importOptions, projectRoot: staging.projectRoot },
        context,
      );
      if (!saved.ok) return saved;
      const entry = await promoteGhidraProjectCacheStaging(
        staging.stagingRoot,
        cache.root,
        key,
        basename(session.targetPath),
      );
      promoted = true;
      return ok(entry);
    } finally {
      if (!promoted)
        await discardGhidraProjectCacheStaging(staging.stagingRoot);
    }
  }

  /** Run one import and analysis to completion; Ghidra saves it on exit. */
  async #importPass(
    importOptions: GhidraHeadlessArgumentOptions,
    context: LaunchContext,
  ): Promise<Result<null, GhidraLaunchError | AnalysisCancelledError>> {
    const { paths, platform, signal } = context;
    const logs = {
      ghidraLogPath: paths.importGhidraLogPath,
      scriptLogPath: paths.importScriptLogPath,
    };
    const command = await this.#command(
      paths,
      ghidraHeadlessImportArguments({ ...importOptions, ...logs }),
      platform,
      signal,
    );
    const started = await this.#spawn(
      command,
      context.session.runId,
      platform,
      signal,
    );
    const supervisor = new ProviderProcessSupervisor(
      ownedGhidraProcess(started, platform),
      { maxDiagnosticBytes: 64 * 1024 },
    );
    while (!(await supervisor.waitForExit(250)))
      if (isAborted(signal)) {
        await supervisor.stop();
        return err(new AnalysisCancelledError("open_binary"));
      }
    const exit = supervisor.snapshot();
    await supervisor.stop();
    const log = await readFile(paths.importGhidraLogPath, "utf8").catch(
      () => "",
    );
    if (exit.exitCode !== 0 || !ghidraImportPassSaved(log)) {
      // The runtime root, and the log with it, is removed when startup fails.
      const reported = `${log}\n${exit.stdout.text}\n${exit.stderr.text}`
        .split("\n")
        .filter((line) => /ERROR|Exception/u.test(line))
        .slice(-5)
        .map((line) => line.trim());
      return err(
        new GhidraLaunchError(
          `Ghidra project cache import did not save an analysed program (exit ${String(exit.exitCode)})${reported.length === 0 ? "" : `: ${reported.join(" | ")}`}`,
        ),
      );
    }
    return ok(null);
  }
}

interface LaunchContext {
  readonly session: GhidraLaunchSession;
  readonly paths: ReturnType<typeof ghidraRuntimePaths>;
  readonly platform: NodeJS.Platform;
  readonly signal: AbortSignal | undefined;
  readonly psp: boolean;
  readonly seedPath: string | undefined;
}

const ownedGhidraLaunch = (
  spawned: SpawnedOwnedProviderProcess,
  paths: ReturnType<typeof ghidraRuntimePaths>,
  platform: NodeJS.Platform,
): GhidraLaunch => ({
  ...ownedGhidraProcess(spawned, platform),
  projectRoot: paths.projectRoot,
  ghidraLogPath: paths.ghidraLogPath,
  scriptLogPath: paths.scriptLogPath,
});

const ownedGhidraProcess = (
  spawned: SpawnedOwnedProviderProcess,
  platform: NodeJS.Platform,
): Pick<
  Extract<ProviderProcessLaunch, { readonly ownsProcessLifetime: true }>,
  "process" | "ownsProcessLifetime" | "ownership" | "cleanup"
> => ({
  process: spawned.process,
  ownsProcessLifetime: true,
  ownership: spawned.ownership,
  cleanup: () => cleanupStartedProcess(spawned, platform),
});

/** Exact executable and argv passed to shell-free process creation. */
export interface GhidraHeadlessCommand {
  readonly command: string;
  readonly arguments: readonly string[];
}

/** Build a direct POSIX launch or a conservatively quoted Windows batch call. */
export const ghidraHeadlessCommand = (options: {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly platform: NodeJS.Platform;
  readonly analyzeHeadlessPath: string;
  readonly arguments: readonly string[];
  readonly comSpec?: string;
}): GhidraHeadlessCommand => {
  if (options.platform !== "win32")
    return {
      command: options.analyzeHeadlessPath,
      arguments: [...options.arguments],
    };
  const command = ghidraBatchStep(() =>
    windowsBatchCommand({
      environment: options.environment,
      batchPath: options.analyzeHeadlessPath,
      arguments: options.arguments,
      ...(options.comSpec === undefined ? {} : { comSpec: options.comSpec }),
    }),
  );
  if ((command.arguments.at(-1)?.length ?? 0) > 30_000)
    throw new GhidraLaunchError(
      "Windows Ghidra command exceeds the P0 length limit",
    );
  return command;
};

/** Keep Ghidra's launch error type and P0 wording for shared batch checks. */
const ghidraBatchStep = <T>(step: () => T): T => {
  try {
    return step();
  } catch (cause: unknown) {
    if (!(cause instanceof WindowsBatchCommandError)) throw cause;
    throw new GhidraLaunchError(
      cause.reason === "metacharacter"
        ? "Windows Ghidra P0 paths cannot contain command-interpreter metacharacters"
        : cause.message,
      { cause },
    );
  }
};

const cleanupStartedProcess = (
  started: SpawnedOwnedProviderProcess,
  platform: NodeJS.Platform,
): Promise<ProcessCleanupResult> =>
  started.cleanup !== undefined
    ? started.cleanup()
    : platform === "win32"
      ? cleanupWindowsProcessTree(started.ownership.leaderPid)
      : cleanupOwnedProcessGroup(started.ownership);

/** Paths encoded into one bounded analyzeHeadless invocation. */
export interface GhidraHeadlessArgumentOptions {
  readonly platform?: NodeJS.Platform;
  readonly projectRoot: string;
  readonly targetPath: string;
  readonly bridgeScriptPath: string;
  readonly descriptorPath: string;
  readonly ghidraLogPath: string;
  readonly scriptLogPath: string;
  readonly psp?: true;
  readonly dosMz?: true;
  readonly dosCom?: true;
  readonly rawBinary?: {
    readonly languageId: string;
    readonly compilerSpecId: string;
    readonly baseAddr: string;
  };
  readonly languageOverride?: GhidraLanguageOverride;
  /** Auto-analyzers disabled by the pre-analysis options script. */
  readonly disabledAnalyzers?: readonly string[];
  /** Canonical seed snapshot passed to the pre-analysis seed script. */
  readonly seedPath?: string;
  readonly rawImage?: GhidraRawImageImport;
  /** Private runtime file holding the block map for a mapped raw image. */
  readonly rawImageMapPath?: string;
}

/** Import and analyse into a persistent project without serving a session. */
export const ghidraHeadlessImportArguments = (
  options: GhidraHeadlessArgumentOptions,
): readonly string[] => {
  const ephemeral = ghidraHeadlessArguments(options);
  // Keep every pre- and post-analysis repair script; drop only the bridge.
  const bridge = ephemeral.lastIndexOf("-postScript");
  return ephemeral
    .slice(0, bridge)
    .filter((value) => value !== "-readOnly" && value !== "-deleteProject");
};

/** Reopen one analysed program from a persistent project without re-analysis. */
export const ghidraHeadlessProcessArguments = (options: {
  readonly projectRoot: string;
  readonly programName: string;
  readonly bridgeScriptPath: string;
  readonly descriptorPath: string;
  readonly ghidraLogPath: string;
  readonly scriptLogPath: string;
}): readonly string[] => [
  options.projectRoot,
  "rea-project",
  "-process",
  options.programName,
  "-noanalysis",
  "-log",
  options.ghidraLogPath,
  "-scriptlog",
  options.scriptLogPath,
  "-scriptPath",
  dirname(options.bridgeScriptPath),
  "-postScript",
  options.bridgeScriptPath,
  options.descriptorPath,
];

/** BinaryLoader import options for a raw image; mapped images import one stub byte. */
const rawImageImportArguments = (
  rawImage: GhidraRawImageImport,
): readonly string[] => [
  "-loader",
  "BinaryLoader",
  "-loader-baseAddr",
  rawImage.mode === "flat" ? rawImage.baseAddress : "0x0",
  ...(rawImage.mode === "flat" ? [] : ["-loader-length", "0x1"]),
  "-processor",
  rawImage.languageId,
  "-cspec",
  rawImage.compilerSpecId,
];

/** Build the complete read-only headless invocation in deterministic order. */
export const ghidraHeadlessArguments = (
  options: GhidraHeadlessArgumentOptions,
): readonly string[] => {
  // Bridge script paths use the target platform's syntax, which differs from
  // the host when building a cross-platform invocation.
  const scriptPath =
    (options.platform ?? process.platform) === "win32" ? win32 : posix;
  const bridgeDirectory = scriptPath.dirname(options.bridgeScriptPath);
  const override = options.languageOverride;
  const rawBinary = options.rawBinary;
  if (
    options.psp === true &&
    (options.dosMz === true ||
      options.dosCom === true ||
      override !== undefined)
  )
    throw new Error(
      "A PSP ELF import cannot be combined with DOS or a generic Ghidra language override.",
    );
  const rawImage = options.rawImage;
  if (
    rawImage !== undefined &&
    (options.psp === true ||
      options.dosMz === true ||
      options.dosCom === true ||
      override !== undefined ||
      rawBinary !== undefined)
  )
    throw new Error(
      "A raw-image import cannot be combined with another import selection.",
    );
  if (options.psp === true && rawBinary !== undefined)
    throw new Error(
      "A PSP ELF import cannot be combined with a raw-binary import.",
    );
  if (
    override !== undefined &&
    (options.dosMz === true || options.dosCom === true)
  )
    throw new Error(
      "A Ghidra language override cannot be combined with a DOS import.",
    );
  if (override !== undefined && rawBinary !== undefined)
    throw new Error(
      "A Ghidra language override cannot be combined with a raw-binary import.",
    );
  if (
    rawBinary !== undefined &&
    (options.dosMz === true || options.dosCom === true)
  )
    throw new Error(
      "A raw-binary import cannot be combined with a DOS import.",
    );
  return [
    options.projectRoot,
    "rea-project",
    "-import",
    options.targetPath,
    ...(options.dosMz === true
      ? [
          "-loader",
          "MzLoader",
          "-processor",
          "x86:LE:16:Real Mode",
          "-cspec",
          "default",
        ]
      : options.dosCom === true
        ? [
            "-loader",
            "BinaryLoader",
            "-loader-baseAddr",
            "1000:0100",
            "-processor",
            "x86:LE:16:Real Mode",
            "-cspec",
            "default",
          ]
        : rawImage !== undefined
          ? rawImageImportArguments(rawImage)
          : rawBinary === undefined
            ? options.psp === true
              ? [
                  "-loader",
                  "PspElfLoader",
                  "-processor",
                  "Allegrex:LE:32:default",
                  "-cspec",
                  "default",
                ]
              : override !== undefined
                ? [
                    "-processor",
                    override.languageId,
                    ...(override.compilerSpecId === undefined
                      ? []
                      : ["-cspec", override.compilerSpecId]),
                  ]
                : []
            : [
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                rawBinary.baseAddr,
                "-processor",
                rawBinary.languageId,
                "-cspec",
                rawBinary.compilerSpecId,
              ]),
    "-readOnly",
    "-deleteProject",
    "-log",
    options.ghidraLogPath,
    "-scriptlog",
    options.scriptLogPath,
    "-scriptPath",
    bridgeDirectory,
    ...(options.dosCom === true
      ? [
          "-preScript",
          scriptPath.join(bridgeDirectory, "ReaGhidraPrepareCom.java"),
        ]
      : []),
    ...(rawBinary === undefined
      ? []
      : [
          "-preScript",
          scriptPath.join(bridgeDirectory, "ReaGhidraPrepareRaw.java"),
          rawBinary.languageId,
          rawBinary.baseAddr,
        ]),
    ...(rawImage === undefined
      ? []
      : [
          "-preScript",
          scriptPath.join(bridgeDirectory, "ReaGhidraPrepareRawImage.java"),
          rawImage.mode === "flat"
            ? rawImage.entryAddress
            : `map=${options.rawImageMapPath ?? ""}`,
        ]),
    // Seeds follow any loader preparation and precede default auto-analysis.
    ...(options.seedPath === undefined
      ? []
      : [
          "-preScript",
          scriptPath.join(bridgeDirectory, GHIDRA_SEED_SCRIPT),
          options.seedPath,
        ]),
    // Analyzer options must apply before default auto-analysis and before the
    // post-analysis repair and bridge scripts start serving.
    ...(options.disabledAnalyzers === undefined ||
    options.disabledAnalyzers.length === 0
      ? []
      : [
          "-preScript",
          scriptPath.join(bridgeDirectory, "ReaGhidraAnalysisOptions.java"),
          options.disabledAnalyzers.join(","),
        ]),
    ...((options.platform ?? process.platform) === "win32"
      ? []
      : [
          "-postScript",
          scriptPath.join(bridgeDirectory, "ReaGhidraNoReturnFix.java"),
        ]),
    "-postScript",
    // Ghidra checks the caller's cwd before scriptPath for a basename. Select
    // the packaged source explicitly so unrelated entries cannot shadow it.
    options.bridgeScriptPath,
    options.descriptorPath,
  ];
};

const ghidraRuntimePaths = (runtimeRoot: string) => ({
  projectRoot: join(runtimeRoot, "project"),
  homeRoot: join(runtimeRoot, "home"),
  tempRoot: join(runtimeRoot, "tmp"),
  cacheRoot: join(runtimeRoot, "cache"),
  configRoot: join(runtimeRoot, "config"),
  dataRoot: join(runtimeRoot, "data"),
  descriptorPath: join(runtimeRoot, "session.json"),
  rawImageMapPath: join(runtimeRoot, "raw-image-map.json"),
  ownershipPath: join(runtimeRoot, "ownership.json"),
  ghidraLogPath: join(runtimeRoot, "ghidra.log"),
  scriptLogPath: join(runtimeRoot, "script.log"),
  importGhidraLogPath: join(runtimeRoot, "import-ghidra.log"),
  importScriptLogPath: join(runtimeRoot, "import-script.log"),
});

const createGhidraRuntimeDirectories = async (
  paths: ReturnType<typeof ghidraRuntimePaths>,
  platform: NodeJS.Platform,
): Promise<void> => {
  if (platform === "win32") {
    const runtime = windowsPrivateRuntime(dirname(paths.projectRoot));
    for (const path of [
      paths.projectRoot,
      paths.homeRoot,
      paths.tempRoot,
      paths.cacheRoot,
      paths.configRoot,
      paths.dataRoot,
    ])
      runtime.mkdir(basename(path));
    return;
  }
  await Promise.all(
    [
      paths.projectRoot,
      paths.homeRoot,
      paths.tempRoot,
      paths.cacheRoot,
      paths.configRoot,
      paths.dataRoot,
    ].map((path) => mkdir(path, { recursive: true, mode: 0o700 })),
  );
};

const writeGhidraRuntimeFile = async (
  path: string,
  content: string,
  platform: NodeJS.Platform,
): Promise<void> => {
  if (platform === "win32") {
    windowsPrivateRuntime(dirname(path)).writeFile(basename(path), content);
    return;
  }
  await writeFileAtomic(path, content, { encoding: "utf8", mode: 0o600 });
};

const ghidraLaunchEnvironment = (
  paths: ReturnType<typeof ghidraRuntimePaths>,
  javaHome: string | undefined,
  platform: NodeJS.Platform,
  executable: string,
  selectedEnvironment: Readonly<NodeJS.ProcessEnv>,
): NodeJS.ProcessEnv => {
  return {
    ...ghidraJavaEnvironment(javaHome, selectedEnvironment, platform),
    ...ghidraHeadlessJavaOptions(paths.homeRoot, paths.tempRoot, platform),
    HOME: paths.homeRoot,
    TMPDIR: paths.tempRoot,
    ...(platform === "win32"
      ? {
          // Batch FOR /F launches another command interpreter through ComSpec.
          // Use the same executable with the spelling consumed by cmd.exe.
          ComSpec: executable.replaceAll("/", "\\"),
          USERPROFILE: paths.homeRoot,
          APPDATA: paths.configRoot,
          LOCALAPPDATA: paths.cacheRoot,
          TEMP: paths.tempRoot,
          TMP: paths.tempRoot,
        }
      : {}),
    XDG_CACHE_HOME: paths.cacheRoot,
    XDG_CONFIG_HOME: paths.configRoot,
    XDG_DATA_HOME: paths.dataRoot,
  };
};

/** Encode provider-owned JVM paths for the platform launcher that consumes them. */
export const ghidraHeadlessJavaOptions = (
  homeRoot: string,
  tempRoot: string,
  platform: NodeJS.Platform,
): Pick<
  NodeJS.ProcessEnv,
  "JDK_JAVA_OPTIONS" | "GHIDRA_HEADLESS_JAVA_OPTIONS"
> => {
  const options = [`-Duser.home=${homeRoot}`, `-Djava.io.tmpdir=${tempRoot}`];
  if (platform === "win32")
    return {
      JDK_JAVA_OPTIONS: [...options, "-XX:-UsePerfData"]
        .map((option) => ghidraBatchStep(() => quoteWindowsBatchToken(option)))
        .join(" "),
      GHIDRA_HEADLESS_JAVA_OPTIONS: "",
    };
  // POSIX launches the JVM directly, so these properties travel as separate
  // argv items instead of the shell-split analyzeHeadless option list.
  return { JDK_JAVA_OPTIONS: "", GHIDRA_HEADLESS_JAVA_OPTIONS: "" };
};

const isAborted = (signal?: AbortSignal): boolean => signal?.aborted === true;
