import { isAnnotationOperation } from "../domain/native/nativeDataAnnotations.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { fileURLToPath } from "node:url";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisClientContext,
  type AnalysisOperation,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import {
  ghidraSeedCommitmentSchema,
  ghidraSeedFailure,
  ghidraSeedLimitations,
} from "./GhidraAnalysisSeeds.js";
import {
  ghidraProfileDisabledAnalyzers,
  ghidraProfileLanguageOverride,
  sameGhidraDisabledAnalyzers,
  sameGhidraLanguageOverride,
} from "./GhidraAnalysisProfile.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  AnalysisCancelledError,
  AnalysisArtifactChangedError,
  AnalysisAccessDeniedError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import type { Logger } from "pino";
import { GhidraClient } from "./GhidraClient.js";
import type { GhidraClientOptions } from "./GhidraClientTypes.js";
import {
  isGhidraFunctionOperation,
  parseGhidraFunctionInput,
  parseGhidraFunctionResult,
} from "./GhidraFunctionValues.js";
import {
  isGhidraInventoryOperation,
  parseGhidraInventoryInput,
  parseGhidraInventoryResult,
} from "./GhidraInventoryValues.js";
import {
  ghidraInstallationDiagnostics,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import {
  isGhidraPspTarget,
  GHIDRA_PSP_LIMITATIONS,
} from "./GhidraPspProfile.js";
import { ghidraPspExtensionSchema } from "./GhidraPspExtension.js";
import { unverifiedGhidraBuildLimitation } from "./GhidraInstallationPolicy.js";
import {
  GhidraHeadlessLauncher,
  type GhidraRawImageImport,
} from "./GhidraLauncher.js";
import { GhidraProjectCacheBusyError } from "./GhidraProjectCache.js";
import type { RawImageProfile } from "../domain/rawImage.js";
import { attestGhidraNativeLoadImage } from "./GhidraLoadImageAttest.js";
import {
  NATIVE_AOT_MAX_REPORT_BYTES,
  NATIVE_AOT_MAX_SOURCE_BYTES,
  nativeAotSnapshotOverCapacity,
  parseNativeAotPe,
  type NativeAotPeResult,
} from "../domain/native/nativeAotPe.js";
import {
  ABORTED,
  waitForAbortable,
} from "../application/binary/AbortablePromise.js";
import { nativeLoadImageObservationSchema } from "../domain/native/nativeLoadImage.js";
import {
  GHIDRA_PROVIDER_IDENTITY,
  healthLimitations,
  windowsP0Limitations,
  limitationsFor,
} from "./GhidraProviderCapabilities.js";
import type { GhidraSessionError } from "./GhidraSessionError.js";
import type { GhidraSessionInfo } from "./GhidraSessionValues.js";
import { ghidraExtensionFailure } from "./extensions/GhidraExtensionFailures.js";
import {
  GHIDRA_SWITCH_COMPILER_SPEC_ID,
  GHIDRA_SWITCH_LANGUAGE_ID,
  ghidraLoaderExtensionSchema,
  isGhidraSwitchTarget,
} from "./extensions/GhidraLoaderExtensions.js";
import { GHIDRA_SWITCH_LOADER_NAME } from "../config/ghidraLoaderExtensions.js";
import {
  ghidraExtensionSchema,
  validateGhidraExtensionProfile,
  ghidraExtensionLimitations,
} from "./extensions/GhidraExtensions.js";
import {
  windowsNativeAuthorityUnavailableReason,
  hasWindowsNativeAuthority,
} from "../process/WindowsAuthority.js";
import { ghidraRawBinaryLanguage } from "./GhidraRawBinaryLanguage.js";

/** Production seam for exercising provider projection without a real process. */
export type GhidraProviderClientFactory = (
  options: GhidraClientOptions,
) => Pick<GhidraClient, "start" | "callTool" | "close"> &
  Partial<
    Pick<
      GhidraClient,
      "runtimeLineage" | "readTargetSnapshot" | "hashTargetSnapshot"
    >
  >;

type GhidraProviderClientInstance = ReturnType<GhidraProviderClientFactory>;

type NativeAotSnapshotOwner = {
  readonly derive: (
    imageBase: string,
    operation: AnalysisOperation,
    callerSignal: AbortSignal | undefined,
    observations: JsonValue,
  ) => Promise<Result<NativeAotPeResult, AnalysisError>>;
  readonly readTypeDetail: (
    address: string,
  ) => ReturnType<NativeAotPeResult["readTypeDetail"]>;
  readonly close: () => void;
};

/** Own one session's captured PE snapshot and immutable NativeAOT derivation. */
const createNativeAotSnapshotOwner = (input: {
  readonly client: GhidraProviderClientInstance;
  readonly target: BinaryTarget;
  readonly startupTimeoutMs: number;
}): NativeAotSnapshotOwner => {
  const { client, target, startupTimeoutMs } = input;
  const controller = new AbortController();
  let identity: string | undefined;
  let result: NativeAotPeResult | undefined;
  let pending:
    | {
        readonly identity: string;
        readonly promise: Promise<Result<NativeAotPeResult, AnalysisError>>;
      }
    | undefined;
  let closed = false;
  let identityConflict = false;
  let identityConflictObservation:
    | { readonly imageBase: string; readonly observations: JsonValue }
    | undefined;
  const identityError = (
    operation: AnalysisOperation,
    reason: string,
    observedBase: string,
    observations: JsonValue,
  ): AnalysisError =>
    new ProviderAdapterError("ghidra", operation, {
      diagnostics: {
        reason,
        artifact_sha256: target.sha256,
        bound_image_base:
          identity === undefined
            ? null
            : `0x${identity.slice(target.sha256.length + 1)}`,
        observed_image_base: observedBase,
        measured_observation: observations,
        conflicting_image_base: identityConflictObservation?.imageBase ?? null,
        conflicting_observation:
          identityConflictObservation?.observations ?? null,
      },
    });
  const identityConflictFailure = (
    operation: AnalysisOperation,
    observedBase: string,
    observations: JsonValue,
  ): Result<NativeAotPeResult, AnalysisError> => {
    return err(
      identityError(
        operation,
        "The Ghidra session reported conflicting loaded image bases; reopen the analysis session to establish a new identity.",
        observedBase,
        observations,
      ),
    );
  };
  const derive = async (
    imageBase: string,
    operation: AnalysisOperation,
    callerSignal: AbortSignal | undefined,
    observations: JsonValue,
  ): Promise<Result<NativeAotPeResult, AnalysisError>> => {
    if (callerSignal?.aborted || closed)
      return err(new AnalysisCancelledError(operation));
    if (identityConflict)
      return identityConflictFailure(operation, imageBase, observations);
    if (controller.signal.aborted)
      return err(new AnalysisCancelledError(operation));
    let normalizedBase: string;
    try {
      normalizedBase = BigInt(imageBase).toString(16);
    } catch (cause: unknown) {
      return err(
        new ProviderAdapterError("ghidra", operation, {
          diagnostics: {
            reason:
              "Ghidra returned an invalid loaded image base for NativeAOT identity binding.",
            artifact_sha256: target.sha256,
            observed_image_base: imageBase,
            measured_observation: observations,
          },
          cause,
        }),
      );
    }
    const key = `${target.sha256}:${normalizedBase}`;
    if (identity !== undefined && identity !== key) {
      identityConflict = true;
      identityConflictObservation = { imageBase, observations };
      result = undefined;
      controller.abort();
      return err(
        identityError(
          operation,
          "The Ghidra session reported a different loaded image base after NativeAOT metadata was bound to its captured snapshot; reopen the analysis session to establish a new identity.",
          imageBase,
          observations,
        ),
      );
    }
    identity ??= key;
    if (result !== undefined) {
      const settled = await waitForAbortable(
        Promise.resolve(ok(result)),
        callerSignal,
      );
      if (closed) return err(new AnalysisCancelledError(operation));
      if (identityConflict)
        return identityConflictFailure(operation, imageBase, observations);
      if (controller.signal.aborted)
        return err(new AnalysisCancelledError(operation));
      return settled === ABORTED
        ? err(new AnalysisCancelledError(operation))
        : settled;
    }
    if (pending !== undefined && pending.identity !== key)
      return err(
        identityError(
          operation,
          "A NativeAOT snapshot derivation is already bound to a different loaded image base.",
          imageBase,
          observations,
        ),
      );
    if (pending === undefined) {
      const promise: Promise<Result<NativeAotPeResult, AnalysisError>> =
        (async () => {
          try {
            if (client.readTargetSnapshot === undefined)
              return err(
                new ProviderAdapterError("ghidra", operation, {
                  diagnostics: {
                    reason:
                      "The Ghidra client does not expose its immutable target snapshot for NativeAOT metadata inspection.",
                  },
                }),
              );
            const snapshot = await client.readTargetSnapshot(
              NATIVE_AOT_MAX_SOURCE_BYTES,
              controller.signal,
            );
            if (!snapshot.ok)
              return err(
                projectSessionError(
                  operation,
                  snapshot.error,
                  startupTimeoutMs,
                ),
              );
            if (closed) return err(new AnalysisCancelledError(operation));
            if (identityConflict)
              return identityConflictFailure(
                operation,
                imageBase,
                observations,
              );
            if (controller.signal.aborted)
              return err(new AnalysisCancelledError(operation));
            const parsed =
              snapshot.value.kind === "over-capacity"
                ? {
                    summary: nativeAotSnapshotOverCapacity(
                      target.sha256,
                      snapshot.value.sourceBytesAtLeast,
                      NATIVE_AOT_MAX_REPORT_BYTES,
                    ),
                    readTypeDetail: () => undefined,
                  }
                : parseNativeAotPe(
                    snapshot.value.bytes,
                    target.sha256,
                    NATIVE_AOT_MAX_REPORT_BYTES,
                    imageBase,
                  );
            if (closed) return err(new AnalysisCancelledError(operation));
            if (identityConflict)
              return identityConflictFailure(
                operation,
                imageBase,
                observations,
              );
            if (controller.signal.aborted)
              return err(new AnalysisCancelledError(operation));
            return ok(parsed);
          } catch (cause: unknown) {
            return err(
              new ProviderAdapterError("ghidra", operation, {
                diagnostics: {
                  reason:
                    cause instanceof Error
                      ? cause.message
                      : "NativeAOT metadata could not be derived from the captured target snapshot.",
                },
                cause,
              }),
            );
          }
        })();
      const current = { identity: key, promise };
      pending = current;
      void promise.then((settled) => {
        if (pending !== current) return;
        pending = undefined;
        if (settled.ok && !closed && !identityConflict) result = settled.value;
      });
    }
    const settled = await waitForAbortable(pending.promise, callerSignal);
    if (closed) return err(new AnalysisCancelledError(operation));
    if (identityConflict)
      return identityConflictFailure(operation, imageBase, observations);
    if (controller.signal.aborted)
      return err(new AnalysisCancelledError(operation));
    return settled === ABORTED
      ? err(new AnalysisCancelledError(operation))
      : settled;
  };
  return {
    derive,
    readTypeDetail: (address) =>
      result?.readTypeDetail(address, NATIVE_AOT_MAX_REPORT_BYTES),
    close: () => {
      closed = true;
      controller.abort();
      result = undefined;
      pending = undefined;
    },
  };
};

/** Build one AnalysisClient for an admitted Ghidra target and profile. */
export const createGhidraProviderClient = (input: {
  readonly config: AppConfig;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly logger: Logger;
  readonly clientFactory: GhidraProviderClientFactory;
  readonly target: BinaryTarget;
  readonly profile?: AnalysisProfileCommitment;
  readonly context?: AnalysisClientContext;
  readonly installation: GhidraInstallationInspection;
}): AnalysisClient => {
  const { config, logger, clientFactory, target, context, installation } =
    input;
  const prerequisites = ghidraClientPrerequisites(
    target,
    input.profile,
    installation,
  );
  if (!prerequisites.ok) return unavailableClient(prerequisites.error);
  const committedProfile = prerequisites.value.profile;
  const psp = isGhidraPspTarget(target);
  const pspExtension = psp
    ? ghidraPspExtensionSchema.safeParse(
        committedProfile.parameters.psp_extension,
      )
    : null;
  if (
    pspExtension !== null &&
    (!pspExtension.success ||
      committedProfile.parameters.language_id !== "Allegrex:LE:32:default" ||
      committedProfile.parameters.loader !== "PspElfLoader")
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "Resolve the supported PSP profile and installed Allegrex extension before opening the session.",
        },
      }),
    );
  const extensionProfile = ghidraExtensionSchema
    .array()
    .safeParse(committedProfile.parameters.analysis_extensions ?? []);
  if (
    !extensionProfile.success ||
    (config.ghidraNativeAotJar !== undefined &&
      extensionProfile.data.length === 0)
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "Resolve the configured Ghidra extensions into an analysis profile before opening the session.",
        },
      }),
    );
  const extensions = extensionProfile.data;
  const switchTarget = isGhidraSwitchTarget(target);
  const loaderProfile = ghidraLoaderExtensionSchema
    .array()
    .safeParse(committedProfile.parameters.loader_extensions ?? []);
  const loaderSources = loaderProfile.success
    ? loaderProfile.data.map((extension) => ({
        extension,
        path: config.ghidraLoaderExtensions?.find(
          (configured) =>
            configured.id === extension.id &&
            configured.loader_name === extension.loader_name,
        )?.path,
      }))
    : [];
  if (
    !loaderProfile.success ||
    loaderSources.some(({ path }) => path === undefined) ||
    (switchTarget
      ? loaderSources.length !== 1 ||
        loaderSources[0]?.extension.loader_name !== GHIDRA_SWITCH_LOADER_NAME
      : loaderSources.length !== 0)
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "Resolve the pinned Ghidra loader into an analysis profile before opening the session.",
        },
      }),
    );
  const seedProfile = ghidraSeedCommitmentSchema
    .optional()
    .safeParse(committedProfile.parameters.analysis_seeds);
  if (
    !seedProfile.success ||
    (config.ghidraSeedFile === undefined) !== (seedProfile.data === undefined)
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "Resolve REA_GHIDRA_SEED_FILE into an analysis profile before opening the session.",
        },
      }),
    );
  const seeds = seedProfile.data;
  const languageOverride = ghidraProfileLanguageOverride(
    committedProfile.parameters,
  );
  if (
    !sameGhidraLanguageOverride(languageOverride, config.ghidraLanguageOverride)
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "The committed analysis profile and REA_GHIDRA_LANGUAGE_ID/REA_GHIDRA_COMPILER_SPEC_ID differ; reopen the target to resolve a new profile.",
        },
      }),
    );
  const disabledAnalyzers = ghidraProfileDisabledAnalyzers(
    committedProfile.parameters,
  );
  if (
    !sameGhidraDisabledAnalyzers(
      disabledAnalyzers,
      config.ghidraDisabledAnalyzers,
    )
  )
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: {
          reason:
            "The committed analysis profile and REA_GHIDRA_DISABLED_ANALYZERS differ; reopen the target to resolve a new profile.",
        },
      }),
    );
  const invalidProfile = validateGhidraExtensionProfile(
    extensions,
    config,
    target,
    installation.platform,
  );
  if (invalidProfile !== null)
    return unavailableClient(
      new ProviderAdapterError("ghidra", "open_binary", {
        diagnostics: { reason: invalidProfile },
      }),
    );
  let extensionFailure: AnalysisError | undefined;
  // Replaced by the reported outcome once the session handshake is checked.
  const seedLimitations: string[] = [...ghidraSeedLimitations(seeds)];
  const rawLanguage =
    target.format === "raw-binary"
      ? ghidraRawBinaryLanguage(target.architecture)
      : undefined;
  const targetLimitations = [
    ...(target.format === "raw-image"
      ? rawImageLimitations(target.rawImage)
      : []),
    ...(target.format === "dos-mz"
      ? [
          "DOS MZ uses 16-bit x86 real mode with the Ghidra load segment 0x1000. Returned addresses are linear byte coordinates; they do not identify a unique segment:offset alias.",
          "Static DOS analysis does not emulate BIOS, DOS interrupts, device ports, or self-modifying unpacking code. Packed targets require a separately identified unpacked artifact for original-program analysis; appended overlays are not the initialized load module.",
        ]
      : []),
    ...(switchTarget
      ? [
          "The Switch loader maps NSO/NRO segments at the fixed image base 0x7100000000 and does not apply dynamic relocations, resolve imports, or discover functions beyond the entry point.",
        ]
      : []),
    ...(target.format === "raw-binary"
      ? [
          "Headerless raw-binary analysis uses the caller-supplied architecture and entry address; file offset 0 is mapped at that address. Headers are not discovered from file bytes.",
          "Little-endian generic Ghidra languages are used for x86, x86_64, arm, and arm64. Big-endian, Thumb-only, Cortex-M, and other processor variants are unsupported in this increment.",
          "Static analysis does not emulate reset vectors, memory-mapped I/O, or firmware boot sequences.",
        ]
      : []),
    ...(target.kind === "executable" && target.architecture === "mips"
      ? (target.mips.limitations ?? [])
      : []),
  ];
  const providerLimitations =
    installation.platform === "win32"
      ? windowsP0Limitations
      : installation.platform === "darwin"
        ? [
            "macOS sessions require a matching executable Ghidra native decompiler; REA checks for it but does not build native components or change Gatekeeper quarantine state.",
          ]
        : [];
  const projectCache = ghidraProjectCachePolicy(
    config.ghidraProjectCacheDir,
    installation.platform,
    extensions.length,
  );
  const client = clientFactory({
    startupTimeoutMs: config.ghidraStartupTimeoutMs,
    platform: installation.platform,
    launcher: new GhidraHeadlessLauncher({
      environment: input.environment,
      analyzeHeadlessPath: prerequisites.value.analyzeHeadlessPath,
      javaHome: prerequisites.value.javaHome,
      bridgeScriptPath: fileURLToPath(
        new URL("../../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
      ...(pspExtension?.success === true
        ? { pspExtension: pspExtension.data }
        : {}),
      ...(target.format === "dos-mz" ? { dosMz: true } : {}),
      ...(target.format === "dos-com" ? { dosCom: true } : {}),
      ...(target.format === "raw-image"
        ? {
            rawImage: ghidraRawImageImport(target.rawImage),
          }
        : {}),
      ...(rawLanguage === undefined || target.format !== "raw-binary"
        ? {}
        : {
            rawBinary: {
              languageId: rawLanguage.languageId,
              compilerSpecId: rawLanguage.compilerSpecId,
              baseAddr: target.entryPoint,
            },
          }),
      ...(languageOverride === undefined ? {} : { languageOverride }),
      ...(config.ghidraDisabledAnalyzers === undefined
        ? {}
        : { disabledAnalyzers: config.ghidraDisabledAnalyzers }),
      ...(seeds === undefined ? {} : { analysisSeeds: seeds }),
      platform: installation.platform,
      ...(extensions.length === 0 ? {} : { analysisExtensions: extensions }),
      ...(switchTarget
        ? {
            loaderImport: {
              name: GHIDRA_SWITCH_LOADER_NAME,
              languageId: GHIDRA_SWITCH_LANGUAGE_ID,
              compilerSpecId: GHIDRA_SWITCH_COMPILER_SPEC_ID,
              extensions: loaderSources.flatMap(({ extension, path }) =>
                path === undefined ? [] : [{ extension, path }],
              ),
            },
          }
        : {}),
      ...(projectCache.root === undefined
        ? {}
        : { projectCache: { root: projectCache.root } }),
    }),
    targetPath:
      installation.platform === "win32"
        ? (target.sourcePath ?? target.path)
        : target.path,
    targetSha256: target.sha256,
    transport:
      installation.platform === "win32"
        ? "authenticated-loopback-tcp"
        : "unix-socket",
    providerVersion: prerequisites.value.providerVersion,
    profileDigest: committedProfile.digest,
    ...(switchTarget
      ? {
          expectedLanguageId: GHIDRA_SWITCH_LANGUAGE_ID,
          expectedCompilerSpecId: GHIDRA_SWITCH_COMPILER_SPEC_ID,
        }
      : ["dos-mz", "dos-com"].includes(target.format)
        ? {
            expectedLanguageId: "x86:LE:16:Real Mode",
            expectedCompilerSpecId: "default",
          }
        : target.format === "raw-image"
          ? {
              expectedLanguageId: target.rawImage.processor_language_id,
              expectedCompilerSpecId: target.rawImage.compiler_spec_id,
            }
          : rawLanguage === undefined
            ? languageOverride === undefined
              ? {}
              : {
                  expectedLanguageId: languageOverride.languageId,
                  ...(languageOverride.compilerSpecId === undefined
                    ? {}
                    : {
                        expectedCompilerSpecId: languageOverride.compilerSpecId,
                      }),
                }
            : {
                expectedLanguageId: rawLanguage.languageId,
                expectedCompilerSpecId: rawLanguage.compilerSpecId,
              }),
    ...(psp
      ? {
          expectedLanguageId: "Allegrex:LE:32:default",
          expectedCompilerSpecId: "default",
        }
      : {}),
    ...(context === undefined ? {} : { runId: context.runId }),
    ...(projectCache.root === undefined ? {} : { persistentProject: true }),
    logger: logger.child({ layer: "ghidra-bridge" }),
  });
  const checkExtensions = async (
    operation: AnalysisOperation,
    info: GhidraSessionInfo,
  ): Promise<AnalysisError | undefined> => {
    extensionFailure =
      ghidraExtensionFailure(
        extensions,
        info.analysis_extensions ?? [],
        operation,
      ) ?? ghidraSeedFailure(seeds, info.analysis_seeds, operation);
    if (extensionFailure === undefined && info.analysis_seeds !== undefined)
      seedLimitations.splice(
        0,
        seedLimitations.length,
        ...ghidraSeedLimitations(seeds, info.analysis_seeds),
      );
    if (extensionFailure === undefined) return undefined;
    const closed = await client.close();
    return closed.ok
      ? extensionFailure
      : analysisErrorWithCleanupFailure(
          extensionFailure,
          closed.error,
          operation,
        );
  };
  const releaseLimitation = unverifiedGhidraBuildLimitation(
    prerequisites.value.providerVersion,
  );
  const sessionLimitations = (): readonly string[] => [
    ...providerLimitations,
    ...targetLimitations,
    ...(psp ? GHIDRA_PSP_LIMITATIONS : []),
    ...ghidraExtensionLimitations(extensions),
    ...projectCache.limitations,
    ...seedLimitations,
    ...(releaseLimitation === undefined ? [] : [releaseLimitation]),
  ];
  const nativeAotOwner =
    target.format === "pe"
      ? createNativeAotSnapshotOwner({
          client,
          target,
          startupTimeoutMs: config.ghidraStartupTimeoutMs,
        })
      : undefined;
  return {
    execute: async (operation, parameters, options) => {
      if (extensionFailure !== undefined) return err(extensionFailure);
      if (
        operation !== "health" &&
        !isGhidraInventoryOperation(operation) &&
        !isGhidraFunctionOperation(operation)
      )
        return err(
          new AnalysisCapabilityUnavailableError(
            GHIDRA_PROVIDER_IDENTITY.id,
            operation,
            "The Ghidra adapter does not declare this operation.",
          ),
        );
      if (operation === "health") {
        const started = await client.start(options?.signal, options?.progress);
        if (!started.ok)
          return err(
            projectSessionError(
              operation,
              started.error,
              config.ghidraStartupTimeoutMs,
            ),
          );
        const failed = await checkExtensions(operation, started.value);
        if (failed !== undefined) return err(failed);
        return ok(
          createAnalysisExecution(started.value, committedProfile.provider, {
            analysisProfile: committedProfile,
            limitations: [...healthLimitations, ...sessionLimitations()],
          }),
        );
      }
      const input = isGhidraFunctionOperation(operation)
        ? parseGhidraFunctionInput(operation, parameters)
        : parseGhidraInventoryInput(operation, parameters);
      if (!input.ok) return input;
      if (extensions.length > 0 || seeds !== undefined) {
        const started = await client.start(options?.signal, options?.progress);
        if (!started.ok)
          return err(
            projectSessionError(
              operation,
              started.error,
              config.ghidraStartupTimeoutMs,
            ),
          );
        const failed = await checkExtensions(operation, started.value);
        if (failed !== undefined) return err(failed);
      }
      const called = await client.callTool(operation, input.value, {
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
        ...(options?.progress === undefined
          ? {}
          : { progress: options.progress }),
      });
      if (!called.ok)
        return err(
          projectSessionError(
            operation,
            called.error,
            config.ghidraStartupTimeoutMs,
          ),
        );
      let normalized: JsonValue;
      let observationLimitations: readonly string[] = [];
      if (isGhidraFunctionOperation(operation)) {
        const result = parseGhidraFunctionResult(operation, called.value);
        if (!result.ok) return result;
        normalized = result.value.value;
        observationLimitations = result.value.limitations;
      } else {
        const result = parseGhidraInventoryResult(operation, called.value);
        if (!result.ok) return result;
        normalized = result.value;
      }
      if (operation === "inspect_native_data_type") {
        const address = input.value.address;
        if (typeof address === "string") {
          if (target.format === "pe" && nativeAotOwner !== undefined) {
            const started = await client.start(
              options?.signal,
              options?.progress,
            );
            if (!started.ok)
              return err(
                projectSessionError(
                  operation,
                  started.error,
                  config.ghidraStartupTimeoutMs,
                ),
              );
            const derived = await nativeAotOwner.derive(
              started.value.target.image_base,
              operation,
              options?.signal,
              normalized,
            );
            if (!derived.ok) return derived;
          }
          let metadata:
            | ReturnType<NativeAotPeResult["readTypeDetail"]>
            | undefined;
          metadata = nativeAotOwner?.readTypeDetail(address);
          if (
            metadata !== undefined &&
            normalized !== null &&
            typeof normalized === "object" &&
            !Array.isArray(normalized)
          ) {
            const nativeResult = normalized as Record<string, JsonValue>;
            if (nativeResult.metadata_recovery === undefined)
              normalized = jsonValueSchema.parse({
                ...nativeResult,
                metadata_recovery: metadata,
              });
          }
        }
      }
      if (operation === "inspect_native_load_image") {
        let derived: NativeAotPeResult | undefined;
        if (target.format === "pe") {
          const observations =
            nativeLoadImageObservationSchema.parse(normalized);
          if (nativeAotOwner === undefined)
            return err(
              new ProviderAdapterError("ghidra", operation, {
                diagnostics: {
                  reason:
                    "The admitted PE session has no read-only NativeAOT snapshot owner.",
                },
              }),
            );
          const result = await nativeAotOwner.derive(
            observations.image_base,
            operation,
            options?.signal,
            normalized,
          );
          if (!result.ok) return result;
          derived = result.value;
        }
        const attested = await attestGhidraNativeLoadImage({
          target,
          operation,
          measured: normalized,
          client,
          mapSessionError: (failure) =>
            projectSessionError(
              operation,
              failure,
              config.ghidraStartupTimeoutMs,
            ),
          nativeAotResult: derived,
          signal: options?.signal,
        });
        if (!attested.ok) return attested;
        normalized = attested.value;
      }
      return ok(
        createAnalysisExecution(normalized, committedProfile.provider, {
          rawResult: called.value,
          analysisProfile: committedProfile,
          limitations: [
            ...limitationsFor(operation),
            ...observationLimitations,
            ...sessionLimitations(),
          ],
        }),
      );
    },
    runtimeLineageSnapshots: () => {
      const observation = client.runtimeLineage?.() ?? null;
      return observation === null
        ? []
        : [{ provider: committedProfile.provider, observation }];
    },
    close: async () => {
      nativeAotOwner?.close();
      return client.close();
    },
  };
};

interface GhidraClientCoordinates {
  readonly analyzeHeadlessPath: string;
  readonly javaHome: string;
  readonly providerVersion: string;
  readonly profile: AnalysisProfileCommitment;
}

const ghidraClientPrerequisites = (
  target: BinaryTarget,
  profile: AnalysisProfileCommitment | undefined,
  installation: GhidraInstallationInspection,
): Result<GhidraClientCoordinates, AnalysisError> => {
  if (target.kind !== "executable")
    return err(
      new AnalysisCapabilityUnavailableError(
        "ghidra",
        "health",
        `Ghidra cannot import ${target.kind} targets through this adapter.`,
      ),
    );
  if (installation.status === "unavailable")
    return err(
      new ProviderAdapterError("ghidra", "health", {
        diagnostics: ghidraInstallationDiagnostics(installation),
      }),
    );
  if (
    installation.platform === "win32" &&
    !hasWindowsNativeAuthority(installation.platform)
  )
    return err(
      new AnalysisCapabilityUnavailableError(
        "ghidra",
        "health",
        windowsNativeAuthorityUnavailableReason(installation.platform),
      ),
    );
  if (profile === undefined || profile.provider.id !== "ghidra")
    return err(new ProviderAdapterError("ghidra", "health"));
  return ok({
    analyzeHeadlessPath: installation.analyzeHeadlessPath,
    javaHome: installation.javaHome,
    providerVersion: installation.providerVersion,
    profile,
  });
};

const unavailableClient = (failure: AnalysisError): AnalysisClient => ({
  execute: () => Promise.resolve(err(failure)),
  close: () => Promise.resolve(ok(null)),
});

// Bridge rejections of one annotation field, reported against that input.
const ANNOTATION_FAILURE_FIELDS: Readonly<Record<string, string>> = {
  invalid_function_name: "name",
  invalid_function_signature: "signature",
  invalid_calling_convention: "calling_convention",
  invalid_variable_edit: "variables",
  invalid_label: "label",
  invalid_data_edit: "data_type",
  invalid_declarations: "declarations",
};

// Where a bridge annotation rejection belongs in the caller's input. A set
// rejection names its failing item in the message and applies to the whole
// request, whether it named a built-in pack or inline annotations.
const annotationFailurePath = (
  operation: AnalysisOperation,
  failure: GhidraSessionError,
): readonly string[] | undefined => {
  if (!isAnnotationOperation(operation) || failure.kind !== "remote")
    return undefined;
  if (failure.remoteCode === "invalid_annotation_set") return [];
  const field = ANNOTATION_FAILURE_FIELDS[failure.remoteCode ?? ""];
  return field === undefined ? undefined : [field];
};

const projectSessionError = (
  operation: AnalysisOperation,
  failure: GhidraSessionError,
  startupTimeoutMs: number,
): AnalysisError => {
  const primary = projectPrimarySessionError(
    operation,
    failure,
    startupTimeoutMs,
  );
  return failure.cleanupFailure === undefined
    ? primary
    : analysisErrorWithCleanupFailure(
        primary,
        failure.cleanupFailure,
        operation,
      );
};

const projectPrimarySessionError = (
  operation: AnalysisOperation,
  failure: GhidraSessionError,
  startupTimeoutMs: number,
): AnalysisError => {
  if (failure.cause instanceof AnalysisAccessDeniedError)
    return new AnalysisAccessDeniedError(
      operation,
      failure.cause.path,
      failure.cause.systemCode,
      { cause: failure },
    );
  if (failure.cause instanceof AnalysisArtifactChangedError)
    return new AnalysisArtifactChangedError(
      operation,
      failure.cause.path,
      failure.cause.reason,
      { cause: failure },
    );
  const annotationPath = annotationFailurePath(operation, failure);
  if (annotationPath !== undefined)
    return new AnalysisInputError(operation, { cause: failure }, [
      {
        path: [...annotationPath],
        reason: "invalid_value",
        message: failure.message,
      },
    ]);
  if (failure.cause instanceof GhidraProjectCacheBusyError)
    return new AnalysisResourceConstraintError(
      operation,
      "exclusive-lock",
      failure.message,
      { project_cache_entry: failure.cause.entryRoot },
      {
        cause: failure,
        remediationAction:
          "Close the other REA session analysing this target and analysis profile, then retry. To run sessions side by side, unset REA_GHIDRA_PROJECT_CACHE_DIR so each uses an ephemeral project.",
      },
    );
  if (failure.kind === "cancelled")
    return new AnalysisCancelledError(operation);
  if (failure.kind === "timeout" || failure.kind === "analysis_timeout")
    return new AnalysisTimeoutError(
      operation,
      failure.timeoutMs ?? startupTimeoutMs,
    );
  if (failure.kind === "remote" && failure.remoteCode === "decompile_cancelled")
    return new AnalysisCancelledError(operation);
  if (
    failure.kind === "remote" &&
    failure.remoteCode === "regex_stack_exhausted"
  )
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      failure.message,
      null,
      {
        cause: failure,
        remediationAction:
          "Retry this search in literal mode or simplify the regex. The active analysis session and annotations remain available.",
      },
    );
  if (
    failure.kind === "remote" &&
    ["invalid_request", "not_found", "ambiguous"].includes(
      failure.remoteCode ?? "",
    )
  )
    return new AnalysisInputError(operation, { cause: failure }, [
      { path: [], reason: "invalid_value", message: failure.message },
    ]);
  if (failure.kind === "remote" && failure.remoteCode === "method_unavailable")
    return new AnalysisCapabilityUnavailableError(
      "ghidra",
      operation,
      failure.message,
    );
  return new ProviderAdapterError("ghidra", operation, {
    cause: failure,
    diagnostics: failure.diagnostics,
  });
};

/** Launcher import for a raw image: one flat block, or a mapped block layout. */
const ghidraRawImageImport = (
  profile: RawImageProfile,
): GhidraRawImageImport =>
  profile.schema_version === "dcomp.ghidra-profile.v1"
    ? {
        mode: "flat",
        languageId: profile.processor_language_id,
        compilerSpecId: profile.compiler_spec_id,
        baseAddress: `0x${profile.load_address.toString(16)}`,
        entryAddress: `0x${profile.entry_address.toString(16)}`,
      }
    : {
        mode: "mapped",
        languageId: profile.processor_language_id,
        compilerSpecId: profile.compiler_spec_id,
        blocks: profile.blocks,
      };

/** The declaration is caller-supplied; say so, and say what is not modelled. */
const rawImageLimitations = (profile: RawImageProfile): string[] => {
  const declared = `Raw image interpreted with caller profile ${profile.profile_id}: ${profile.processor_language_id} (${profile.compiler_spec_id}).`;
  return profile.schema_version === "dcomp.ghidra-profile.v1"
    ? [
        `${declared} Loaded at 0x${profile.load_address.toString(16)} with entry 0x${profile.entry_address.toString(16)}. The language, base and entry are declarations, not observations from the bytes.`,
        "A v1 raw image is one flat block in the language's default address space; bank switching, mirrors, overlays and memory-mapped I/O are not modelled.",
      ]
    : [
        `${declared} ${profile.blocks.length} declared block(s) map file slices to CPU addresses; the map, permissions and entries are declarations, not observations from the bytes.`,
        "Overlay blocks are separate Ghidra address spaces named after the block, so a banked address reads <block>:0x<offset>; non-overlay blocks use the default space. References from banked code to shared addresses resolve in the default space; which bank a run-time bank switch selects is not modelled. Mirrors and memory-mapped I/O registers are not modelled unless declared as blocks.",
      ];
};

/** Admit the persistent project cache only where sessions may save edits. */
const ghidraProjectCachePolicy = (
  root: string | undefined,
  platform: NodeJS.Platform,
  extensionCount: number,
): { readonly root?: string; readonly limitations: readonly string[] } => {
  if (root === undefined) return { limitations: [] };
  if (platform === "win32")
    return {
      limitations: [
        "REA_GHIDRA_PROJECT_CACHE_DIR is ignored: Windows P0 sessions have no mutation authority and always use an ephemeral project.",
      ],
    };
  if (extensionCount > 0)
    return {
      limitations: [
        "REA_GHIDRA_PROJECT_CACHE_DIR is ignored while analysis extensions are configured: extensions rerun at every session start and are not proven idempotent over a saved project.",
      ],
    };
  return {
    root,
    limitations: [
      `Persistent project cache: the first open of a target and analysis profile imports and analyses it under ${root}; later sessions reopen that project without re-analysis, and each annotation is saved to it. One session holds an entry at a time; delete an entry directory to rebuild it.`,
    ],
  };
};
