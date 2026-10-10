import { isAnnotationOperation } from "../domain/native/nativeDataAnnotations.js";
import { fileURLToPath } from "node:url";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisClientContext,
  type AnalysisOperation,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import {
  AnalysisCancelledError,
  AnalysisArtifactChangedError,
  AnalysisAccessDeniedError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { type AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import type { Logger } from "../logger.js";
import { GhidraClient } from "./GhidraClient.js";
import type { GhidraClientOptions } from "./GhidraClientTypes.js";
import { GHIDRA_STARTUP_TIMEOUT_MS } from "./GhidraDefaults.js";
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
import { unverifiedGhidraBuildLimitation } from "./GhidraInstallationPolicy.js";
import {
  GhidraHeadlessLauncher,
  type GhidraRawImageImport,
} from "./GhidraLauncher.js";
import { GhidraProjectCacheBusyError } from "./GhidraProjectCache.js";
import type { RawImageProfile } from "../domain/rawImage.js";
import { attestGhidraNativeLoadImage } from "./GhidraLoadImageAttest.js";
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
  ghidraExtensionSchema,
  validateGhidraExtensionProfile,
  ghidraExtensionLimitations,
} from "./extensions/GhidraExtensions.js";
import {
  windowsNativeAuthorityUnavailableReason,
  hasWindowsNativeAuthority,
} from "../process/WindowsAuthority.js";

/** Production seam for exercising provider projection without a real process. */
export type GhidraProviderClientFactory = (
  options: GhidraClientOptions,
) => Pick<GhidraClient, "start" | "callTool" | "close"> &
  Partial<Pick<GhidraClient, "runtimeLineage" | "readTargetSnapshot">>;

/** Build one AnalysisClient for an admitted Ghidra target and profile. */
export const createGhidraProviderClient = (input: {
  readonly config: AppConfig;
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
  const targetLimitations =
    target.format === "raw-image"
      ? rawImageLimitations(target.rawImage)
      : target.format === "dos-mz"
        ? [
            "DOS MZ uses 16-bit x86 real mode with the Ghidra load segment 0x1000. Returned addresses are linear byte coordinates; they do not identify a unique segment:offset alias.",
            "Static DOS analysis does not emulate BIOS, DOS interrupts, device ports, or self-modifying unpacking code. Packed targets require a separately identified unpacked artifact for original-program analysis; appended overlays are not the initialized load module.",
          ]
        : [];
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
    platform: installation.platform,
    launcher: new GhidraHeadlessLauncher({
      analyzeHeadlessPath: prerequisites.value.analyzeHeadlessPath,
      javaHome: prerequisites.value.javaHome,
      bridgeScriptPath: fileURLToPath(
        new URL("../../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
      ),
      ...(target.format === "dos-mz" ? { dosMz: true } : {}),
      ...(target.format === "dos-com" ? { dosCom: true } : {}),
      ...(target.format === "raw-image"
        ? {
            rawImage: ghidraRawImageImport(target.rawImage),
          }
        : {}),
      platform: installation.platform,
      ...(extensions.length === 0 ? {} : { analysisExtensions: extensions }),
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
    ...(["dos-mz", "dos-com"].includes(target.format)
      ? {
          expectedLanguageId: "x86:LE:16:Real Mode",
          expectedCompilerSpecId: "default",
        }
      : target.format === "raw-image"
        ? {
            expectedLanguageId: target.rawImage.processor_language_id,
            expectedCompilerSpecId: target.rawImage.compiler_spec_id,
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
    extensionFailure = ghidraExtensionFailure(
      extensions,
      info.analysis_extensions ?? [],
      operation,
    );
    if (extensionFailure === undefined) return undefined;
    await client.close();
    return extensionFailure;
  };
  const releaseLimitation = unverifiedGhidraBuildLimitation(
    prerequisites.value.providerVersion,
  );
  const sessionLimitations = [
    ...providerLimitations,
    ...targetLimitations,
    ...ghidraExtensionLimitations(extensions),
    ...projectCache.limitations,
    ...(releaseLimitation === undefined ? [] : [releaseLimitation]),
  ];
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
        const started = await client.start(options?.signal);
        if (!started.ok)
          return err(projectSessionError(operation, started.error));
        const failed = await checkExtensions(operation, started.value);
        if (failed !== undefined) return err(failed);
        return ok(
          createAnalysisExecution(started.value, committedProfile.provider, {
            analysisProfile: committedProfile,
            limitations: [...healthLimitations, ...sessionLimitations],
          }),
        );
      }
      const input = isGhidraFunctionOperation(operation)
        ? parseGhidraFunctionInput(operation, parameters)
        : parseGhidraInventoryInput(operation, parameters);
      if (!input.ok) return input;
      if (extensions.length > 0) {
        const started = await client.start(options?.signal);
        if (!started.ok)
          return err(projectSessionError(operation, started.error));
        const failed = await checkExtensions(operation, started.value);
        if (failed !== undefined) return err(failed);
      }
      const called = await client.callTool(
        operation,
        input.value,
        options?.signal === undefined ? {} : { signal: options.signal },
      );
      if (!called.ok) return err(projectSessionError(operation, called.error));
      const result = isGhidraFunctionOperation(operation)
        ? parseGhidraFunctionResult(operation, called.value)
        : parseGhidraInventoryResult(operation, called.value);
      if (!result.ok) return result;
      let normalized = result.value;
      if (operation === "inspect_native_load_image") {
        const attested = await attestGhidraNativeLoadImage(
          target,
          operation,
          result.value,
          client,
          (failure) => projectSessionError(operation, failure),
        );
        if (!attested.ok) return attested;
        normalized = attested.value;
      }
      return ok(
        createAnalysisExecution(normalized, committedProfile.provider, {
          rawResult: called.value,
          analysisProfile: committedProfile,
          limitations: [...limitationsFor(operation), ...sessionLimitations],
        }),
      );
    },
    runtimeLineageSnapshots: () => {
      const observation = client.runtimeLineage?.() ?? null;
      return observation === null
        ? []
        : [{ provider: committedProfile.provider, observation }];
    },
    close: () => client.close(),
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
  close: () => Promise.resolve(),
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
      failure.timeoutMs ?? GHIDRA_STARTUP_TIMEOUT_MS,
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
