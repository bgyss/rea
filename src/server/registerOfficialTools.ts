import {
  isAnnotationOperation,
  type AnnotationOperation,
} from "../domain/native/nativeDataAnnotations.js";
import {
  AnnotationLedgerBinding,
  appendAnnotationFromEvidence,
} from "../application/AnnotationLedger.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { ServerContext } from "@modelcontextprotocol/server";

import type {
  AnalysisExecution,
  AnalysisOperationPort,
} from "../application/AnalysisProvider.js";
import type { ProgressReporter } from "../application/ProgressReporter.js";
import { OFFICIAL_TOOL_CONTRACTS } from "../contracts/officialToolContracts.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { jsonObjectSchema, type JsonValue } from "../domain/jsonValue.js";
import { ok, type Result } from "../domain/result.js";
import type { Logger } from "pino";
import { mcpProgressReporter } from "./mcpProgress.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Optional session services used by direct tool registration. */
export interface OfficialToolRegistration {
  readonly logger: Logger;
  readonly activeTarget: (() => BinaryTarget | undefined) | undefined;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
  readonly withAdmittedAnalysis: WithAdmittedAnalysis;
  /** Ledger bound by open_binary; annotation tools append to it. */
  readonly annotationLedger?: AnnotationLedgerBinding;
}

/** Register direct bridge proxies, preserving MCP cancellation and typed errors. */
export const registerOfficialTools = (
  server: EvidenceMcpServer,
  options: OfficialToolRegistration,
): void => {
  for (const contract of OFFICIAL_TOOL_CONTRACTS) {
    registerOfficialTool(server, contract, {
      logger: options.logger,
      activeTarget: options.activeTarget,
      recordEvidence: options.recordEvidence,
      withAdmittedAnalysis: options.withAdmittedAnalysis,
      ...(options.annotationLedger === undefined
        ? {}
        : { annotationLedger: options.annotationLedger }),
    });
  }
};

const registerOfficialTool = (
  server: EvidenceMcpServer,
  contract: (typeof OFFICIAL_TOOL_CONTRACTS)[number],
  registration: {
    readonly logger: Logger;
    readonly activeTarget: (() => BinaryTarget | undefined) | undefined;
    readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
    readonly withAdmittedAnalysis: WithAdmittedAnalysis;
    readonly annotationLedger?: AnnotationLedgerBinding;
  },
): void => {
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input: unknown, context: ServerContext) => {
      const admitted = await registration.withAdmittedAnalysis(
        contract.name,
        context.mcpReq.signal,
        async (admittedAnalysis) => {
          const arguments_ = jsonObjectSchema.parse(
            contract.inputSchema.parse(input),
          );
          const progress = mcpProgressReporter(context);
          const result = await runOfficialOperation(
            admittedAnalysis,
            contract,
            arguments_,
            {
              logger: registration.logger,
              signal: context.mcpReq.signal,
              progress,
            },
          );
          if (!result.ok) {
            return server.delivery.toCallToolResult(result, contract);
          }
          const evidence = createEvidence(
            result.value.subject ?? registration.activeTarget?.(),
            result.value.provider,
            {
              operation: contract.name,
              parameters: arguments_,
              result: result.value.result,
              ...(result.value.analysisProfile === undefined
                ? {}
                : { analysisProfile: result.value.analysisProfile }),
              rawResult: result.value.rawResult,
              limitations: result.value.limitations,
              locations: result.value.locations,
            },
          );
          const recorded = registration.recordEvidence?.(evidence);
          if (
            (recorded === undefined || recorded.ok) &&
            isAnnotationOperation(contract.name)
          ) {
            const appended = await recordAnnotation(
              registration.annotationLedger,
              registration.activeTarget?.(),
              contract.name,
              arguments_,
              evidence,
            );
            if (!appended.ok)
              return server.delivery.toCallToolResult(appended, contract);
          }
          return server.delivery.toEvidenceToolResult(
            evidence,
            contract,
            recorded,
          );
        },
      );
      return admitted.ok
        ? admitted.value
        : server.delivery.toCallToolResult(admitted, contract);
    },
  );
};

const runOfficialOperation = async (
  analysis: AnalysisOperationPort,
  contract: (typeof OFFICIAL_TOOL_CONTRACTS)[number],
  arguments_: Readonly<Record<string, JsonValue>>,
  execution: {
    readonly logger: Logger;
    readonly signal: AbortSignal;
    readonly progress: ProgressReporter;
  },
): Promise<Result<AnalysisExecution, AnalysisError>> => {
  await execution.progress.report({
    phase: contract.name,
    completed: 0,
    total: 1,
    message: "started",
  });
  const result = await logToolExecution(execution.logger, contract.name, () =>
    analysis.execute(contract.name, arguments_, {
      signal: execution.signal,
      progress: execution.progress,
    }),
  );
  await execution.progress.report({
    phase: contract.name,
    completed: 1,
    total: 1,
    message: result.ok ? "completed" : "failed",
    terminal: true,
  });
  return result;
};

/** Append to the ledger bound for the active target, if any. */
const recordAnnotation = (
  ledger: AnnotationLedgerBinding | undefined,
  target: BinaryTarget | undefined,
  operation: AnnotationOperation,
  arguments_: Readonly<Record<string, JsonValue>>,
  evidence: Evidence,
): Promise<Result<null, AnalysisError>> => {
  const bound = ledger?.current();
  return bound === undefined || target?.sha256 !== bound.targetSha256
    ? Promise.resolve(ok(null))
    : appendAnnotationFromEvidence(bound, operation, arguments_, evidence);
};
