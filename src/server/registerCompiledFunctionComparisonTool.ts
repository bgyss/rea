import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";

import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import { COMPILED_FUNCTION_COMPARISON_PROVIDER } from "../application/InvestigationProviders.js";
import { toolContract } from "../contracts/toolContracts.js";
import { compareCompiledFunctions } from "../domain/compiledFunctionComparison.js";
import {
  createEvidence,
  parseEvidence,
  type Evidence,
} from "../domain/evidence.js";
import { EvidenceIntegrityError } from "../domain/evidenceErrors.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err } from "../domain/result.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";
import { withAdmittedAnalysis } from "./analysisAdmission.js";
import { recordDerivedEvidence } from "./recordDerivedEvidence.js";
import { runDerivedOperation } from "./runDerivedOperation.js";
import { recordSessionEvidenceSources } from "./sessionEvidence.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register the instruction-aligned original-versus-rebuilt function comparison. */
export const registerCompiledFunctionComparisonTool = (
  server: EvidenceMcpServer,
  session: BinarySessionPort,
  contract: ReturnType<typeof toolContract<"compare_compiled_function">>,
): void => {
  const admission = withAdmittedAnalysis({ kind: "session", session });
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) =>
      runAdmittedToolOperation(
        server,
        admission,
        contract.name,
        context.mcpReq.signal,
        async () => {
          let leftEvidence: Evidence;
          let rightEvidence: Evidence;
          try {
            leftEvidence = parseEvidence(input.left);
            rightEvidence = parseEvidence(input.right);
          } catch (cause: unknown) {
            return server.delivery.toCallToolResult(
              err(
                new EvidenceIntegrityError(
                  cause instanceof Error ? cause.message : "Invalid Evidence",
                ),
              ),
              contract,
            );
          }
          const computed = await runDerivedOperation(
            context,
            contract.name,
            () =>
              compareCompiledFunctions(
                leftEvidence,
                rightEvidence,
                input.masking,
              ),
          );
          if (!computed.ok)
            return server.delivery.toCallToolResult(computed, contract);
          const comparison = computed.value;
          const recordedSources = recordSessionEvidenceSources(
            (evidence) => session.recordEvidence(evidence),
            [leftEvidence, rightEvidence],
          );
          if (!recordedSources.ok)
            return server.delivery.toCallToolResult(recordedSources, contract);
          const evidence = createEvidence(
            undefined,
            COMPILED_FUNCTION_COMPARISON_PROVIDER,
            {
              predicateType: "rea.compiled-function-comparison",
              operation: contract.name,
              parameters: {
                left_evidence_id: leftEvidence.evidence_id,
                right_evidence_id: rightEvidence.evidence_id,
                masking: comparison.masking,
              },
              result: jsonValueSchema.parse(comparison),
              confidence: "derived",
              authority: "analyst-inference",
              limitations: comparison.limitations,
              evidenceLinks: [
                leftEvidence.evidence_id,
                rightEvidence.evidence_id,
              ],
            },
          );
          return server.delivery.toEvidenceToolResult(
            evidence,
            contract,
            recordDerivedEvidence(session, evidence, undefined),
          );
        },
      ),
  );
};
