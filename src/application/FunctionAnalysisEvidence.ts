import type {
  AnalysisOperationPort,
  ExecutionOptions,
} from "./AnalysisProvider.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import { createEvidence } from "../domain/evidence.js";
import {
  canonicalFunctionDossierFacets,
  functionDossierSchema,
  parseFunctionDossier,
  projectFunctionDossier,
} from "../domain/hopperValues.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";

/** Raw provider output is not projected generically; its absence must be explained. */
const FACET_PROJECTION_LIMITATION =
  "Facet projection: only the selected dossier sections are returned and raw_result is omitted. The selection was made after the provider's complete dossier validated; re-run analyze_function without facets for the complete dossier and raw provider result.";

/** Preserve the provider's observations when presenting a validated function dossier. */
export const executeFunctionAnalysisEvidence = async (
  analysis: AnalysisOperationPort,
  parameters: Readonly<Record<string, JsonValue>>,
  target: BinaryTarget | undefined,
  options?: ExecutionOptions,
) => {
  const input =
    toolContract("analyze_function").inputSchema.safeParse(parameters);
  if (!input.success)
    return err(
      analysisInputErrorFromIssues(
        "analyze_function",
        input.error.issues,
        parameters,
        { cause: input.error },
      ),
    );
  const { facets, ...providerInput } = input.data;
  const selected =
    facets === undefined ? undefined : canonicalFunctionDossierFacets(facets);
  const execution = await analysis.execute(
    "analyze_function",
    jsonObjectSchema.parse(providerInput),
    options,
  );
  if (!execution.ok) return execution;
  const dossier = parseFunctionDossier(execution.value.result);
  if (!dossier.ok) return dossier;
  const observation = execution.value;
  const projected =
    selected === undefined
      ? undefined
      : projectFunctionDossier(
          functionDossierSchema.parse(dossier.value),
          selected,
        );
  return ok(
    createEvidence(observation.subject ?? target, observation.provider, {
      operation: "analyze_function",
      parameters: jsonObjectSchema.parse(
        selected === undefined
          ? providerInput
          : { ...providerInput, facets: selected },
      ),
      result:
        projected === undefined
          ? dossier.value
          : jsonValueSchema.parse(projected),
      ...(projected === undefined ? { rawResult: observation.rawResult } : {}),
      limitations:
        projected === undefined
          ? observation.limitations
          : [...observation.limitations, FACET_PROJECTION_LIMITATION],
      locations: observation.locations,
      ...(observation.analysisProfile === undefined
        ? {}
        : { analysisProfile: observation.analysisProfile }),
    }),
  );
};
