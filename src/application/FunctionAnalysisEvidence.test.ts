import { describe, expect, it } from "vitest";

import {
  createAnalysisExecution,
  type AnalysisOperationPort,
} from "./AnalysisProvider.js";
import { executeFunctionAnalysisEvidence } from "./FunctionAnalysisEvidence.js";
import { ghidraFunctionDossier } from "../domain/ghidraValues.fixture.js";
import { parseFunctionEvidence } from "../domain/functionDossierEvidence.js";
import {
  FUNCTION_DOSSIER_FACETS,
  functionDossierSchema,
  parseCompleteFunctionDossierEvidence,
} from "../domain/hopperValues.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import { ok } from "../domain/result.js";

const provider = { id: "fixture", name: "Fixture", version: "1" };
const target: BinaryTarget = {
  path: "/tmp/fixture",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
};
const providerDossier = functionDossierSchema.parse(ghidraFunctionDossier());

/** Provider seam that records every request and returns one complete dossier. */
const recordingProvider = () => {
  const requests: Readonly<Record<string, unknown>>[] = [];
  const analysis: AnalysisOperationPort = {
    execute: (_operation, parameters) => {
      requests.push(parameters);
      return Promise.resolve(
        ok(
          createAnalysisExecution(ghidraFunctionDossier(), provider, {
            limitations: ["provider limitation"],
          }),
        ),
      );
    },
  };
  return { analysis, requests };
};

describe("analyze_function facet projection", () => {
  it("keeps the complete dossier and raw result when no facets are selected", async () => {
    const { analysis, requests } = recordingProvider();
    const result = await executeFunctionAnalysisEvidence(
      analysis,
      { procedure: "fixture_main" },
      target,
    );
    if (!result.ok) throw result.error;
    expect(requests).toEqual([{ procedure: "fixture_main" }]);
    expect(result.value.parameters).toEqual({ procedure: "fixture_main" });
    expect(result.value.raw_result).toEqual(ghidraFunctionDossier());
    expect(result.value.normalized_result).toEqual(providerDossier);
    expect(result.value.limitations).toEqual(["provider limitation"]);
    expect(() =>
      parseCompleteFunctionDossierEvidence(
        result.value.normalized_result,
        "Test",
        "analyze_function",
      ),
    ).not.toThrow();
  });

  it("returns only selected sections, names omitted and unavailable ones, and explains the missing raw result", async () => {
    const { analysis, requests } = recordingProvider();
    const result = await executeFunctionAnalysisEvidence(
      analysis,
      {
        procedure: "fixture_main",
        facets: ["assembly", "unresolved_calls", "pseudocode"],
      },
      target,
    );
    if (!result.ok) throw result.error;
    // The provider contract is unchanged: it never sees the projection request.
    expect(requests).toEqual([{ procedure: "fixture_main" }]);
    expect(result.value.parameters).toEqual({
      procedure: "fixture_main",
      facets: ["pseudocode", "assembly", "unresolved_calls"],
    });
    const projected = result.value.normalized_result;
    expect(projected).toEqual({
      procedure: expect.objectContaining({ name: "fixture_main" }),
      pseudocode: "int fixture_main(void) { return 42; }",
      assembly: ["0x401000: CALL 0x401020", "0x401005: RET"],
      limitations: providerDossier.limitations,
      facets: {
        selected: ["pseudocode", "assembly", "unresolved_calls"],
        omitted: FUNCTION_DOSSIER_FACETS.filter(
          (facet) =>
            !["pseudocode", "assembly", "unresolved_calls"].includes(facet),
        ),
        unavailable: ["unresolved_calls"],
      },
    });
    expect(result.value.raw_result).toBeNull();
    expect(result.value.limitations).toEqual([
      "provider limitation",
      expect.stringContaining("Facet projection"),
    ]);
  });

  it("gives equal selections in any order the same Evidence identity", async () => {
    const first = await executeFunctionAnalysisEvidence(
      recordingProvider().analysis,
      { procedure: "fixture_main", facets: ["callees", "pseudocode"] },
      target,
    );
    const second = await executeFunctionAnalysisEvidence(
      recordingProvider().analysis,
      { procedure: "fixture_main", facets: ["pseudocode", "callees"] },
      target,
    );
    if (!first.ok || !second.ok) throw new Error("expected Evidence");
    expect(first.value.evidence_id).toBe(second.value.evidence_id);
  });

  it("rejects unknown and empty selections before calling the provider", async () => {
    for (const facets of [["stack_frame"], []]) {
      const { analysis, requests } = recordingProvider();
      const result = await executeFunctionAnalysisEvidence(
        analysis,
        { procedure: "fixture_main", facets },
        target,
      );
      expect(result.ok).toBe(false);
      expect(requests).toEqual([]);
    }
  });

  it("refuses projected Evidence where a complete dossier is required", async () => {
    const result = await executeFunctionAnalysisEvidence(
      recordingProvider().analysis,
      { procedure: "fixture_main", facets: ["pseudocode"] },
      target,
    );
    if (!result.ok) throw result.error;
    let thrown: unknown;
    try {
      parseFunctionEvidence(result.value);
    } catch (cause: unknown) {
      thrown = cause;
    }
    if (!(thrown instanceof AnalysisInputError))
      throw new Error("expected a typed input error");
    expect(thrown.operation).toBe("compare_functions");
    expect(thrown.issues).toEqual([
      {
        path: [],
        reason: "invalid_value",
        message: expect.stringMatching(
          /requires a complete function dossier.*Re-run analyze_function without facets/u,
        ),
      },
    ]);
  });
});
