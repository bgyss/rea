import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { COMPILED_FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/compiledFunctionComparisonExample.js";
import { FUNCTION_COMPARISON_EXAMPLE } from "../../../src/contracts/functionComparisonExample.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { jsonObjectSchema } from "../../../src/domain/jsonValue.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const connect = async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Compiled function comparison must not launch a provider");
  });
  const server = createServer(session, session);
  const client = new Client({ name: "compiled-comparison-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
};

describe("compare_compiled_function MCP integration", () => {
  it("compares an original and a rebuilt listing and records Evidence", async () => {
    const { client, server } = await connect();
    try {
      const { left, right } = COMPILED_FUNCTION_COMPARISON_EXAMPLE;
      const compared = await client.callTool({
        name: "compare_compiled_function",
        arguments: { left, right },
      });
      expect(compared.isError).not.toBe(true);
      const evidence = parseEvidence(
        jsonObjectSchema.parse(compared.structuredContent).evidence,
      );
      expect(evidence.operation).toBe("compare_compiled_function");
      expect(evidence.predicate_type).toBe("rea.compiled-function-comparison");
      expect(evidence.parameters).toEqual({
        left_evidence_id: left.evidence_id,
        right_evidence_id: right.evidence_id,
        masking: { immediates: "exact" },
      });
      expect(evidence.evidence_links).toEqual([
        left.evidence_id,
        right.evidence_id,
      ]);
      expect(evidence.normalized_result).toMatchObject({
        verdict: "identical",
        score: 1,
        first_divergence: null,
        counts: { matched: 2, masked: 0, replaced: 0 },
      });
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("names the Evidence that is not an instruction listing", async () => {
    const { client, server } = await connect();
    try {
      const rejected = await client.callTool({
        name: "compare_compiled_function",
        arguments: {
          left: FUNCTION_COMPARISON_EXAMPLE.left,
          right: COMPILED_FUNCTION_COMPARISON_EXAMPLE.right,
        },
      });
      expect(rejected.isError).toBe(true);
      expect(JSON.stringify(rejected.structuredContent)).toContain(
        "inspect_native_function_instructions",
      );
    } finally {
      await client.close();
      await server.close();
    }
  });
});
