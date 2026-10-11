import { createEvidence } from "../domain/evidence.js";
import { jsonValueSchema } from "../domain/jsonValue.js";

const instruction = (
  address: string,
  offset: number,
  bytes: string,
  mnemonic: string,
  operand: string | null,
) => ({
  address,
  offset,
  bytes,
  length: bytes.length / 2,
  mnemonic,
  raw_disassembly: operand === null ? mnemonic : `${mnemonic} ${operand}`,
  operands:
    operand === null
      ? []
      : [
          {
            index: 0,
            raw: operand,
            provider_type: 0,
            memory_addressing: "unavailable",
            components: [
              {
                kind: "register",
                text: operand,
                value: operand,
                bit_width: 32,
              },
            ],
          },
        ],
  flow: {
    kind: "fallthrough",
    conditional: false,
    computed: false,
    direct_destinations: [],
  },
  references: [],
  relocations: [],
});

const listing = (entry: string, address: string, mnemonic: string) =>
  jsonValueSchema.parse({
    procedure: { address: entry, name: "main" },
    architecture: "x86:LE:64:default",
    mode: "default",
    instructions: [
      instruction(entry, 0, "50", "push", "RAX"),
      instruction(address, 1, "c3", mnemonic, null),
    ],
    limitations: [],
  });

const observe = (digit: string, entry: string, address: string) =>
  createEvidence(
    {
      path: `/tmp/function-${digit}`,
      sha256: digit.repeat(64),
      format: "elf",
    },
    { id: "ghidra", name: "Ghidra", version: "12.1.4" },
    {
      operation: "inspect_native_function_instructions",
      parameters: { procedure: "main" },
      result: listing(entry, address, "ret"),
      confidence: "observed",
      authority: "shipped-artifact",
    },
  );

/** Canonical original and candidate listings used in public contract examples. */
export const COMPILED_FUNCTION_COMPARISON_EXAMPLE = {
  left: observe("0", "0x401000", "0x401001"),
  right: observe("1", "0x0", "0x1"),
} as const;
