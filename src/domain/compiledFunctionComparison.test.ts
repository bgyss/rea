import { describe, expect, it } from "vitest";
import { compareCompiledFunctions } from "./compiledFunctionComparison.js";
import { createEvidence } from "./evidence.js";
import type { NativeFunctionInstructions } from "./native/nativeFunctionInstructions.js";

type Part = {
  readonly kind: "register" | "immediate" | "address";
  readonly text: string;
  readonly value?: string;
};
type Spec = {
  readonly mnemonic: string;
  readonly operands: readonly (readonly Part[])[];
  readonly bytes: string;
  readonly relocation?: string;
  readonly reference?: { readonly target: string; readonly operand: number };
};

const listing = (
  entry: number,
  specs: readonly Spec[],
  architecture = "MIPS:BE:32:default",
): NativeFunctionInstructions => {
  let offset = 0;
  const instructions = specs.map((spec) => {
    const address = `0x${(entry + offset).toString(16)}`;
    const length = spec.bytes.length / 2;
    const raw = spec.operands
      .map((operand) => operand.map(({ text }) => text).join(""))
      .join(",");
    const instruction = {
      address,
      offset,
      bytes: spec.bytes,
      length,
      mnemonic: spec.mnemonic,
      raw_disassembly: `${spec.mnemonic} ${raw}`.trim(),
      operands: spec.operands.map((components, index) => ({
        index,
        raw: components.map(({ text }) => text).join(""),
        provider_type: 0,
        memory_addressing: "unavailable" as const,
        components: components.map((part) => ({
          kind: part.kind,
          text: part.text,
          value: part.value ?? null,
          bit_width: null,
        })),
      })),
      flow: {
        kind: "fallthrough" as const,
        conditional: false,
        computed: false,
        direct_destinations: [],
      },
      references:
        spec.reference === undefined
          ? []
          : [
              {
                target_address: spec.reference.target,
                type: "UNCONDITIONAL_CALL",
                call: true,
                jump: false,
                indirect: false,
                computed: false,
                operand_index: spec.reference.operand,
              },
            ],
      relocations:
        spec.relocation === undefined
          ? []
          : [
              {
                byte_offset: 0,
                type: 4,
                status: "APPLIED",
                symbol: spec.relocation,
                original_bytes_hex: null,
              },
            ],
    };
    offset += length;
    return instruction;
  });
  return {
    procedure: { address: `0x${entry.toString(16)}`, name: "func" },
    architecture,
    mode: "default",
    instructions,
    limitations: [],
  };
};

const evidence = (digit: string, result: NativeFunctionInstructions) =>
  createEvidence(
    { path: `/tmp/${digit}`, sha256: digit.repeat(64), format: "elf" },
    { id: "ghidra", name: "Ghidra", version: "12" },
    {
      operation: "inspect_native_function_instructions",
      parameters: { procedure: "func" },
      result,
      confidence: "observed",
      authority: "shipped-artifact",
    },
  );

const reg = (text: string): Part => ({ kind: "register", text });
const imm = (value: number): Part => ({
  kind: "immediate",
  text: `0x${value.toString(16)}`,
  value: `0x${value.toString(16)}`,
});
const addr = (value: number): Part => ({
  kind: "address",
  text: `0x${value.toString(16)}`,
  value: `0x${value.toString(16)}`,
});

const body = (
  constant: number,
  callee: number,
  extra: readonly Spec[] = [],
): readonly Spec[] => [
  {
    mnemonic: "addiu",
    operands: [[reg("sp")], [reg("sp")], [imm(0xffe8)]],
    bytes: "27bdffe8",
  },
  {
    mnemonic: "li",
    operands: [[reg("a0")], [imm(constant)]],
    bytes: `2404${constant.toString(16).padStart(4, "0")}`,
  },
  {
    mnemonic: "jal",
    operands: [[addr(callee)]],
    bytes: "0c000000",
    reference: { target: `0x${callee.toString(16)}`, operand: 0 },
  },
  ...extra,
  { mnemonic: "jr", operands: [[reg("ra")]], bytes: "03e00008" },
];

const compare = (
  left: readonly Spec[],
  right: readonly Spec[],
  masking: unknown = {},
) =>
  compareCompiledFunctions(
    evidence("a", listing(0x80010000, left)),
    evidence("b", listing(0x100, right)),
    masking,
  );

describe("compareCompiledFunctions masking", () => {
  it("reports identical code, ignoring where each function is placed", () => {
    const result = compare(body(5, 0x80020000), body(5, 0x80020000));
    expect(result).toMatchObject({
      verdict: "identical",
      score: 1,
      first_divergence: null,
    });
  });

  it("masks a relocated call target and keeps the symbol", () => {
    const relocated: Spec = {
      mnemonic: "jal",
      operands: [[addr(0)]],
      bytes: "0c000000",
      relocation: "helper",
      reference: { target: "0x0", operand: 0 },
    };
    const right = body(5, 0).map((spec) =>
      spec.mnemonic === "jal" ? relocated : spec,
    );
    const result = compare(body(5, 0x80020000), right);
    expect(result.verdict).toBe("equivalent_masked");
    expect(result.counts).toMatchObject({ matched: 3, masked: 1, replaced: 0 });
    expect(result.right_relocations).toEqual([
      expect.objectContaining({ right_index: 2, symbol: "helper" }),
    ]);
    expect(result.rows[2]).toMatchObject({
      kind: "masked",
      masked: [{ operand_index: 0, reason: "relocation" }],
    });
  });

  it("masks every constant of an unattributed relocation", () => {
    const left: Spec = {
      mnemonic: "lui",
      operands: [[reg("v0")], [imm(0x8002)]],
      bytes: "3c028002",
    };
    const right: Spec = {
      ...left,
      operands: [[reg("v0")], [imm(0)]],
      bytes: "3c020000",
      relocation: "table",
    };
    const result = compare([left], [right]);
    expect(result.rows[0]).toMatchObject({
      kind: "masked",
      masked: [{ operand_index: 1, reason: "relocation_unattributed" }],
    });
  });

  it("pairs a relocated displacement with its linked form", () => {
    // ldr w8,[x8] in the linked binary; ldr w8,[x8,#0x4c] once the object's
    // relocation is applied. The operand shapes differ, the pair is still aligned.
    const linked: Spec = {
      mnemonic: "ldr",
      operands: [[reg("w8")], [reg("x8")]],
      bytes: "080140b9",
    };
    const object: Spec = {
      mnemonic: "ldr",
      operands: [[reg("w8")], [reg("x8"), imm(0x4c)]],
      bytes: "084d40b9",
      relocation: "counter",
    };
    const result = compare([linked], [object]);
    expect(result.counts).toMatchObject({
      masked: 1,
      left_only: 0,
      right_only: 0,
    });
    expect(result.rows[0]).toMatchObject({
      kind: "masked",
      masked: [{ operand_index: 1, reason: "relocation_unattributed" }],
    });
  });

  it("does not mask a constant on an unrelocated instruction", () => {
    const linked: Spec = {
      mnemonic: "ldr",
      operands: [[reg("w8")], [reg("x8")]],
      bytes: "080140b9",
    };
    const result = compare(
      [linked],
      [
        {
          ...linked,
          operands: [[reg("w8")], [reg("x8"), imm(4)]],
          bytes: "08",
        },
      ],
    );
    expect(result.verdict).toBe("different");
  });
});

describe("compareCompiledFunctions differences", () => {
  it("names the first differing operand", () => {
    const result = compare(body(5, 0x80020000), body(6, 0x80020000));
    expect(result.verdict).toBe("different");
    expect(result.first_divergence).toMatchObject({
      kind: "replace",
      differences: [
        { kind: "operand", operand_index: 1, left: "0x5", right: "0x6" },
      ],
    });
    expect(result.score).toBeCloseTo(0.75);
  });

  it("can mask immediates by policy", () => {
    const result = compare(body(5, 0x80020000), body(6, 0x80020000), {
      immediates: "mask",
    });
    expect(result.verdict).toBe("equivalent_masked");
    expect(result.rows[1]).toMatchObject({
      kind: "masked",
      masked: [{ reason: "immediate_policy" }],
    });
  });

  it("reports an inserted instruction as right-only", () => {
    const nop: Spec = { mnemonic: "nop", operands: [], bytes: "00000000" };
    const result = compare(body(5, 0x80020000), body(5, 0x80020000, [nop]));
    expect(result.counts).toMatchObject({ right_only: 1, matched: 4 });
    expect(result.first_divergence).toMatchObject({
      kind: "right_only",
      right: { index: 3, text: "nop" },
    });
  });

  it("reports a different encoding of the same instruction", () => {
    const right = body(5, 0x80020000).map((spec) =>
      spec.mnemonic === "jr" ? { ...spec, bytes: "03e00009" } : spec,
    );
    const result = compare(body(5, 0x80020000), right);
    expect(result.first_divergence).toMatchObject({
      kind: "replace",
      differences: [{ kind: "encoding", left: "03e00008", right: "03e00009" }],
    });
  });

  it("rejects listings for different architectures", () => {
    expect(() =>
      compareCompiledFunctions(
        evidence("a", listing(0x100, body(5, 0x200))),
        evidence("b", listing(0x100, body(5, 0x200), "x86:LE:32:default")),
      ),
    ).toThrow(
      expect.objectContaining({
        issues: [
          expect.objectContaining({
            path: ["right"],
            message: expect.stringContaining("does not match"),
          }),
        ],
      }),
    );
  });

  it("rejects Evidence from another operation", () => {
    const other = createEvidence(
      { path: "/tmp/x", sha256: "c".repeat(64), format: "elf" },
      { id: "ghidra", name: "Ghidra", version: "12" },
      {
        operation: "analyze_function",
        parameters: {},
        result: {},
        confidence: "observed",
        authority: "shipped-artifact",
      },
    );
    expect(() =>
      compareCompiledFunctions(
        other,
        evidence("b", listing(0x100, body(5, 1))),
      ),
    ).toThrow();
  });
});
