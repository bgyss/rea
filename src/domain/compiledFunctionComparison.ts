import type { z } from "zod";
import { AnalysisInputError } from "./analysisErrorCore.js";
import {
  compiledFunctionComparisonResultSchema,
  compiledFunctionMaskingSchema,
  type CompiledFunctionComparisonResult,
  type CompiledFunctionRow,
} from "./compiledFunctionComparisonSchemas.js";
import { parseEvidence, type Evidence } from "./evidence.js";
import {
  nativeFunctionInstructionsSchema,
  type NativeFunctionInstruction,
  type NativeFunctionInstructions,
} from "./native/nativeFunctionInstructions.js";

export {
  compiledFunctionComparisonInputSchema,
  compiledFunctionComparisonResultSchema,
} from "./compiledFunctionComparisonSchemas.js";

const OPERATION = "compare_compiled_function";
const LISTING_OPERATION = "inspect_native_function_instructions";
/** Edit distance beyond which alignment falls back to positional pairing. */
const MAX_EDIT_DISTANCE = 4_000;

type Masking = z.output<typeof compiledFunctionMaskingSchema>;
type Operand = NativeFunctionInstruction["operands"][number];
type MaskReason = Extract<
  CompiledFunctionRow,
  { kind: "masked" }
>["masked"][number]["reason"];
type Difference = Extract<
  CompiledFunctionRow,
  { kind: "replace" }
>["differences"][number];

interface Side {
  readonly evidence: Evidence;
  readonly listing: NativeFunctionInstructions;
  readonly entry: bigint;
  readonly internal: ReadonlySet<string>;
}

const inputError = (side: "left" | "right", message: string): never => {
  throw new AnalysisInputError(OPERATION, undefined, [
    { path: [side], reason: "invalid_value", message },
  ]);
};

const parseSide = (side: "left" | "right", input: unknown): Side => {
  const evidence = parseEvidence(input);
  if (evidence.operation !== LISTING_OPERATION)
    return inputError(side, `Expected ${LISTING_OPERATION} Evidence`);
  if (evidence.subject === null)
    return inputError(side, "Expected artifact-bound Evidence");
  const parsed = nativeFunctionInstructionsSchema.safeParse(
    evidence.normalized_result,
  );
  if (!parsed.success)
    return inputError(
      side,
      `Evidence does not hold a complete instruction listing: ${parsed.error.message}`,
    );
  const listing = parsed.data;
  return {
    evidence,
    listing,
    entry: addressValue(listing.procedure.address),
    internal: new Set(listing.instructions.map(({ address }) => address)),
  };
};

/** The numeric part of a canonical address; the space name is identity, not magnitude. */
const addressValue = (address: string): bigint =>
  BigInt(address.slice(address.lastIndexOf(":") + 1));

/** Constants are excluded so a relocated operand pairs with its linked form. */
const operandSkeleton = (operand: Operand): string =>
  operand.components
    .filter(({ kind }) => kind !== "immediate" && kind !== "address")
    .map(({ text }) => text)
    .join(",");

const skeleton = (instruction: NativeFunctionInstruction): string =>
  `${instruction.mnemonic} ${instruction.operands.map(operandSkeleton).join(" | ")}`;

type Edit = readonly ["eq" | "del" | "ins", number, number];

/** Shortest edit script (Myers), or null when the scripts exceed the safety bound. */
const shortestEdits = (
  left: readonly string[],
  right: readonly string[],
): readonly Edit[] | null => {
  const n = left.length;
  const m = right.length;
  const max = Math.min(n + m, MAX_EDIT_DISTANCE);
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  let found = false;
  for (let d = 0; d <= max && !found; d += 1) {
    trace.push(v.slice(offset - d - 1, offset + d + 2));
    for (let k = -d; k <= d; k += 2) {
      let x =
        k === -d ||
        (k !== d && (v[offset + k - 1] ?? 0) < (v[offset + k + 1] ?? 0))
          ? (v[offset + k + 1] ?? 0)
          : (v[offset + k - 1] ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && left[x] === right[y]) {
        x += 1;
        y += 1;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) {
        found = true;
        break;
      }
    }
  }
  if (!found) return null;
  const edits: Edit[] = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d -= 1) {
    const state = trace[d];
    if (state === undefined) return null;
    const at = (k: number): number => state[k + d + 1] ?? 0;
    const k = x - y;
    const previousK =
      k === -d || (k !== d && at(k - 1) < at(k + 1)) ? k + 1 : k - 1;
    const previousX = d === 0 ? 0 : at(previousK);
    const previousY = d === 0 ? 0 : previousX - previousK;
    while (x > previousX && y > previousY) {
      edits.push(["eq", x - 1, y - 1]);
      x -= 1;
      y -= 1;
    }
    if (d > 0) {
      if (x === previousX) edits.push(["ins", x, y - 1]);
      else edits.push(["del", x - 1, y]);
    }
    x = previousX;
    y = previousY;
  }
  return edits.reverse();
};

const positionalEdits = (n: number, m: number): readonly Edit[] => [
  ...Array.from({ length: Math.min(n, m) }, (_, index): Edit => [
    "eq",
    index,
    index,
  ]),
  ...Array.from({ length: Math.max(0, n - m) }, (_, index): Edit => [
    "del",
    Math.min(n, m) + index,
    m,
  ]),
  ...Array.from({ length: Math.max(0, m - n) }, (_, index): Edit => [
    "ins",
    n,
    Math.min(n, m) + index,
  ]),
];

const sideRow = (
  instruction: NativeFunctionInstruction,
  index: number,
): Extract<CompiledFunctionRow, { kind: "match" }>["left"] => ({
  index,
  address: instruction.address,
  offset: instruction.offset,
  text: instruction.raw_disassembly,
  bytes: instruction.bytes,
});

/** Operands that carry a link-time address, from typed references and address tokens. */
const attributedOperands = (
  instruction: NativeFunctionInstruction,
  side: Side,
): ReadonlySet<number> => {
  const indexes = new Set<number>();
  for (const reference of instruction.references)
    if (
      reference.operand_index >= 0 &&
      !side.internal.has(reference.target_address)
    )
      indexes.add(reference.operand_index);
  for (const operand of instruction.operands)
    if (
      operand.components.some(
        ({ kind, value }) =>
          kind === "address" && value !== null && !side.internal.has(value),
      )
    )
      indexes.add(operand.index);
  return indexes;
};

interface OperandOutcome {
  readonly state: "equal" | "masked" | "differs";
  readonly reason?: MaskReason;
}

type Component = Operand["components"][number];

const isConstant = ({ kind }: Component): boolean =>
  kind === "immediate" || kind === "address";

const compareOperand = (
  index: number,
  left: Operand,
  right: Operand,
  context: {
    readonly left: Side;
    readonly right: Side;
    readonly relocated: boolean;
    readonly unattributed: boolean;
    readonly attributed: ReadonlySet<number>;
    readonly masking: Masking;
  },
): OperandOutcome => {
  const leftTokens = left.components.filter((item) => !isConstant(item));
  const rightTokens = right.components.filter((item) => !isConstant(item));
  if (
    leftTokens.length !== rightTokens.length ||
    leftTokens.some(
      ({ text }, position) => text !== rightTokens[position]?.text,
    )
  )
    return { state: "differs" };
  const leftConstants = left.components.filter(isConstant);
  const rightConstants = right.components.filter(isConstant);
  const same =
    leftConstants.length === rightConstants.length &&
    leftConstants.every(
      (item, position) =>
        item.kind === rightConstants[position]?.kind &&
        item.value === rightConstants[position]?.value,
    );
  if (same) return { state: "equal" };
  if (
    context.relocated &&
    (context.unattributed || context.attributed.has(index))
  )
    return {
      state: "masked",
      reason: context.unattributed ? "relocation_unattributed" : "relocation",
    };
  let masked: MaskReason | undefined;
  const policyMasksImmediates = context.masking.immediates === "mask";
  const strictLeft = leftConstants.filter(
    ({ kind }) => !(policyMasksImmediates && kind === "immediate"),
  );
  const strictRight = rightConstants.filter(
    ({ kind }) => !(policyMasksImmediates && kind === "immediate"),
  );
  if (policyMasksImmediates && strictLeft.length !== leftConstants.length)
    masked = "immediate_policy";
  if (strictLeft.length !== strictRight.length) return { state: "differs" };
  for (const [position, l] of strictLeft.entries()) {
    const r = strictRight[position];
    if (r === undefined || l.kind !== r.kind) return { state: "differs" };
    if (l.value === r.value) continue;
    if (l.kind === "immediate" || l.value === null || r.value === null)
      return { state: "differs" };
    const leftInternal = context.left.internal.has(l.value);
    const rightInternal = context.right.internal.has(r.value);
    if (leftInternal !== rightInternal) return { state: "differs" };
    if (leftInternal) {
      if (
        addressValue(l.value) - context.left.entry !==
        addressValue(r.value) - context.right.entry
      )
        return { state: "differs" };
      continue;
    }
    masked ??= "external_address";
  }
  return masked === undefined
    ? { state: "equal" }
    : { state: "masked", reason: masked };
};

const comparePair = (
  leftIndex: number,
  rightIndex: number,
  left: Side,
  right: Side,
  masking: Masking,
): CompiledFunctionRow => {
  const l = left.listing.instructions[leftIndex];
  const r = right.listing.instructions[rightIndex];
  if (l === undefined || r === undefined)
    throw new TypeError("Alignment referenced a missing instruction");
  const sides = {
    left: sideRow(l, leftIndex),
    right: sideRow(r, rightIndex),
  };
  const differences: Difference[] = [];
  const masked: Extract<CompiledFunctionRow, { kind: "masked" }>["masked"] = [];
  if (l.mnemonic !== r.mnemonic)
    differences.push({
      kind: "mnemonic",
      operand_index: null,
      left: l.mnemonic,
      right: r.mnemonic,
    });
  else if (l.operands.length !== r.operands.length)
    differences.push({
      kind: "operand_count",
      operand_index: null,
      left: String(l.operands.length),
      right: String(r.operands.length),
    });
  else {
    const relocated = l.relocations.length > 0 || r.relocations.length > 0;
    const attributed = new Set([
      ...attributedOperands(l, left),
      ...attributedOperands(r, right),
    ]);
    for (const [index, leftOperand] of l.operands.entries()) {
      const rightOperand = r.operands[index];
      if (rightOperand === undefined) continue;
      const outcome = compareOperand(index, leftOperand, rightOperand, {
        left,
        right,
        relocated,
        unattributed: relocated && attributed.size === 0,
        attributed,
        masking,
      });
      if (outcome.state === "differs")
        differences.push({
          kind: "operand",
          operand_index: index,
          left: leftOperand.raw,
          right: rightOperand.raw,
        });
      else if (outcome.state === "masked" && outcome.reason !== undefined)
        masked.push({
          operand_index: index,
          reason: outcome.reason,
          left: leftOperand.raw,
          right: rightOperand.raw,
        });
    }
  }
  if (differences.length === 0 && masked.length === 0 && l.bytes !== r.bytes)
    differences.push({
      kind: "encoding",
      operand_index: null,
      left: l.bytes,
      right: r.bytes,
    });
  if (differences.length > 0) return { kind: "replace", ...sides, differences };
  if (masked.length > 0) return { kind: "masked", ...sides, masked };
  return { kind: "match", ...sides };
};

const alignRows = (
  left: Side,
  right: Side,
  masking: Masking,
): { readonly rows: CompiledFunctionRow[]; readonly exact: boolean } => {
  const leftKeys = left.listing.instructions.map(skeleton);
  const rightKeys = right.listing.instructions.map(skeleton);
  const shortest = shortestEdits(leftKeys, rightKeys);
  const edits = shortest ?? positionalEdits(leftKeys.length, rightKeys.length);
  const rows: CompiledFunctionRow[] = [];
  let deleted: number[] = [];
  let inserted: number[] = [];
  const flush = (): void => {
    const pairs = Math.min(deleted.length, inserted.length);
    for (let index = 0; index < pairs; index += 1)
      rows.push(
        comparePair(
          deleted[index] ?? 0,
          inserted[index] ?? 0,
          left,
          right,
          masking,
        ),
      );
    for (const index of deleted.slice(pairs)) {
      const instruction = left.listing.instructions[index];
      if (instruction !== undefined)
        rows.push({ kind: "left_only", left: sideRow(instruction, index) });
    }
    for (const index of inserted.slice(pairs)) {
      const instruction = right.listing.instructions[index];
      if (instruction !== undefined)
        rows.push({ kind: "right_only", right: sideRow(instruction, index) });
    }
    deleted = [];
    inserted = [];
  };
  for (const [kind, leftIndex, rightIndex] of edits) {
    if (kind === "del") deleted.push(leftIndex);
    else if (kind === "ins") inserted.push(rightIndex);
    else {
      flush();
      rows.push(comparePair(leftIndex, rightIndex, left, right, masking));
    }
  }
  flush();
  return { rows, exact: shortest !== null };
};

const functionSummary = (side: Side) => ({
  name: side.listing.procedure.name,
  address: side.listing.procedure.address,
  instruction_count: side.listing.instructions.length,
  evidence_id: side.evidence.evidence_id,
  subject_sha256: side.evidence.subject?.digest.sha256 ?? "",
});

/**
 * Align an original function with a rebuilt candidate instruction by
 * instruction. Instructions are aligned by mnemonic and operand shape, then
 * each aligned pair is compared with relocations, external addresses and
 * (optionally) immediates masked. Bytes of a masked pair are not compared.
 */
export const compareCompiledFunctions = (
  leftInput: unknown,
  rightInput: unknown,
  maskingInput: unknown = {},
): CompiledFunctionComparisonResult => {
  const masking = compiledFunctionMaskingSchema.parse(maskingInput);
  const left = parseSide("left", leftInput);
  const right = parseSide("right", rightInput);
  if (left.listing.architecture !== right.listing.architecture)
    inputError(
      "right",
      `Architecture ${right.listing.architecture} does not match the original's ${left.listing.architecture}`,
    );
  const { rows, exact } = alignRows(left, right, masking);
  const count = (kind: CompiledFunctionRow["kind"]): number =>
    rows.filter((row) => row.kind === kind).length;
  const counts = {
    matched: count("match"),
    masked: count("masked"),
    replaced: count("replace"),
    left_only: count("left_only"),
    right_only: count("right_only"),
  };
  const total =
    left.listing.instructions.length + right.listing.instructions.length;
  const aligned = counts.matched + counts.masked;
  const different = counts.replaced + counts.left_only + counts.right_only > 0;
  return compiledFunctionComparisonResultSchema.parse({
    verdict: different
      ? "different"
      : counts.masked > 0
        ? "equivalent_masked"
        : "identical",
    score: total === 0 ? 1 : (2 * aligned) / total,
    architecture: left.listing.architecture,
    mode: left.listing.mode,
    left: functionSummary(left),
    right: functionSummary(right),
    masking,
    counts,
    first_divergence:
      rows.find(
        ({ kind }) =>
          kind === "replace" || kind === "left_only" || kind === "right_only",
      ) ?? null,
    rows,
    right_relocations: right.listing.instructions.flatMap(
      (instruction, index) =>
        instruction.relocations.map((relocation) => ({
          right_index: index,
          byte_offset: relocation.byte_offset,
          symbol: relocation.symbol,
          type: relocation.type,
          status: relocation.status,
        })),
    ),
    limitations: [
      ...new Set([
        ...(exact
          ? []
          : [
              `Instruction sequences differ by more than ${MAX_EDIT_DISTANCE} edits; instructions were paired by position instead of aligned.`,
            ]),
        "Instructions are aligned by mnemonic and operand shape; a pair that differs only in a constant or target reports the differing operand.",
        "Operands of a relocated instruction are masked only where a typed reference or address token attributes the relocation; otherwise every immediate and address of that instruction is masked (relocation_unattributed). Bytes of a masked pair are not compared.",
        "Targets outside the function are masked, so a call to the wrong function is not detected by this comparison; compare the right side's relocation symbols with the original's callees.",
        ...left.listing.limitations.map((item) => `Left: ${item}`),
        ...right.listing.limitations.map((item) => `Right: ${item}`),
      ]),
    ].sort((a, b) => a.localeCompare(b)),
  });
};
