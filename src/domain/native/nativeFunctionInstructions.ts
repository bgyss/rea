import { z } from "zod";
import { nativeInstructionSchema } from "./nativeInstruction.js";

/** One procedure, selected by symbol or address, whose instructions are listed. */
export const nativeFunctionInstructionsInputSchema = z.strictObject({
  procedure: z.string().min(1),
});

const relocationSchema = z.strictObject({
  byte_offset: z.number().int().nonnegative(),
  type: z.number().int(),
  status: z.string(),
  symbol: z.string().nullable(),
  original_bytes_hex: z.string().nullable(),
});

const instructionSchema = z.strictObject({
  address: z.string(),
  offset: z.number().int(),
  bytes: z.string(),
  length: z.number().int().positive(),
  mnemonic: z.string(),
  raw_disassembly: z.string(),
  operands: nativeInstructionSchema.shape.operands,
  flow: nativeInstructionSchema.shape.flow,
  references: nativeInstructionSchema.shape.references,
  relocations: z.array(relocationSchema),
});

/** Every instruction of one function with decoded operands and applied relocations. */
export const nativeFunctionInstructionsSchema = z.strictObject({
  procedure: z.object({ address: z.string(), name: z.string() }),
  architecture: z.string(),
  mode: z.string(),
  instructions: z.array(instructionSchema),
  limitations: z.array(z.string()),
});

export type NativeFunctionInstructions = z.infer<
  typeof nativeFunctionInstructionsSchema
>;
export type NativeFunctionInstruction =
  NativeFunctionInstructions["instructions"][number];
