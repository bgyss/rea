import { readFileSync } from "node:fs";

import { z } from "incur";

import { runDirectAnalysis } from "../composition/directAnalysis.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "../logger.js";
import {
  directAnalysisOptions,
  annotationLedgerOptions,
  formatSelectionOptions,
  providerSelectionOption,
} from "./options.js";
import type { CliInstance } from "./types.js";
import { LABEL_PACKS } from "../domain/native/nativeLabelPacks.js";
import { jsonObjectSchema } from "../domain/jsonValue.js";

/** Register native load-image, memory, and annotation CLI commands. */
export const registerCoreNativeCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  registerAnnotationCommand(cli, logger);
  registerDataAnnotationCommand(cli, logger);
  registerTypeDefinitionCommand(cli, logger);
  registerAnnotationSetCommand(cli, logger);
  cli.command(CLI_COMMANDS.inspectNativeLoadImage, {
    description:
      "Verify loaded native bytes, source mappings, relocations and entry",
    args: z.object({ path: z.string().describe("Local executable path") }),
    options: z.object({
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeLoadImage, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_load_image",
          {},
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.readBytes, {
    description: "Read exact provider memory bytes at one analysis address",
    args: z.object({
      path: z.string().describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      length: z
        .number()
        .int()
        .min(1)
        .default(256)
        .describe("Requested byte count"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.readBytes, () =>
        runDirectAnalysis(
          args.path,
          "read_bytes",
          { address: args.address, length: options.length },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.addressToFileOffset, {
    description: "Resolve an analysis address to its original file byte offset",
    args: z.object({
      path: z.string().describe("Local executable path"),
      address: z.string().describe("Exact provider memory address"),
    }),
    options: z.object({
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.addressToFileOffset, () =>
        runDirectAnalysis(
          args.path,
          "address_to_file_offset",
          { address: args.address },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.traceNativeValues, {
    description: "Trace bounded native def-use and call dependencies",
    args: z.object({
      path: z.string().describe("Local native executable or app path"),
      procedure: z
        .string()
        .describe("Explicit native procedure symbol or address"),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(16)
        .default(3)
        .describe("Maximum call traversal depth"),
      maxFunctions: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(16)
        .describe("Maximum function decompilations"),
      maxCallSites: z
        .number()
        .int()
        .min(1)
        .max(4096)
        .default(256)
        .describe("Maximum static call-site resolutions"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(20000)
        .default(5000)
        .describe("Maximum retained graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(40000)
        .default(10000)
        .describe("Maximum retained graph edges"),
      offset: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe("First graph node index"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(1000)
        .describe("Maximum nodes on this page"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    alias: {
      maxDepth: "max-depth",
      maxFunctions: "max-functions",
      maxCallSites: "max-call-sites",
      maxNodes: "max-nodes",
      maxEdges: "max-edges",
    },
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.traceNativeValues, () =>
        runDirectAnalysis(
          args.path,
          "trace_native_values",
          {
            procedure: args.procedure,
            max_depth: options.maxDepth,
            max_functions: options.maxFunctions,
            max_call_sites: options.maxCallSites,
            max_nodes: options.maxNodes,
            max_edges: options.maxEdges,
            offset: options.offset,
            limit: options.limit,
          },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
  cli.command(CLI_COMMANDS.inspectNativeDataType, {
    description: "Inspect one recovered database type or typed data object",
    args: z.object({
      path: z.string().describe("Local native executable or app path"),
    }),
    options: z.object({
      type: z.string().optional().describe("Exact database type category path"),
      address: z.string().describe("Exact native address").optional(),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.inspectNativeDataType, () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_data_type",
          {
            ...(options.type === undefined ? {} : { type: options.type }),
            ...(options.address === undefined
              ? {}
              : { address: options.address }),
          },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
  for (const [command, operation] of [
    [CLI_COMMANDS.inspectNativeInstruction, "inspect_native_instruction"],
    [CLI_COMMANDS.resolveNativeCallTargets, "resolve_native_call_targets"],
  ] as const) {
    cli.command(command, {
      description:
        operation === "inspect_native_instruction"
          ? "Inspect one native instruction with decoded operand facts"
          : "Resolve one static native call site",
      args: z.object({
        path: z.string().describe("Local native executable or app path"),
        address: z.string().describe("Exact native address"),
      }),
      options: z.object({
        ...formatSelectionOptions,
        ...annotationLedgerOptions,
        provider: providerSelectionOption,
      }),
      run: ({ args, options }) =>
        logCliCommand(logger, command, () =>
          runDirectAnalysis(
            args.path,
            operation,
            { address: args.address },
            directAnalysisOptions(logger, undefined, options.provider, options),
          ),
        ),
    });
  }
  registerNativeApiCommand(cli, logger);
  registerNativeUiActionCommand(cli, logger);
  registerNativeDispatchMetadataCommand(cli, logger);
};

const registerNativeDispatchMetadataCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectNativeDispatchMetadata, {
    description: "Inspect typed Objective-C and Swift dispatch metadata",
    args: z.object({
      path: z.string().describe("Target path used to bind the result evidence"),
    }),
    options: z.object({
      maxRecords: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(5_000)
        .describe("Maximum symbol records to inspect"),
      snapshot: z
        .string()
        .min(1)
        .optional()
        .describe("Load or update the local analysis snapshot"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    alias: { maxRecords: "max-records" },
    run: async ({ args, options }) =>
      logCliCommand(logger, "inspect-native-dispatch-metadata", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_dispatch_metadata",
          { max_records: options.maxRecords },
          directAnalysisOptions(
            logger,
            options.snapshot,
            options.provider,
            options,
          ),
        ),
      ),
  });
};

const registerNativeUiActionCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.traceNativeUiAction, {
    description:
      "Trace a compiled UI action selector to its native handler and direct callees",
    args: z.object({
      path: z.string().describe("Target path used to bind the result evidence"),
      action: z
        .string()
        .min(1)
        .describe(
          "A unique compiled UI action selector or interface object ID",
        ),
    }),
    options: z.object({
      maxDepth: z
        .number()
        .int()
        .min(0)
        .max(32)
        .default(8)
        .describe("Maximum relationship depth"),
      maxNodes: z
        .number()
        .int()
        .min(1)
        .max(2_000)
        .default(250)
        .describe("Maximum returned graph nodes"),
      maxEdges: z
        .number()
        .int()
        .min(1)
        .max(5_000)
        .default(500)
        .describe("Maximum returned graph edges"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    alias: {
      maxDepth: "max-depth",
      maxNodes: "max-nodes",
      maxEdges: "max-edges",
    },
    run: async ({ args, options }) =>
      logCliCommand(logger, "trace-native-ui-action", () =>
        runDirectAnalysis(
          args.path,
          "trace_native_ui_action",
          {
            action: args.action,
            max_depth: options.maxDepth,
            max_nodes: options.maxNodes,
            max_edges: options.maxEdges,
          },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
};

const registerNativeApiCommand = (cli: CliInstance, logger: Logger): void => {
  cli.command(CLI_COMMANDS.inspectNativeApi, {
    description: "Reconstruct one native function API boundary with evidence",
    args: z.object({
      path: z.string().describe("App or program path"),
      address: z.string().describe("Procedure name or address"),
    }),
    options: z.object({
      snapshot: z
        .string()
        .min(1)
        .optional()
        .describe("Load and update a local analysis snapshot"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, "inspect-native-api", () =>
        runDirectAnalysis(
          args.path,
          "inspect_native_api",
          { procedure: args.address },
          directAnalysisOptions(
            logger,
            options.snapshot,
            options.provider,
            options,
          ),
        ),
      ),
  });
};

/**
 * Merge repeated OLD=NEW renames and NAME=TYPE retypes into one edit per
 * variable, in first-mention order. Malformed pairs pass through unsplit so
 * the shared input schema reports them against `variables`.
 */
const variableEdits = (
  renames: readonly string[],
  retypes: readonly string[],
): { variables?: Record<string, string>[] } => {
  const edits = new Map<string, Record<string, string>>();
  const add = (pair: string, field: "new_name" | "data_type") => {
    const separator = pair.indexOf("=");
    const name = separator < 0 ? pair : pair.slice(0, separator);
    const value = separator < 0 ? "" : pair.slice(separator + 1);
    edits.set(name, { name, ...edits.get(name), [field]: value });
  };
  for (const pair of renames) add(pair, "new_name");
  for (const pair of retypes) add(pair, "data_type");
  return edits.size === 0 ? {} : { variables: [...edits.values()] };
};

const registerAnnotationCommand = (cli: CliInstance, logger: Logger): void => {
  cli.command(CLI_COMMANDS.annotateNativeFunction, {
    description: "Edit function annotations and return refreshed analysis",
    args: z.object({
      path: z.string().describe("Local executable path"),
      procedure: z
        .string()
        .describe("Exact function entry address or unique name"),
    }),
    options: z.object({
      name: z.string().min(1).optional().describe("Analyst function name"),
      comment: z
        .string()
        .optional()
        .describe("Regular entry comment; empty text clears it"),
      "inline-comment": z
        .string()
        .optional()
        .describe("Inline entry comment; empty text clears it"),
      signature: z
        .string()
        .min(1)
        .optional()
        .describe(
          "C prototype, e.g. 'int draw_sprite(struct sprite *s, uint8_t x)'; its name must match the function's",
        ),
      "calling-convention": z
        .string()
        .min(1)
        .optional()
        .describe("Calling convention defined by the program's compiler spec"),
      "rename-variable": z
        .array(z.string().min(1))
        .default([])
        .describe("OLD=NEW decompiler local or parameter rename; repeatable"),
      "retype-variable": z
        .array(z.string().min(1))
        .default([])
        .describe("NAME=C_TYPE decompiler local or parameter type; repeatable"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.annotateNativeFunction, () =>
        runDirectAnalysis(
          args.path,
          "annotate_native_function",
          {
            procedure: args.procedure,
            ...(options.name === undefined ? {} : { name: options.name }),
            ...(options.comment === undefined
              ? {}
              : { comment: options.comment }),
            ...(options["inline-comment"] === undefined
              ? {}
              : { inline_comment: options["inline-comment"] }),
            ...(options.signature === undefined
              ? {}
              : { signature: options.signature }),
            ...(options["calling-convention"] === undefined
              ? {}
              : { calling_convention: options["calling-convention"] }),
            ...variableEdits(
              options["rename-variable"],
              options["retype-variable"],
            ),
          },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
};

const registerDataAnnotationCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.annotateNativeData, {
    description: "Label, type, or comment one address and return the readback",
    args: z.object({
      path: z.string().describe("Local executable path"),
      address: z.string().describe("Exact address, as REA reports addresses"),
    }),
    options: z.object({
      label: z.string().min(1).optional().describe("Primary label"),
      "data-type": z
        .string()
        .min(1)
        .optional()
        .describe(
          "Fixed-length C type to define; replaces undefined bytes only",
        ),
      comment: z
        .string()
        .optional()
        .describe("Regular comment; empty text clears it"),
      "inline-comment": z
        .string()
        .optional()
        .describe("Inline comment; empty text clears it"),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.annotateNativeData, () =>
        runDirectAnalysis(
          args.path,
          "annotate_native_data",
          {
            address: args.address,
            ...(options.label === undefined ? {} : { label: options.label }),
            ...(options["data-type"] === undefined
              ? {}
              : { data_type: options["data-type"] }),
            ...(options.comment === undefined
              ? {}
              : { comment: options.comment }),
            ...(options["inline-comment"] === undefined
              ? {}
              : { inline_comment: options["inline-comment"] }),
          },
          directAnalysisOptions(logger, undefined, options.provider, options),
        ),
      ),
  });
};

// The header's text, or why it cannot be read.
const readHeader = (
  path: string,
): { readonly text: string } | { readonly error: string } => {
  try {
    return { text: readFileSync(path, "utf8") };
  } catch (cause: unknown) {
    return {
      error: `Cannot read C header ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
};

const registerTypeDefinitionCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.defineNativeTypes, {
    description:
      "Define the struct, union, enum and typedef declarations in a preprocessed C header and return their layouts",
    args: z.object({
      path: z.string().describe("Local executable path"),
      header: z
        .string()
        .describe(
          "Preprocessed C header; expand macros and includes first (cc -E -P)",
        ),
    }),
    options: z.object({
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.defineNativeTypes, () => {
        const header = readHeader(args.header);
        const analysis = directAnalysisOptions(
          logger,
          undefined,
          options.provider,
          options,
        );
        return runDirectAnalysis(
          args.path,
          "define_native_types",
          "text" in header ? { declarations: header.text } : {},
          "text" in header
            ? analysis
            : {
                ...analysis,
                optionError: { option: "header", message: header.error },
              },
        );
      }),
  });
};

// The annotation set in a rea.label-pack.v1 file or a bare set file, as the
// request's annotations; the provider validates its contents.
const readAnnotationSetFile = (
  path: string,
): { readonly annotations: unknown } | { readonly error: string } => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (cause: unknown) {
    return {
      error: `Cannot read annotation set ${path}: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
  const pack = z
    .object({
      schema_version: z.literal("rea.label-pack.v1"),
      annotations: z.unknown(),
    })
    .safeParse(parsed);
  return { annotations: pack.success ? pack.data.annotations : parsed };
};

const registerAnnotationSetCommand = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.applyNativeAnnotations, {
    description:
      "Apply a built-in hardware label pack or an annotation set file atomically and return the readback",
    args: z.object({ path: z.string().describe("Local executable path") }),
    options: z.object({
      pack: z
        .enum(Object.keys(LABEL_PACKS) as [string, ...string[]])
        .optional()
        .describe("Built-in label pack"),
      file: z
        .string()
        .optional()
        .describe(
          "rea.label-pack.v1 file, or a JSON annotation set with memory_blocks, declarations, data and functions",
        ),
      ...formatSelectionOptions,
      ...annotationLedgerOptions,
      provider: providerSelectionOption,
    }),
    run: ({ args, options }) =>
      logCliCommand(logger, CLI_COMMANDS.applyNativeAnnotations, () => {
        const analysis = directAnalysisOptions(
          logger,
          undefined,
          options.provider,
          options,
        );
        const file =
          options.file === undefined
            ? undefined
            : readAnnotationSetFile(options.file);
        if (file !== undefined && "error" in file)
          return runDirectAnalysis(
            args.path,
            "apply_native_annotations",
            {},
            {
              ...analysis,
              optionError: { option: "file", message: file.error },
            },
          );
        return runDirectAnalysis(
          args.path,
          "apply_native_annotations",
          jsonObjectSchema.parse({
            ...(options.pack === undefined ? {} : { pack: options.pack }),
            ...(file === undefined ? {} : { annotations: file.annotations }),
          }),
          analysis,
        );
      }),
  });
};
