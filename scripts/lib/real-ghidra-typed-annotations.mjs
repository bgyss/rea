import assert from "node:assert/strict";

/**
 * Signature, calling-convention, and decompiler-variable edits (B6) on the
 * inventory fixture's `int rea_ghidra_inventory_indirect(int (*)(int), int)`,
 * plus a stack local and an uncommitted parameter in its switch function.
 * `call` and `invalid` drive one open MCP session; `cli` runs a fresh one.
 */
export const verifyTypedAnnotations = async (
  { call, invalid, cli },
  { address: entry, value: name },
  switchProcedure,
) => {
  const before = await call("annotate_native_function", {
    procedure: entry,
    comment: "typed annotation probe",
  });
  const conventionError = await invalid(
    "annotate_native_function",
    { procedure: entry, calling_convention: "__rea_missing" },
    /Unknown calling convention __rea_missing; .*defines: /u,
  );
  const defined = JSON.stringify(conventionError.details.issues)
    .match(/defines: ([^"]+)/u)[1]
    .split(", ");
  assert.ok(defined.includes("unknown") && defined.includes("default"));
  assert.ok(defined.includes(before.annotations.calling_convention));
  // The first spec-defined convention, which differs from the reset values.
  const convention = defined[0];
  const signature = `int ${name}(void *callback, int value)`;
  // A bad variable rolls back the signature applied earlier in the request.
  await invalid(
    "annotate_native_function",
    {
      procedure: entry,
      signature,
      variables: [{ name: "rea_missing_variable", new_name: "x" }],
    },
    /No uniquely named decompiler variable rea_missing_variable/u,
  );
  const unchanged = await call("annotate_native_function", {
    procedure: entry,
    comment: "typed annotation probe",
  });
  assert.equal(unchanged.annotations.signature, before.annotations.signature);
  await invalid(
    "annotate_native_function",
    { procedure: entry, signature: "int rea_wrong_name(int value)" },
    /names rea_wrong_name but the function/u,
  );
  await invalid(
    "annotate_native_function",
    { procedure: entry, signature: `int ${name}(struct rea_missing *m)` },
    /signature/u,
  );
  const typed = await call("annotate_native_function", {
    procedure: entry,
    signature,
    calling_convention: convention,
    variables: [{ name: "value", new_name: "count", data_type: "uint" }],
  });
  assert.match(typed.annotations.signature, /void \* *callback/u);
  assert.match(typed.annotations.signature, /uint count/u);
  assert.equal(typed.annotations.calling_convention, convention);
  assert.deepEqual(
    typed.annotations.variables.map(
      ({ variable, name, data_type, parameter }) => ({
        variable,
        name,
        data_type,
        parameter,
      }),
    ),
    [
      {
        variable: "value",
        name: "count",
        data_type: "uint",
        parameter: true,
      },
    ],
  );
  assert.match(typed.dossier.pseudocode, /\bcount\b/u);
  assert.equal(typed.dossier.procedure.signature, typed.annotations.signature);
  // Each CLI run is a fresh session, so it reapplies the signature first.
  const cliTyped = await cli("annotate-native-function", entry, [
    "--signature",
    signature,
    "--rename-variable",
    "callback=handler",
  ]);
  assert.equal(cliTyped.annotations.variables[0].name, "handler");
  assert.match(cliTyped.dossier.pseudocode, /\bhandler\b/u);
  // No signature here: the parameter is committed by the variable edit itself.
  const { pseudocode } = await call("analyze_function", {
    procedure: switchProcedure.address,
  });
  const local = pseudocode.match(/^\s+\w+ (local_[0-9a-f]+);$/mu)?.[1];
  const parameter = pseudocode.match(/\((?:\w+ )+(param_1)\b/u)?.[1];
  assert.ok(local && parameter, `no stack local or param_1 in ${pseudocode}`);
  const locals = await call("annotate_native_function", {
    procedure: switchProcedure.address,
    variables: [
      { name: local, new_name: "result", data_type: "int" },
      { name: parameter, new_name: "selector" },
    ],
  });
  assert.deepEqual(
    locals.annotations.variables.map(({ variable, name, parameter }) => ({
      variable,
      name,
      parameter,
    })),
    [
      { variable: local, name: "result", parameter: false },
      { variable: parameter, name: "selector", parameter: true },
    ],
  );
  assert.equal(locals.annotations.variables[0].data_type, "int");
  assert.match(locals.dossier.pseudocode, /\bint result;/u);
  assert.match(locals.dossier.pseudocode, /\bselector\b/u);
  return {
    local_and_parameter_renamed: true,
    signature: typed.annotations.signature,
    calling_conventions: defined.length,
    variables: typed.annotations.variables.length,
  };
};

/**
 * Label, typed data, and comments at the fixture's int
 * `rea_ghidra_inventory_global` (B6), plus rejections at a function entry.
 */
export const verifyDataAnnotations = async (
  { call, invalid, cli },
  { address, value: original },
  functionEntry,
) => {
  const labelled = await call("annotate_native_data", {
    address,
    label: "rea_counter",
    data_type: "int",
    comment: "Global counter",
    inline_comment: "",
  });
  assert.deepEqual(labelled.annotations, {
    address,
    label: "rea_counter",
    data_type: "int",
    size_bytes: 4,
    comment: "Global counter",
    inline_comment: null,
  });
  assert.equal(await call("address_name", { address }), "rea_counter");
  // Repeating the same edit is idempotent, as ledger replay requires.
  const repeated = await call("annotate_native_data", {
    address,
    label: "rea_counter",
    data_type: "int",
  });
  assert.deepEqual(repeated.annotations, labelled.annotations);
  await invalid(
    "annotate_native_data",
    { address: functionEntry, label: "rea_not_a_function_name" },
    /rename it with annotate_native_function/u,
  );
  await invalid(
    "annotate_native_data",
    { address: functionEntry, data_type: "uint" },
    /without replacing instructions or other defined data/u,
  );
  // Defined data is never replaced either, and the rejection rolls back the
  // label applied earlier in the same request.
  await invalid(
    "annotate_native_data",
    { address, label: "rea_rolled_back", data_type: "uint" },
    /without replacing instructions or other defined data/u,
  );
  assert.equal(await call("address_name", { address }), "rea_counter");
  await invalid(
    "annotate_native_data",
    { address, data_type: "struct rea_missing" },
    /Unknown or variable-length data type struct rea_missing/u,
  );
  const cliLabelled = await cli("annotate-native-data", address, [
    "--label",
    "rea_cli_counter",
    "--data-type",
    "uint",
  ]);
  assert.equal(cliLabelled.annotations.label, "rea_cli_counter");
  assert.equal(cliLabelled.annotations.data_type, "uint");
  return { labelled: original !== "rea_counter", cli_labelled: true };
};
