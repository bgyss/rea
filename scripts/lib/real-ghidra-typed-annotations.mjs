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

/**
 * C type definitions (B6): parse, replace, roll back and reject, then name
 * a defined type in a function signature. `entry` is the inventory fixture's
 * indirect function; `dataAddress` is its already-typed global.
 */
export const verifyTypeDefinitions = async (
  { call, invalid, cli },
  { address: entry, value: name },
  dataAddress,
  headerPath,
) => {
  const declarations = [
    "typedef int (*rea_callback)(int);",
    "enum rea_mode { REA_OFF = 0, REA_ON = 1 };",
    "struct rea_pair { int left; short right; };",
    "typedef struct rea_pair rea_pair_t;",
    "int rea_proto(int value);",
  ].join("\n");
  const defined = await call("define_native_types", { declarations });
  const byId = new Map(defined.types.map((type) => [type.id, type]));
  assert.deepEqual([...byId.keys()].sort(), [
    "/rea/rea_callback",
    "/rea/rea_mode",
    "/rea/rea_pair",
    "/rea/rea_pair_t",
  ]);
  assert.ok(defined.types.every((type) => type.outcome === "created"));
  const pair = byId.get("/rea/rea_pair");
  assert.equal(pair.kind, "struct");
  assert.equal(pair.size_bytes, 8);
  assert.deepEqual(
    pair.fields.map((field) => [field.name, field.offset_bytes, field.type_id]),
    [
      ["left", 0, "/int"],
      ["right", 4, "/short"],
    ],
  );
  assert.deepEqual(byId.get("/rea/rea_mode").members, [
    { name: "REA_OFF", value: "0" },
    { name: "REA_ON", value: "1" },
  ]);
  assert.equal(byId.get("/rea/rea_pair_t").referenced_type, "/rea/rea_pair");
  // A function-pointer typedef's signature is stored under a distinct name,
  // so the typedef's own name stays unambiguous.
  const callback = byId.get("/rea/rea_callback");
  assert.equal(callback.kind, "typedef");
  assert.match(callback.referenced_type, /rea_callback_fn \*/u);
  assert.ok(defined.types.every((type) => type.other_ids.length === 0));
  assert.deepEqual(defined.skipped, [{ name: "rea_proto", kind: "function" }]);
  // Identical declarations are unchanged, as ledger replay requires.
  const repeated = await call("define_native_types", { declarations });
  assert.ok(repeated.types.every((type) => type.outcome === "unchanged"));
  // A changed definition replaces the type at its path.
  const replaced = await call("define_native_types", {
    declarations: "struct rea_pair { int left; int right; int extra; };",
  });
  assert.deepEqual(
    replaced.types.map(({ id, outcome, size_bytes }) => [
      id,
      outcome,
      size_bytes,
    ]),
    [["/rea/rea_pair", "replaced", 12]],
  );
  const inspected = await call("inspect_native_data_type", {
    type: "/rea/rea_pair",
  });
  assert.equal(inspected.size_bytes, 12);
  // A defined typedef resolves by bare name in a signature.
  const signed = await call("annotate_native_function", {
    procedure: entry,
    signature: `int ${name}(rea_callback callback, int value)`,
  });
  assert.match(signed.annotations.signature, /rea_callback callback/u);
  // A parse failure rolls back the types parsed before it.
  await invalid(
    "define_native_types",
    { declarations: "struct rea_rolled_back { int a; };\nstruct rea_broken {" },
    /C parser rejected the declarations/u,
  );
  const rolledBack = await call("inspect_native_data_type", {
    type: "/rea/rea_rolled_back",
  });
  assert.equal(rolledBack.status, "unavailable");
  await invalid(
    "define_native_types",
    { declarations: "#define REA_PPU_CTRL 0x2000\n" },
    /C parser rejected the declarations/u,
  );
  await invalid(
    "define_native_types",
    { declarations: "int rea_only_prototype(int value);" },
    /define no struct, union, enum or typedef/u,
  );
  // A different same-named type elsewhere makes the bare name ambiguous.
  const shadow = await call("define_native_types", {
    declarations: '#line 1 "rea_other"\nstruct rea_pair { char c; };',
  });
  assert.deepEqual(
    shadow.types.map(({ id, other_ids }) => [id, other_ids]),
    [["/rea_other/rea_pair", ["/rea/rea_pair"]]],
  );
  await invalid(
    "annotate_native_data",
    { address: dataAddress, data_type: "rea_pair" },
    /Unknown or variable-length data type rea_pair/u,
  );
  const cliDefined = await cli("define-native-types", headerPath);
  assert.deepEqual(
    cliDefined.types.map(({ id, kind, outcome }) => [id, kind, outcome]),
    [["/rea/rea_cli_flags", "enum", "created"]],
  );
  return {
    defined: defined.types.length,
    replaced: true,
    rolled_back: true,
    ambiguous_name_rejected: true,
    cli_defined: true,
  };
};

/**
 * An inline annotation set (B6 bulk apply): declarations, a data edit and a
 * function edit naming the declared type, applied atomically; a rejected
 * function item rolls back the type and label applied before it.
 */
export const verifyAnnotationSets = async (
  { call, invalid },
  { address: entry, value: name },
  dataAddress,
) => {
  const annotations = {
    declarations: "typedef int (*rea_set_callback)(int);",
    data: [{ address: dataAddress, label: "rea_set_counter" }],
    functions: [
      {
        procedure: entry,
        signature: `int ${name}(rea_set_callback callback, int value)`,
        comment: "set probe",
      },
    ],
  };
  await invalid(
    "apply_native_annotations",
    {
      annotations: {
        ...annotations,
        declarations: "typedef int (*rea_set_rolled_back)(int);",
        functions: [{ procedure: "rea_missing_function", comment: "x" }],
      },
    },
    /functions\[0\]: Unknown Ghidra procedure name or address: rea_missing_function/u,
  );
  const rolledBack = await call("inspect_native_data_type", {
    type: "/rea/rea_set_rolled_back",
  });
  assert.equal(rolledBack.status, "unavailable");
  assert.notEqual(
    await call("address_name", { address: dataAddress }),
    "rea_set_counter",
  );
  const applied = await call("apply_native_annotations", { annotations });
  assert.equal(applied.pack, null);
  assert.deepEqual(
    applied.types.map((type) => type.id),
    ["/rea/rea_set_callback"],
  );
  assert.equal(applied.data[0].label, "rea_set_counter");
  assert.match(applied.functions[0].signature, /rea_set_callback callback/u);
  assert.equal(applied.functions[0].comment, "set probe");
  return { applied: true, item_rejection_rolled_back: true };
};
