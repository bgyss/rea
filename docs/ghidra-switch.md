# Nintendo Switch NSO and NRO

REA opens Nintendo Switch NSO and NRO executables through an operator-pinned
Ghidra loader. Ghidra 12.1.4 ships no loader for either format, so REA carries
the source of one, builds it on request, and installs it into a private
per-session Ghidra settings directory. It never installs software into the
Ghidra distribution and never downloads a loader.

## Build and pin the loader

Run this inside the pinned environment (`GHIDRA_INSTALL_DIR` and `JAVA_HOME`
must be set):

```bash
npm run build:ghidra-switch-loader -- --out /absolute/path/to/loader-build
```

It compiles `bridge/ghidra-loaders/switch/` against your Ghidra jars with
`-Xlint:all -Werror`, and prints one JSON line with the jar path and its
SHA-256. The build is reproducible: the same sources and JDK give the same
digest. `npm run build:ghidra-switch-loader -- --self-test` compiles and runs
the loader's own checks (LZ4 decoding, header parsing and rejection of
truncated, oversized and overlapping segments) without Ghidra running.

Pin the jar in the environment that starts REA:

```bash
export REA_GHIDRA_LOADER_EXTENSIONS_JSON='[{"id":"switch-nxo","path":"/absolute/path/to/loader-build/rea-switch-loader.jar","sha256":"<printed digest>","loader_name":"ReaSwitchLoader"}]'
```

`id` names the extension directory, `path` must be absolute, `sha256` is the
digest REA must observe, and `loader_name` is the Ghidra loader class the jar
provides (`ReaSwitchLoader` for this loader). A relative path, an uppercase or
short digest, an unknown field, or a duplicate `id` or `loader_name` is refused
at startup.

## Open a Switch executable

Pass the format explicitly. REA does not infer it from the file name or header:

```bash
rea list-procedures /absolute/path/to/main --target-format switch-nso --provider ghidra
rea read-bytes /absolute/path/to/app.nro 0x7100001000 --length 16 --target-format switch-nro --provider ghidra
```

MCP uses `open_binary` with `format: "switch-nso"` or `"switch-nro"`. REA checks
the magic before starting Ghidra: `NSO0` at offset 0, or `NRO0` at offset
0x10. A hint that disagrees with the file is refused with the expected magic,
and `architecture` and `entry_point` are rejected, since the loader declares
both.

Evidence from a Switch target carries the pinned jar's digest in the analysis
profile (`loader_extensions`) and the loader's declared language
(`AARCH64:LE:64:v8A`, compiler spec `default`). A different jar gives a
different profile digest, so a snapshot or annotation ledger recorded with one
loader is never replayed under another.

## What the loader maps

Everything is placed at the fixed image base `0x7100000000`.

| Format | Segments                                                                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| NSO0   | `.text`, `.rodata`, `.data` at their header memory offsets; each is LZ4-decoded when its header flag is set; `.bss` follows `.data` (header size) |
| NRO0   | `.text`, `.rodata`, `.data` at their file offsets; `.bss` follows `.data`; a MOD0 header's `bss_end - bss_start` replaces the header's bss size   |

The entry point is the start of `.text`, labeled `entry`. When MOD0 is present
REA labels it `MOD0` and the dynamic section `_DYNAMIC`. `.text` is
read-and-execute, `.rodata` read-only, `.data` and `.bss` read-and-write.

## What is not covered

- Dynamic relocations, imports, symbol tables and `.eh_frame`-based function
  discovery. Only the entry point is a function until Ghidra's analysis finds
  more.
- NCA, XCI, NSP and other containers, decryption, and compression other than
  per-segment LZ4.
- Windows hosts. Pinned loaders are refused there.
- Hopper and IDA. They decline Switch targets and name Ghidra.
- Real game files. The verifier uses authored fixtures only.

## How the loader is installed

At profile resolution REA reads the jar once through an open handle, compares
its SHA-256 with the pin, and commits the digest. At launch it reads the jar
again, refuses any change, and writes
`<private home>/ghidra-settings/ghidra/<ghidra_version>/Extensions/<id>/` with
`Module.manifest`, `extension.properties` and `lib/<id>.jar`. The JVM is
started with `-Dapplication.settingsdir=<private home>/ghidra-settings`, inside
the private `user.home`, which keeps Ghidra's directory naming predictable.
Ghidra's production class search scans a module's `lib` jar only when the jar's
file name starts with the module directory's name, so the jar is always named
after its `id`.

This is content identity, not a signature or a sandbox: the loader runs inside
Ghidra's JVM with that process's authority. Pin only a jar you built or
reviewed.

## Verification

`npm run verify:ghidra:nxo` builds the loader, pins it, and opens authored NSO
(with and without a compressed `.rodata`) and NRO fixtures through MCP on real
Ghidra 12.1.4. It checks each memory map and permission, the decoded `.rodata`
bytes, the entry procedure and its instructions, and an NSO entry compared
with an assembled AArch64 object through `compare_compiled_function`. It also
checks that a hint that disagrees with the header, a missing pin, and a pin
that does not match the jar are refused, and that the CLI returns the same
bytes as MCP. It needs `GHIDRA_INSTALL_DIR`, `JAVA_HOME` and a C compiler that
can assemble for AArch64 (`--target=aarch64-linux-gnu`).

Only AArch64 macOS has been exercised. Linux hosts, other Ghidra versions and
real Switch binaries are not verified.
