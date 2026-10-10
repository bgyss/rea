# Raw memory images with Ghidra

REA can analyze headerless memory images, such as console ROM banks, PRG data, or extracted RAM segments. The caller declares the processor, base address, and entry point. Ghidra imports the bytes with `BinaryLoader`, using the declared language and compiler specification, seeds the entry as a function, and then runs default auto-analysis. Linux x64 and macOS hosts are supported; the Windows P0 boundary admits PE only.

The declaration uses the `dcomp.ghidra-profile.v1` JSON shape, so one profile file and its digest can serve both REA and dcomp:

```json
{
  "schema_version": "dcomp.ghidra-profile.v1",
  "profile_id": "nes-ricoh-2a03-mini-v1",
  "platform": "nes",
  "processor_language_id": "6502:LE:16:default",
  "compiler_spec_id": "default",
  "loader": "BinaryLoader",
  "load_address": 32768,
  "entry_address": 32768,
  "analysis_timeout_seconds": 120,
  "max_instruction_facts": 256
}
```

`processor_language_id` must be a Ghidra language ID (`PROCESSOR:LE|BE:BITS:VARIANT`) available in the installation. `load_address` and `entry_address` are linear byte addresses in the language's default address space. `analysis_timeout_seconds` and `max_instruction_facts` are dcomp fact-export bounds. REA records them as part of the profile identity but doesn't apply them.

## Banked and mapped images (v2)

A `dcomp.ghidra-profile.v2` profile maps slices of the file to CPU addresses, for
cartridges and consoles that switch banks or load overlays:

```json
{
  "schema_version": "dcomp.ghidra-profile.v2",
  "profile_id": "mmc1-title-v2",
  "platform": "nes",
  "processor_language_id": "6502:LE:16:default",
  "compiler_spec_id": "default",
  "blocks": [
    {
      "name": "prg_bank5",
      "file_offset": 81936,
      "length": 16384,
      "load_address": 32768,
      "overlay": true,
      "permissions": "rx",
      "entry_addresses": [32768]
    },
    {
      "name": "prg_fixed",
      "file_offset": 114704,
      "length": 16384,
      "load_address": 49152,
      "overlay": false,
      "permissions": "rx",
      "entry_addresses": [65532]
    }
  ],
  "analysis_timeout_seconds": 120,
  "max_instruction_facts": 256
}
```

- Each block maps `length` bytes from `file_offset` to `load_address`, with
  `r`, `rw`, `rx` or `rwx` permissions.
- An `overlay` block becomes its own Ghidra address space named after the
  block. Banks that share CPU addresses keep distinct identities, written
  `<block>:0x<offset>` (for example `prg_bank5:0x8000`), and stay selectable
  by that address. Non-overlay blocks use the default space and must not
  overlap each other.
- Every entry address must lie inside its block, and at least one entry is
  required. Entries are named `<block>_entry` (or `<block>_entry_<hex>` when a
  block has several).
- Block names are unique (1–32 letters, digits or underscores). Blocks must lie
  inside the file and the language's address width.
- REA imports a one-byte stub, then rebuilds memory from the whole source file
  after checking its SHA-256 against the imported executable digest. Each
  block keeps its file offset, so `address_to_file_offset` reports the exact
  ROM byte.
- Code in a bank that calls or reads a shared address (such as `JSR $8000`
  from a fixed bank) resolves in the default space. Which bank a run-time
  bank switch selects is not modelled.

## Open and inspect

```bash
rea inspect /abs/prg.bin --target-format raw-image --raw-image-profile /abs/nes.profile.json --provider ghidra --json
rea function /abs/prg.bin entry --target-format raw-image --raw-image-profile /abs/nes.profile.json --provider ghidra --json
rea instructions /abs/prg.bin entry --target-format raw-image --raw-image-profile /abs/nes.profile.json --provider ghidra --json
```

For MCP, pass the profile inline:

```json
{
  "path": "/abs/prg.bin",
  "format": "raw-image",
  "raw_image_profile": {
    "schema_version": "dcomp.ghidra-profile.v1",
    "...": "..."
  },
  "provider_id": "ghidra"
}
```

Admission rejects:

- `raw-image` without a profile;
- a profile without `raw-image`;
- an image that overflows the language's address width at its base;
- an entry outside the loaded bytes;
- segmented 16-bit x86 languages, which use the [DOS interpretations](ghidra-dos.md) instead.

Hopper and IDA decline raw images, because they can't apply the declared profile.

For iterative work on one ROM, set `REA_GHIDRA_PROJECT_CACHE_DIR` so the analysed project is kept and reopened without re-analysis, and annotations persist between runs. Pass `--annotation-ledger` (or `annotation_ledger_path`) to also keep a reviewable record of names. See [Persistent project cache](native-investigation.md#persistent-project-cache) and [Annotation ledger](native-investigation.md#annotation-ledger).

## Evidence semantics

- `subject.format` is `raw-image`, and `subject.architecture` is `null`. REA doesn't map a Ghidra language to a CPU family; the exact language ID is in the analysis profile.
- The analysis profile records `loader: BinaryLoader`, `language_id`, `compiler_spec_id`, `base_address`, `entry_address`, and the complete `raw_image_profile`. Changing any field changes the profile digest, so snapshots and cached evidence never cross profiles.
- Function evidence lists the declaration as a limitation. The language, base, and entry are caller assertions, not observations from the bytes.
- A v1 image is one flat block; use a v2 map for banks and overlays. Mirrors and memory-mapped I/O are not modelled unless declared as blocks. Languages may add their own blocks (Ghidra's 6502 language defines `ZERO_PAGE` and `STACK`); a non-overlay block that collides with one fails with a clear error.

## Verification

`npm run verify:ghidra:raw` writes authored 6502 and MIPS R3000 flat fixtures and a banked 6502 v2 fixture (two overlay banks at `$8000` plus a fixed bank) (no ROMs, game data, or cross-compilers). It checks:

- admission rejections;
- decoding at the declared entry;
- decompilation;
- the profile in the evidence;
- CLI and MCP parity;
- unchanged source bytes;
- owned process cleanup.

It was verified on macOS arm64 with Ghidra 12.1.2 and JDK 21. Linux x64 and macOS x64 aren't verified yet.
