// Authored NSO and NRO fixtures: AArch64 `nop; ret`, no game data.
export const FIXTURE_IMAGE_BASE = 0x7100000000n;
export const RODATA_TEXT = "abcdabcdabcdwxyz!";
// LZ4 block for RODATA_TEXT: "abcd" literals, a match (offset 4, length 8),
// then the 5 trailing literals "wxyz!".
export const LZ4_RODATA = Buffer.from([
  0x44, 0x61, 0x62, 0x63, 0x64, 0x04, 0x00, 0x50, 0x77, 0x78, 0x79, 0x7a, 0x21,
]);
export const TEXT = Buffer.from([
  0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6,
]);
export const DATA = Buffer.from([1, 2, 3, 4]);

/** NSO0 with plain text and data; rodata is LZ4-compressed when asked. */
export const buildNso = ({ compressRodata }) => {
  const rodata = Buffer.from(RODATA_TEXT, "ascii");
  const stored = compressRodata ? LZ4_RODATA : rodata;
  const header = Buffer.alloc(0x100);
  header.write("NSO0", 0, "ascii");
  header.writeUInt32LE(compressRodata ? 0b010 : 0, 0x0c);
  const fileOffset = [
    0x100,
    0x100 + TEXT.length,
    0x100 + TEXT.length + stored.length,
  ];
  const memory = [0, 0x1000, 0x2000];
  const size = [TEXT.length, rodata.length, DATA.length];
  const kept = [TEXT.length, stored.length, DATA.length];
  for (let i = 0; i < 3; i++) {
    const record = 0x10 + 0x10 * i;
    header.writeUInt32LE(fileOffset[i], record);
    header.writeUInt32LE(memory[i], record + 4);
    header.writeUInt32LE(size[i], record + 8);
    header.writeUInt32LE(kept[i], 0x60 + 4 * i);
  }
  header.writeUInt32LE(0x100, 0x3c); // bss size, in the data record
  return Buffer.concat([header, TEXT, stored, DATA]);
};

/** NRO0 mapped flat, with a MOD0 header whose bss range overrides the header's. */
export const buildNro = () => {
  const file = Buffer.alloc(0x300);
  file.writeUInt32LE(0x14000040, 0x00); // b +0x100, past MOD0, to the ret
  file.writeUInt32LE(0x80, 0x04); // module_header_offset
  file.write("NRO0", 0x10, "ascii");
  file.writeUInt32LE(0x300, 0x18);
  file.writeUInt32LE(0, 0x20);
  file.writeUInt32LE(0x200, 0x24); // text spans the header and MOD0
  file.writeUInt32LE(0x200, 0x28);
  file.writeUInt32LE(0x80, 0x2c); // rodata
  file.writeUInt32LE(0x280, 0x30);
  file.writeUInt32LE(0x80, 0x34); // data
  file.writeUInt32LE(0x40, 0x38); // header bss size, overridden by MOD0
  file.write("MOD0", 0x80, "ascii");
  file.writeUInt32LE(0x140, 0x84); // dynamic, relative to MOD0
  file.writeUInt32LE(0x200, 0x88); // bss_start
  file.writeUInt32LE(0x2c0, 0x8c); // bss_end: size 0xc0
  TEXT.copy(file, 0x100);
  return file;
};
