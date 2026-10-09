import { err, ok, type Result } from "./result.js";

/** DOS load-module coordinates before applying the loader's segment relocation. */
export interface DosMzHeader {
  readonly headerBytes: number;
  readonly imageBytes: number;
  readonly moduleBytes: number;
  readonly overlayBytes: number;
  readonly relocationCount: number;
  readonly relocationTableOffset: number;
  readonly entrySegment: number;
  readonly entryOffset: number;
}

/**
 * Locate a Windows new-header declaration without interpreting a short DOS
 * header's load-module or relocation-table bytes at 0x3c as e_lfanew. A
 * new-header pointer must lie in a sufficiently large header and outside
 * actual relocation records. Zero-sized legacy stubs remain eligible for
 * PE signature validation.
 */
export const mzWindowsHeaderOffset = (bytes: Buffer): number | null => {
  if (bytes.length < 64) return null;
  const headerBytes = bytes.readUInt16LE(8) * 16;
  if (headerBytes !== 0 && headerBytes < 64) return null;
  const relocationCount = bytes.readUInt16LE(6);
  const tableStart = bytes.readUInt16LE(24);
  if (
    headerBytes !== 0 &&
    relocationCount > 0 &&
    tableStart < 64 &&
    tableStart + relocationCount * 4 > 60
  )
    return null;
  const offset = bytes.readUInt32LE(60);
  return offset === 0 ? null : offset;
};

/**
 * Validate a DOS MZ load module using a bounded header/table and the actual
 * file length. Appended overlay bytes are retained separately; they are not
 * silently included in the initialized load module.
 */
export const parseDosMzHeader = (
  bytes: Buffer,
  fileSize = bytes.length,
): Result<DosMzHeader, string> => {
  if (bytes.length < 28 || bytes.toString("ascii", 0, 2) !== "MZ")
    return err("invalid or truncated DOS MZ header");
  if (!Number.isSafeInteger(fileSize) || fileSize < bytes.length)
    return err("invalid DOS MZ file length");
  if (mzWindowsHeaderOffset(bytes) !== null)
    return err("MZ declares a Windows new header; it is not a DOS-only image");
  const lastPageBytes = bytes.readUInt16LE(2);
  const pages = bytes.readUInt16LE(4);
  if (pages === 0 || lastPageBytes > 511)
    return err("invalid DOS MZ page count or final-page size");
  const imageBytes =
    (pages - 1) * 512 + (lastPageBytes === 0 ? 512 : lastPageBytes);
  const headerBytes = bytes.readUInt16LE(8) * 16;
  if (headerBytes < 28 || headerBytes >= imageBytes)
    return err("invalid DOS MZ header size or empty load module");
  if (imageBytes > fileSize) return err("truncated DOS MZ load module");
  const relocationCount = bytes.readUInt16LE(6);
  const relocationTableOffset = bytes.readUInt16LE(24);
  const tableEnd = relocationTableOffset + relocationCount * 4;
  if (
    relocationCount > 0 &&
    (relocationTableOffset < 28 || tableEnd > headerBytes)
  )
    return err("DOS MZ relocation table lies outside its header");
  if (relocationCount > 0 && tableEnd > bytes.length)
    return err("truncated DOS MZ relocation table");
  const moduleBytes = imageBytes - headerBytes;
  const relocations = validateRelocations(
    bytes,
    relocationTableOffset,
    relocationCount,
    moduleBytes,
  );
  if (!relocations.ok) return relocations;
  const entryOffset = bytes.readUInt16LE(20);
  const entrySegment = bytes.readUInt16LE(22);
  if (entrySegment * 16 + entryOffset >= moduleBytes)
    return err("DOS MZ entry point lies outside its initialized load module");
  return ok({
    headerBytes,
    imageBytes,
    moduleBytes,
    overlayBytes: fileSize - imageBytes,
    relocationCount,
    relocationTableOffset,
    entrySegment,
    entryOffset,
  });
};

/** A linear-executable program bound into a DOS MZ file's appended overlay. */
export interface BoundLinearExecutable {
  readonly signature: "LE" | "LX";
  /** File offset of the embedded MZ stub that declares the linear header. */
  readonly stubOffset: number;
  /** File offset of the LE/LX header. */
  readonly headerOffset: number;
}

const LINEAR_HEADER_PROBE_BYTES = 12;

/**
 * Find a linear executable bound after a DOS-extender load module, such as a
 * DOS/4GW-bound Watcom program. Binders append the 32-bit program as an
 * embedded MZ stub whose e_lfanew, relative to that stub, selects an LE/LX
 * header. The outer load module is the extender itself, so analyzing it as
 * the program would silently describe the wrong code. `overlay` holds the
 * file bytes beginning at `overlayOffset`.
 */
export const findBoundLinearExecutable = (
  overlay: Buffer,
  overlayOffset: number,
): BoundLinearExecutable | null => {
  for (let stub = 0; stub + 64 <= overlay.length; stub += 1) {
    if (overlay[stub] !== 0x4d || overlay[stub + 1] !== 0x5a) continue;
    if (overlay.readUInt16LE(stub + 8) * 16 < 64) continue;
    const relative = overlay.readUInt32LE(stub + 60);
    const header = stub + relative;
    if (relative < 64 || header + LINEAR_HEADER_PROBE_BYTES > overlay.length)
      continue;
    const signature = overlay.toString("ascii", header, header + 2);
    if (signature !== "LE" && signature !== "LX") continue;
    if (!plausibleLinearHeader(overlay, header)) continue;
    return {
      signature,
      stubOffset: overlayOffset + stub,
      headerOffset: overlayOffset + header,
    };
  }
  return null;
};

/** Byte/word order, format level, CPU and OS fields of an LE/LX header. */
const plausibleLinearHeader = (bytes: Buffer, header: number): boolean => {
  const byteOrder = bytes[header + 2] ?? 0xff;
  const wordOrder = bytes[header + 3] ?? 0xff;
  const cpu = bytes.readUInt16LE(header + 8);
  const os = bytes.readUInt16LE(header + 10);
  return (
    byteOrder <= 1 &&
    wordOrder <= 1 &&
    bytes.readUInt32LE(header + 4) === 0 &&
    cpu >= 1 &&
    cpu <= 0x42 &&
    os <= 4
  );
};

const validateRelocations = (
  bytes: Buffer,
  relocationTableOffset: number,
  relocationCount: number,
  moduleBytes: number,
): Result<void, string> => {
  for (let index = 0; index < relocationCount; index += 1) {
    const record = relocationTableOffset + index * 4;
    const offset = bytes.readUInt16LE(record);
    const segment = bytes.readUInt16LE(record + 2);
    if (segment * 16 + offset + 2 > moduleBytes)
      return err(`DOS MZ relocation ${index} points outside its load module`);
  }
  return ok(undefined);
};
