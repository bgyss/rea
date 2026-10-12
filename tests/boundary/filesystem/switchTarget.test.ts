import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const nso = (): Buffer => {
  const bytes = Buffer.alloc(0x200);
  bytes.write("NSO0", 0, "ascii");
  return bytes;
};
const nro = (): Buffer => {
  const bytes = Buffer.alloc(0x200);
  bytes.write("NRO0", 0x10, "ascii");
  return bytes;
};

const resolveWith = async (
  bytes: Buffer,
  options: Parameters<typeof parseBinaryTarget>[1],
) => {
  const directory = await createTestTempDirectory("rea-switch-target-");
  const path = join(directory, "main");
  await writeFile(path, bytes);
  return parseBinaryTarget(path, {
    cwd: directory,
    hostArchitecture: "arm64",
    ...options,
  });
};

describe("Switch executable admission", () => {
  it("admits an NSO0 header as an arm64 executable", async () => {
    const bytes = nso();
    expect(
      await resolveWith(bytes, { formatHint: "switch-nso" }),
    ).toMatchObject({
      ok: true,
      value: {
        kind: "executable",
        format: "switch-nso",
        architecture: "arm64",
        availableArchitectures: ["arm64"],
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
    });
  });

  it("admits an NRO0 header at offset 0x10", async () => {
    expect(
      await resolveWith(nro(), { formatHint: "switch-nro" }),
    ).toMatchObject({
      ok: true,
      value: { format: "switch-nro", architecture: "arm64" },
    });
  });

  it("does not infer a Switch format from the header alone", async () => {
    const detected = await resolveWith(nso(), {});
    expect(detected.ok && detected.value.format).not.toBe("switch-nso");
  });

  it("refuses a hint that does not match the header, naming the magic", async () => {
    const wrongKind = await resolveWith(nro(), { formatHint: "switch-nso" });
    expect(wrongKind.ok).toBe(false);
    expect(JSON.stringify(wrongKind)).toContain("NSO0");
    const empty = await resolveWith(Buffer.alloc(0x200), {
      formatHint: "switch-nro",
    });
    expect(empty.ok).toBe(false);
    expect(JSON.stringify(empty)).toContain("NRO0");
  });

  it("refuses a file too short to hold the header", async () => {
    const tiny = await resolveWith(Buffer.from("NSO0"), {
      formatHint: "switch-nso",
    });
    expect(tiny).toMatchObject({
      ok: false,
      error: { _tag: "BinaryTargetError" },
    });
  });

  it("rejects architecture and entry_point with a Switch format", async () => {
    expect(
      await resolveWith(nso(), {
        formatHint: "switch-nso",
        architecture: "arm64",
        entryPoint: "0x1000",
      }),
    ).toMatchObject({ ok: false, error: { _tag: "BinaryTargetError" } });
  });

  it("rejects a contradictory target kind", async () => {
    expect(
      await resolveWith(nso(), {
        formatHint: "switch-nso",
        targetKind: "database",
      }),
    ).toMatchObject({ ok: false, error: { _tag: "BinaryTargetError" } });
  });
});
