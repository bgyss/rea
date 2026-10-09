import { describe, expect, it } from "vitest";

import { parseConfig } from "../config.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "./HopperProvider.js";

describe("Hopper provider capabilities", () => {
  it("declines DOS MZ targets with a provider-specific support reason", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger);
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/legacy.exe",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });

  it("declines raw images whose processor is a caller declaration", () => {
    const config = parseConfig({});
    if (!config.ok) throw new Error("expected valid configuration");
    const provider = new HopperProvider(config.value, silentLogger);
    expect(
      provider.inspectTargetSupport({
        path: "/tmp/prg.bin",
        sha256: "a".repeat(64),
        kind: "executable",
        format: "raw-image",
        rawImage: {
          schema_version: "dcomp.ghidra-profile.v1",
          profile_id: "nes",
          platform: "nes",
          processor_language_id: "6502:LE:16:default",
          compiler_spec_id: "default",
          loader: "BinaryLoader",
          load_address: 0x8000,
          entry_address: 0x8000,
          analysis_timeout_seconds: 1,
          max_instruction_facts: 1,
        },
      }),
    ).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("Ghidra"),
    });
  });
});
