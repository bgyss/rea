import type { LabelPack } from "../nativeAnnotationSets.js";

const register = (address: number, label: string, comment: string) => ({
  address: `0x${address.toString(16)}`,
  label,
  data_type: "byte",
  comment,
});

/** NES (Ricoh 2C02 PPU and 2A03 APU/IO) memory-mapped registers. */
export const NES_REGISTERS_PACK: LabelPack = {
  schema_version: "rea.label-pack.v1",
  id: "nes-registers",
  version: 1,
  title: "NES PPU, APU and I/O registers",
  platform: "nes",
  sources: [
    "https://www.nesdev.org/wiki/PPU_registers",
    "https://www.nesdev.org/wiki/APU_registers",
    "https://www.nesdev.org/wiki/2A03",
  ],
  limitations: [
    "Labels the canonical register addresses only: the PPU mirrors at $2008-$3FFF and the CPU test registers at $4018-$401F are not labelled.",
    "$4017 is the second controller port on read and the APU frame counter on write; one label cannot name both.",
    "Mapper registers are cartridge-specific and are not included.",
  ],
  annotations: {
    processors: ["6502"],
    memory_blocks: [
      { name: "PPU_REGS", address: "0x2000", size_bytes: 8, volatile: true },
      {
        name: "APU_IO_REGS",
        address: "0x4000",
        size_bytes: 0x18,
        volatile: true,
      },
    ],
    data: [
      register(
        0x2000,
        "PPUCTRL",
        "PPU control: NMI enable, sprite size, pattern tables, nametable select (write)",
      ),
      register(
        0x2001,
        "PPUMASK",
        "PPU mask: colour emphasis, sprite and background enable (write)",
      ),
      register(
        0x2002,
        "PPUSTATUS",
        "PPU status: vblank, sprite 0 hit, sprite overflow; reading clears the address latch (read)",
      ),
      register(0x2003, "OAMADDR", "OAM address (write)"),
      register(0x2004, "OAMDATA", "OAM data (read/write)"),
      register(0x2005, "PPUSCROLL", "Scroll position, X then Y (write twice)"),
      register(
        0x2006,
        "PPUADDR",
        "VRAM address, high byte then low (write twice)",
      ),
      register(0x2007, "PPUDATA", "VRAM data (read/write)"),
      register(0x4000, "SQ1_VOL", "Pulse 1 duty, envelope and volume"),
      register(0x4001, "SQ1_SWEEP", "Pulse 1 sweep unit"),
      register(0x4002, "SQ1_LO", "Pulse 1 timer low"),
      register(0x4003, "SQ1_HI", "Pulse 1 length counter load and timer high"),
      register(0x4004, "SQ2_VOL", "Pulse 2 duty, envelope and volume"),
      register(0x4005, "SQ2_SWEEP", "Pulse 2 sweep unit"),
      register(0x4006, "SQ2_LO", "Pulse 2 timer low"),
      register(0x4007, "SQ2_HI", "Pulse 2 length counter load and timer high"),
      register(0x4008, "TRI_LINEAR", "Triangle linear counter"),
      register(0x400a, "TRI_LO", "Triangle timer low"),
      register(0x400b, "TRI_HI", "Triangle length counter load and timer high"),
      register(0x400c, "NOISE_VOL", "Noise envelope and volume"),
      register(0x400e, "NOISE_LO", "Noise mode and period"),
      register(0x400f, "NOISE_HI", "Noise length counter load"),
      register(0x4010, "DMC_FREQ", "DMC IRQ enable, loop and frequency"),
      register(0x4011, "DMC_RAW", "DMC direct load (7-bit output level)"),
      register(0x4012, "DMC_START", "DMC sample address: $C000 + value * 64"),
      register(0x4013, "DMC_LEN", "DMC sample length: value * 16 + 1 bytes"),
      register(
        0x4014,
        "OAMDMA",
        "Sprite DMA: copies page $XX00-$XXFF to OAM (write)",
      ),
      register(
        0x4015,
        "SND_CHN",
        "APU channel enable (write) and status (read)",
      ),
      register(
        0x4016,
        "JOY1",
        "Controller strobe (write) and controller 1 data (read)",
      ),
      register(
        0x4017,
        "JOY2",
        "Controller 2 data (read); APU frame counter mode and IRQ inhibit (write)",
      ),
    ],
  },
};
