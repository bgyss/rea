import type { LabelPack } from "../nativeAnnotationSets.js";

type Width = "byte" | "word" | "dword";

const register = (
  address: number,
  label: string,
  data_type: Width,
  comment: string,
) => ({
  address: `0x${address.toString(16)}`,
  label,
  data_type,
  comment,
});

const IO = 0x1f801000;

const DMA_CHANNELS = [
  "MDEC_IN",
  "MDEC_OUT",
  "GPU",
  "CDROM",
  "SPU",
  "PIO",
  "OTC",
] as const;

const dmaRegisters = DMA_CHANNELS.flatMap((channel, index) => {
  const base = IO + 0x80 + index * 0x10;
  return [
    register(
      base,
      `DMA${index}_MADR`,
      "dword",
      `DMA channel ${index} (${channel}) base address`,
    ),
    register(
      base + 4,
      `DMA${index}_BCR`,
      "dword",
      `DMA channel ${index} (${channel}) block control`,
    ),
    register(
      base + 8,
      `DMA${index}_CHCR`,
      "dword",
      `DMA channel ${index} (${channel}) channel control`,
    ),
  ];
});

const timerRegisters = [0, 1, 2].flatMap((timer) => {
  const base = IO + 0x100 + timer * 0x10;
  return [
    register(
      base,
      `T${timer}_COUNT`,
      "dword",
      `Timer ${timer} current counter value`,
    ),
    register(
      base + 4,
      `T${timer}_MODE`,
      "dword",
      `Timer ${timer} counter mode`,
    ),
    register(
      base + 8,
      `T${timer}_TARGET`,
      "dword",
      `Timer ${timer} counter target value`,
    ),
  ];
});

const voiceRegisters = Array.from({ length: 24 }, (_, voice) => {
  const base = IO + 0xc00 + voice * 0x10;
  const name = `SPU_VOICE${voice}`;
  return [
    register(base, `${name}_VOL_L`, "word", `SPU voice ${voice} volume left`),
    register(
      base + 2,
      `${name}_VOL_R`,
      "word",
      `SPU voice ${voice} volume right`,
    ),
    register(
      base + 4,
      `${name}_PITCH`,
      "word",
      `SPU voice ${voice} ADPCM sample rate`,
    ),
    register(
      base + 6,
      `${name}_START`,
      "word",
      `SPU voice ${voice} ADPCM start address`,
    ),
    register(
      base + 8,
      `${name}_ADSR_LO`,
      "word",
      `SPU voice ${voice} ADSR attack, decay and sustain level`,
    ),
    register(
      base + 0xa,
      `${name}_ADSR_HI`,
      "word",
      `SPU voice ${voice} ADSR sustain and release`,
    ),
    register(
      base + 0xc,
      `${name}_ADSR_VOL`,
      "word",
      `SPU voice ${voice} current ADSR volume`,
    ),
    register(
      base + 0xe,
      `${name}_REPEAT`,
      "word",
      `SPU voice ${voice} ADPCM repeat address`,
    ),
  ];
}).flat();

/** PlayStation (PS1) scratchpad and I/O port registers at 0x1F80xxxx. */
export const PS1_REGISTERS_PACK: LabelPack = {
  schema_version: "rea.label-pack.v1",
  id: "ps1-registers",
  version: 1,
  title: "PlayStation I/O port registers",
  platform: "ps1",
  sources: ["https://psx-spx.consoledev.net/iomap/"],
  limitations: [
    "Labels the KUSEG addresses 0x1F800000-0x1F801FFF only; the KSEG0 and KSEG1 mirrors (0x9F80xxxx, 0xBF80xxxx) are not labelled.",
    "GPU, MDEC, CD-ROM and serial registers have different meanings on read and write; each label names one and the comment gives both.",
    "SPU reverb configuration (0x1F801DC0-0x1F801DFF), Expansion Region 2 and the cache control register are not included.",
  ],
  annotations: {
    processors: ["MIPS"],
    memory_blocks: [
      {
        name: "SCRATCHPAD",
        address: "0x1f800000",
        size_bytes: 0x400,
        volatile: false,
      },
      {
        name: "IO_PORTS",
        address: "0x1f801000",
        size_bytes: 0x1000,
        volatile: true,
      },
    ],
    data: [
      {
        address: "0x1f800000",
        label: "SCRATCHPAD",
        comment: "1 KiB data cache used as fast RAM",
      },
      register(IO + 0x00, "EXP1_BASE", "dword", "Expansion 1 base address"),
      register(IO + 0x04, "EXP2_BASE", "dword", "Expansion 2 base address"),
      register(IO + 0x08, "EXP1_DELAY", "dword", "Expansion 1 delay and size"),
      register(IO + 0x0c, "EXP3_DELAY", "dword", "Expansion 3 delay and size"),
      register(IO + 0x10, "BIOS_ROM_DELAY", "dword", "BIOS ROM delay and size"),
      register(IO + 0x14, "SPU_DELAY", "dword", "SPU delay and size"),
      register(IO + 0x18, "CDROM_DELAY", "dword", "CD-ROM delay and size"),
      register(IO + 0x1c, "EXP2_DELAY", "dword", "Expansion 2 delay and size"),
      register(IO + 0x20, "COM_DELAY", "dword", "Common delay"),
      register(
        IO + 0x40,
        "JOY_DATA",
        "dword",
        "Controller and memory card transmit (write) and receive (read) data",
      ),
      register(
        IO + 0x44,
        "JOY_STAT",
        "dword",
        "Controller and memory card status",
      ),
      register(
        IO + 0x48,
        "JOY_MODE",
        "word",
        "Controller and memory card mode",
      ),
      register(
        IO + 0x4a,
        "JOY_CTRL",
        "word",
        "Controller and memory card control",
      ),
      register(
        IO + 0x4e,
        "JOY_BAUD",
        "word",
        "Controller and memory card baud rate reload",
      ),
      register(
        IO + 0x50,
        "SIO_DATA",
        "dword",
        "Serial port transmit (write) and receive (read) data",
      ),
      register(IO + 0x54, "SIO_STAT", "dword", "Serial port status"),
      register(IO + 0x58, "SIO_MODE", "word", "Serial port mode"),
      register(IO + 0x5a, "SIO_CTRL", "word", "Serial port control"),
      register(IO + 0x5c, "SIO_MISC", "word", "Serial port internal register"),
      register(IO + 0x5e, "SIO_BAUD", "word", "Serial port baud rate reload"),
      register(IO + 0x60, "RAM_SIZE", "dword", "Main RAM size and timing"),
      register(
        IO + 0x70,
        "I_STAT",
        "dword",
        "Interrupt status; write 0 bits to acknowledge",
      ),
      register(IO + 0x74, "I_MASK", "dword", "Interrupt mask"),
      ...dmaRegisters,
      register(
        IO + 0xf0,
        "DPCR",
        "dword",
        "DMA control: channel priority and enable",
      ),
      register(IO + 0xf4, "DICR", "dword", "DMA interrupt control and flags"),
      ...timerRegisters,
      register(
        IO + 0x800,
        "CDROM_STATUS",
        "byte",
        "CD-ROM index and status (index register select)",
      ),
      register(
        IO + 0x801,
        "CDROM_REG1",
        "byte",
        "CD-ROM command (write) and response FIFO (read), by index",
      ),
      register(
        IO + 0x802,
        "CDROM_REG2",
        "byte",
        "CD-ROM parameter FIFO (write) and data FIFO (read), by index",
      ),
      register(
        IO + 0x803,
        "CDROM_REG3",
        "byte",
        "CD-ROM interrupt enable and flags, by index",
      ),
      register(
        IO + 0x810,
        "GPU_GP0",
        "dword",
        "GPU GP0 rendering commands (write) and GPUREAD (read)",
      ),
      register(
        IO + 0x814,
        "GPU_GP1",
        "dword",
        "GPU GP1 display control (write) and GPUSTAT (read)",
      ),
      register(
        IO + 0x820,
        "MDEC_DATA",
        "dword",
        "MDEC command and parameters (write) and data response (read)",
      ),
      register(
        IO + 0x824,
        "MDEC_CTRL",
        "dword",
        "MDEC control and reset (write) and status (read)",
      ),
      ...voiceRegisters,
      register(IO + 0xd80, "SPU_MAIN_VOL_L", "word", "SPU main volume left"),
      register(IO + 0xd82, "SPU_MAIN_VOL_R", "word", "SPU main volume right"),
      register(
        IO + 0xd84,
        "SPU_REVERB_VOL_L",
        "word",
        "SPU reverb output volume left",
      ),
      register(
        IO + 0xd86,
        "SPU_REVERB_VOL_R",
        "word",
        "SPU reverb output volume right",
      ),
      register(
        IO + 0xd88,
        "SPU_KEY_ON",
        "dword",
        "SPU voice key on (start attack)",
      ),
      register(
        IO + 0xd8c,
        "SPU_KEY_OFF",
        "dword",
        "SPU voice key off (start release)",
      ),
      register(
        IO + 0xd90,
        "SPU_PITCH_MOD",
        "dword",
        "SPU voice pitch modulation enable",
      ),
      register(
        IO + 0xd94,
        "SPU_NOISE_MODE",
        "dword",
        "SPU voice noise mode enable",
      ),
      register(
        IO + 0xd98,
        "SPU_REVERB_MODE",
        "dword",
        "SPU voice reverb enable",
      ),
      register(
        IO + 0xd9c,
        "SPU_ENDX",
        "dword",
        "SPU voice status: reached loop end",
      ),
      register(
        IO + 0xda2,
        "SPU_REVERB_START",
        "word",
        "SPU reverb work area start address",
      ),
      register(IO + 0xda4, "SPU_IRQ_ADDR", "word", "SPU sound RAM IRQ address"),
      register(
        IO + 0xda6,
        "SPU_TRANSFER_ADDR",
        "word",
        "SPU sound RAM data transfer address",
      ),
      register(
        IO + 0xda8,
        "SPU_TRANSFER_FIFO",
        "word",
        "SPU sound RAM data transfer FIFO",
      ),
      register(IO + 0xdaa, "SPU_CTRL", "word", "SPU control (SPUCNT)"),
      register(
        IO + 0xdac,
        "SPU_TRANSFER_CTRL",
        "word",
        "SPU sound RAM data transfer control",
      ),
      register(IO + 0xdae, "SPU_STAT", "word", "SPU status (SPUSTAT)"),
      register(
        IO + 0xdb0,
        "SPU_CD_VOL_L",
        "word",
        "SPU CD audio input volume left",
      ),
      register(
        IO + 0xdb2,
        "SPU_CD_VOL_R",
        "word",
        "SPU CD audio input volume right",
      ),
      register(
        IO + 0xdb4,
        "SPU_EXT_VOL_L",
        "word",
        "SPU external audio input volume left",
      ),
      register(
        IO + 0xdb6,
        "SPU_EXT_VOL_R",
        "word",
        "SPU external audio input volume right",
      ),
      register(
        IO + 0xdb8,
        "SPU_CUR_VOL_L",
        "word",
        "SPU current main volume left",
      ),
      register(
        IO + 0xdba,
        "SPU_CUR_VOL_R",
        "word",
        "SPU current main volume right",
      ),
    ],
  },
};
