package rea.switchloader;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

/** Loads Nintendo Switch NSO0 and NRO0 executables as AArch64 at a fixed image base. */
public final class ReaSwitchLoader extends AbstractProgramWrapperLoader {
    static final long IMAGE_BASE = 0x7100000000L;
    static final String LANGUAGE_ID = "AARCH64:LE:64:v8A";
    static final String COMPILER_SPEC_ID = "default";

    @Override
    public String getName() {
        return "Nintendo Switch NSO/NRO (REA)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        try {
            NxoImage.parse(read(provider));
        }
        catch (IllegalArgumentException notSwitch) {
            return List.of();
        }
        return List.of(new LoadSpec(this, IMAGE_BASE,
            new LanguageCompilerSpecPair(LANGUAGE_ID, COMPILER_SPEC_ID), true));
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
        throws CancelledException, IOException {
        NxoImage image;
        try {
            image = NxoImage.parse(read(settings.provider()));
        }
        catch (IllegalArgumentException invalid) {
            throw new IOException("Not a loadable Switch image: " + invalid.getMessage(), invalid);
        }
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Memory memory = program.getMemory();
        try {
            program.setImageBase(space.getAddress(IMAGE_BASE), true);
            for (NxoImage.Segment segment : image.segments) {
                if (segment.bytes().length == 0) {
                    continue;
                }
                MemoryBlock block = memory.createInitializedBlock(segment.name(),
                    space.getAddress(IMAGE_BASE + segment.offset()),
                    new ByteArrayInputStream(segment.bytes()), segment.bytes().length, settings.monitor(), false);
                block.setRead(true);
                block.setWrite(segment.write());
                block.setExecute(segment.execute());
            }
            if (image.bssSize > 0) {
                MemoryBlock bss = memory.createUninitializedBlock(".bss",
                    space.getAddress(IMAGE_BASE + image.bssOffset), image.bssSize, false);
                bss.setRead(true);
                bss.setWrite(true);
                bss.setExecute(false);
            }
            Address entry = space.getAddress(IMAGE_BASE + image.entryOffset);
            program.getSymbolTable().createLabel(entry, "entry", SourceType.IMPORTED);
            program.getSymbolTable().addExternalEntryPoint(entry);
            if (image.modOffset >= 0) {
                program.getSymbolTable().createLabel(space.getAddress(IMAGE_BASE + image.modOffset), "MOD0",
                    SourceType.IMPORTED);
                program.getSymbolTable().createLabel(space.getAddress(IMAGE_BASE + image.dynamicOffset),
                    "_DYNAMIC", SourceType.IMPORTED);
            }
        }
        catch (CancelledException cancelled) {
            throw cancelled;
        }
        catch (Exception failure) {
            throw new IOException("Could not map the Switch image: " + failure.getMessage(), failure);
        }
    }

    private static byte[] read(ByteProvider provider) throws IOException {
        long length = provider.length();
        if (length < 0x80 || length > NxoImage.MAX_SEGMENT_BYTES) {
            throw new IllegalArgumentException("size outside the admitted range");
        }
        return provider.readBytes(0, (int) length);
    }
}
