import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/** Seed the caller-declared raw-image entry point before default auto-analysis. */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || !args[0].matches("0x[0-9a-f]+")) {
            throw new IllegalArgumentException("raw-image preparation requires one 0x-prefixed entry address");
        }
        if (!currentProgram.getExecutableFormat().equals("Raw Binary")) {
            throw new IllegalArgumentException("raw-image preparation requires a BinaryLoader import");
        }
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(args[0].substring(2), 16));
        if (currentProgram.getMemory().getBlock(entry) == null) {
            throw new IllegalArgumentException("raw-image entry " + args[0] + " lies outside the imported bytes");
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("raw-image entry " + args[0] + " cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw image prepared", true);
    }
}
