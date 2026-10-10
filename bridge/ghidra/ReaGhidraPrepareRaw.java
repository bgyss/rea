import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Prepare a raw image before default auto-analysis. A flat image (one
 * 0x-prefixed entry argument) seeds its entry. A mapped image (`map=<path>`)
 * replaces the one-byte import stub with the declared blocks, built from the
 * digest-verified source file; overlay blocks become their own address spaces.
 */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (!currentProgram.getExecutableFormat().equals("Raw Binary")) {
            throw new IllegalArgumentException("raw-image preparation requires a BinaryLoader import");
        }
        if (args.length == 1 && args[0].matches("0x[0-9a-f]+")) {
            prepareFlat(args[0]);
        }
        else if (args.length == 1 && args[0].startsWith("map=")) {
            prepareMapped(Path.of(args[0].substring(4)));
        }
        else {
            throw new IllegalArgumentException(
                "raw-image preparation requires a 0x-prefixed entry address or map=<path>");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw image prepared", true);
    }

    private void prepareFlat(String argument) throws Exception {
        Address entry = defaultSpace().getAddress(Long.parseUnsignedLong(argument.substring(2), 16));
        if (currentProgram.getMemory().getBlock(entry) == null) {
            throw new IllegalArgumentException("raw-image entry " + argument + " lies outside the imported bytes");
        }
        seed(entry, "entry");
    }

    private void prepareMapped(Path mapPath) throws Exception {
        JsonArray blocks = JsonParser.parseString(Files.readString(mapPath, StandardCharsets.UTF_8))
            .getAsJsonObject().getAsJsonArray("blocks");
        Memory memory = currentProgram.getMemory();
        Path source = Path.of(currentProgram.getExecutablePath());
        byte[] bytes = Files.readAllBytes(source);
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!digest.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("raw-image source bytes differ from the imported executable digest");
        }
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.getSourceInfos().isEmpty() && block.getSourceInfos().get(0).getFileBytes().isPresent()) {
                memory.removeBlock(block, monitor);
            }
        }
        FileBytes file;
        try (InputStream input = Files.newInputStream(source)) {
            file = memory.createFileBytes(source.getFileName().toString(), 0, bytes.length, input, monitor);
        }
        for (JsonElement element : blocks) {
            JsonObject spec = element.getAsJsonObject();
            String name = spec.get("name").getAsString();
            MemoryBlock block;
            try {
                block = memory.createInitializedBlock(
                    name,
                    defaultSpace().getAddress(spec.get("load_address").getAsLong()),
                    file,
                    spec.get("file_offset").getAsLong(),
                    spec.get("length").getAsLong(),
                    spec.get("overlay").getAsBoolean());
            }
            catch (MemoryConflictException conflict) {
                throw new IllegalArgumentException(
                    "raw-image block " + name + " overlaps existing memory (" + conflict.getMessage() +
                    "); mark it overlay or move it", conflict);
            }
            String permissions = spec.get("permissions").getAsString();
            block.setRead(permissions.contains("r"));
            block.setWrite(permissions.contains("w"));
            block.setExecute(permissions.contains("x"));
            JsonArray entries = spec.getAsJsonArray("entry_addresses");
            for (JsonElement entry : entries) {
                Address address = block.getStart().getAddressSpace().getAddress(entry.getAsLong());
                seed(address, entries.size() == 1
                    ? name + "_entry"
                    : name + "_entry_" + Long.toHexString(entry.getAsLong()));
            }
        }
    }

    private void seed(Address entry, String name) throws Exception {
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, name) == null) {
            throw new IllegalStateException("raw-image entry " + entry + " cannot be decoded as a function");
        }
    }

    private AddressSpace defaultSpace() {
        return currentProgram.getAddressFactory().getDefaultAddressSpace();
    }
}
