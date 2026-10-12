package rea.switchloader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class NxoSelfTest {
    private static int checks = 0;

    public static void main(String[] args) {
        lz4Vector();
        lz4Overrun();
        nsoMixedCompression();
        nsoRejections();
        nsoExpansionBounds();
        nroWithMod();
        nroWithoutMod();
        System.out.println("NxoSelfTest ok: " + checks + " checks");
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(Runnable action, String message) {
        checks++;
        try {
            action.run();
        }
        catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void rejectsWith(Runnable action, String reason, String message) {
        checks++;
        try {
            action.run();
        }
        catch (IllegalArgumentException expected) {
            if (expected.getMessage() == null || !expected.getMessage().contains(reason)) {
                throw new AssertionError(message + ": refused for another reason: " + expected.getMessage());
            }
            return;
        }
        throw new AssertionError(message);
    }

    // "abcd" literals, a match (offset 4, length 8), then 5 trailing literals.
    static final byte[] LZ4 = {0x44, 'a', 'b', 'c', 'd', 0x04, 0x00, 0x50, 'w', 'x', 'y', 'z', '!'};
    static final String LZ4_TEXT = "abcdabcdabcdwxyz!";

    private static void lz4Vector() {
        byte[] out = Lz4Block.decode(LZ4, 0, LZ4.length, 17);
        check(new String(out, StandardCharsets.US_ASCII).equals(LZ4_TEXT), "lz4 vector");
    }

    private static void lz4Overrun() {
        rejects(() -> Lz4Block.decode(LZ4, 0, LZ4.length, 16), "output shorter than the block");
        rejects(() -> Lz4Block.decode(LZ4, 0, LZ4.length, 18), "output longer than the block");
        rejects(() -> Lz4Block.decode(new byte[] {0x40, 'a', 'b', 'c', 'd', 0x09, 0x00}, 0, 7, 8),
            "offset before the start of output");
        rejects(() -> Lz4Block.decode(new byte[] {(byte) 0xf0}, 0, 1, 4), "literal length runs past the block");
    }

    /** NSO: text and data stored plain, rodata optionally LZ4-compressed, bss after data. */
    static byte[] nso(boolean compressRodata) {
        byte[] text = {0x1f, 0x20, 0x03, (byte) 0xd5, (byte) 0xc0, 0x03, 0x5f, (byte) 0xd6}; // nop; ret
        byte[] rodata = LZ4_TEXT.getBytes(StandardCharsets.US_ASCII);
        byte[] data = {1, 2, 3, 4};
        byte[] rodataStored = compressRodata ? LZ4 : rodata;
        ByteBuffer file = ByteBuffer.allocate(0x100 + text.length + rodataStored.length + data.length)
            .order(ByteOrder.LITTLE_ENDIAN);
        file.put(new byte[] {'N', 'S', 'O', '0'});
        file.putInt(4, 0).putInt(8, 0);
        file.putInt(0x0c, compressRodata ? 0b010 : 0);
        int at = 0x100;
        int[] fileOffset = {at, at + text.length, at + text.length + rodataStored.length};
        int[] memory = {0, 0x1000, 0x2000};
        int[] size = {text.length, rodata.length, data.length};
        int[] stored = {text.length, rodataStored.length, data.length};
        for (int i = 0; i < 3; i++) {
            int record = 0x10 + 0x10 * i;
            file.putInt(record, fileOffset[i]).putInt(record + 4, memory[i]).putInt(record + 8, size[i]);
            file.putInt(0x60 + 4 * i, stored[i]);
        }
        file.putInt(0x3c, 0x100); // bss size, in the data record
        file.position(0x100);
        file.put(text).put(rodataStored).put(data);
        return file.array();
    }

    private static void nsoMixedCompression() {
        for (boolean compressed : new boolean[] {false, true}) {
            NxoImage image = NxoImage.parse(nso(compressed));
            check(image.kind == NxoImage.Kind.NSO, "kind");
            check(image.segments.size() == 3, "three segments");
            check(image.segments.get(0).name().equals(".text") && image.segments.get(0).offset() == 0
                && image.segments.get(0).execute() && !image.segments.get(0).write(), "text");
            check(image.segments.get(1).name().equals(".rodata") && image.segments.get(1).offset() == 0x1000
                && new String(image.segments.get(1).bytes(), StandardCharsets.US_ASCII).equals(LZ4_TEXT),
                "rodata decoded (compressed=" + compressed + ")");
            check(image.segments.get(2).name().equals(".data") && image.segments.get(2).write(), "data");
            check(image.bssOffset == 0x2004 && image.bssSize == 0x100, "bss follows data");
            check(image.entryOffset == 0, "entry is the start of text");
        }
    }

    private static void nsoRejections() {
        byte[] good = nso(true);
        byte[] badMagic = good.clone();
        badMagic[0] = 'X';
        rejects(() -> NxoImage.parse(badMagic), "bad magic");
        rejects(() -> NxoImage.parse(java.util.Arrays.copyOf(good, 0x80)), "truncated header");
        rejects(() -> NxoImage.parse(java.util.Arrays.copyOf(good, good.length - 2)), "truncated segment data");
        byte[] huge = good.clone();
        ByteBuffer.wrap(huge).order(ByteOrder.LITTLE_ENDIAN).putInt(0x18, 0x7fffffff); // text size
        rejects(() -> NxoImage.parse(huge), "segment larger than the admitted bound");
        byte[] overlap = good.clone();
        ByteBuffer.wrap(overlap).order(ByteOrder.LITTLE_ENDIAN).putInt(0x24, 0); // rodata memory offset onto text
        rejects(() -> NxoImage.parse(overlap), "overlapping segments");
    }

    /**
     * An NSO whose three segments are all LZ4-compressed, with the given declared
     * sizes and stored blocks. The stored bytes are not required to be valid LZ4:
     * a header that claims more than the format or the budget allows is refused
     * before any block is decoded or any output buffer is allocated.
     */
    static byte[] compressedNso(long[] declared, byte[][] stored, long bss) {
        int total = 0x100;
        for (byte[] block : stored) total += block.length;
        ByteBuffer file = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        file.put(new byte[] {'N', 'S', 'O', '0'});
        file.putInt(0x0c, 0b111);
        int at = 0x100;
        for (int i = 0; i < 3; i++) {
            int record = 0x10 + 0x10 * i;
            file.putInt(record, at).putInt(record + 4, i * 0x10000000);
            file.putInt(record + 8, (int) declared[i]);
            file.putInt(0x60 + 4 * i, stored[i].length);
            file.position(at);
            file.put(stored[i]);
            at += stored[i].length;
        }
        file.putInt(0x3c, (int) bss);
        return file.array();
    }

    private static void nsoExpansionBounds() {
        byte[][] vector = {LZ4, LZ4, LZ4};
        byte[] ok = compressedNso(new long[] {17, 17, 17}, vector, 0);
        check(NxoImage.parse(ok).segments.size() == 3, "a plausible compressed header still parses");
        // 13 stored bytes cannot expand to 1 MiB: refused before a 1 MiB buffer exists.
        rejectsWith(() -> NxoImage.parse(compressedNso(new long[] {1 << 20, 17, 17}, vector, 0)),
            "maximum ratio", "declared size beyond LZ4's expansion ratio");
        // Nothing stored cannot expand to anything.
        rejectsWith(() -> NxoImage.parse(compressedNso(new long[] {17, 17, 4096},
            new byte[][] {LZ4, LZ4, new byte[0]}, 0)), "maximum ratio", "empty block with a declared size");
        // Each segment passes the ratio (200 MiB from 1 MiB), but together they exceed the budget.
        byte[] megabyte = new byte[1 << 20];
        long twoHundredMiB = 200L << 20;
        rejectsWith(() -> NxoImage.parse(compressedNso(new long[] {twoHundredMiB, twoHundredMiB, twoHundredMiB},
            new byte[][] {megabyte, megabyte, megabyte}, 0)), "memory budget", "segments beyond the image budget");
        // bss counts toward the same budget.
        rejectsWith(() -> NxoImage.parse(compressedNso(new long[] {twoHundredMiB, twoHundredMiB, 17},
            new byte[][] {megabyte, megabyte, LZ4}, 200L << 20)), "memory budget", "bss beyond the image budget");
    }

    /** NRO: mapped flat; MOD0 at 0x80 overrides bss. */
    static byte[] nro(boolean withMod) {
        int fileSize = 0x300;
        ByteBuffer file = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN);
        file.putInt(0x00, 0x14000020); // b +0x80
        file.putInt(0x04, 0x80);       // module_header_offset
        file.put(0x10, (byte) 'N').put(0x11, (byte) 'R').put(0x12, (byte) 'O').put(0x13, (byte) '0');
        file.putInt(0x18, fileSize);
        file.putInt(0x20, 0).putInt(0x24, 0x200);     // text: offset 0, size 0x200 (includes header and MOD0)
        file.putInt(0x28, 0x200).putInt(0x2c, 0x80);  // rodata
        file.putInt(0x30, 0x280).putInt(0x34, 0x80);  // data
        file.putInt(0x38, 0x40);                       // header bss size
        if (withMod) {
            file.put(0x80, (byte) 'M').put(0x81, (byte) 'O').put(0x82, (byte) 'D').put(0x83, (byte) '0');
            file.putInt(0x84, 0x140);  // dynamic, relative to MOD0
            file.putInt(0x88, 0x200);  // bss_start
            file.putInt(0x8c, 0x2c0);  // bss_end  -> size 0xc0
        }
        file.putInt(0x100, 0xd65f03c0); // ret at the _start target
        return file.array();
    }

    private static void nroWithMod() {
        NxoImage image = NxoImage.parse(nro(true));
        check(image.kind == NxoImage.Kind.NRO, "kind");
        check(image.segments.size() == 3, "three segments");
        check(image.segments.get(0).offset() == 0 && image.segments.get(0).bytes().length == 0x200, "text spans header");
        check(image.modOffset == 0x80, "MOD0 found");
        check(image.dynamicOffset == 0x80 + 0x140, "dynamic from MOD0");
        check(image.bssOffset == 0x300 && image.bssSize == 0xc0, "bss from MOD0, after data");
        check(image.entryOffset == 0, "entry at image start");
    }

    private static void nroWithoutMod() {
        NxoImage image = NxoImage.parse(nro(false));
        check(image.modOffset == -1 && image.dynamicOffset == -1, "no MOD0");
        check(image.bssSize == 0x40, "bss from header");
        byte[] outOfFile = nro(false);
        ByteBuffer.wrap(outOfFile).order(ByteOrder.LITTLE_ENDIAN).putInt(0x34, 0x1000); // data size past EOF
        rejects(() -> NxoImage.parse(outOfFile), "segment outside the file");
    }
}
