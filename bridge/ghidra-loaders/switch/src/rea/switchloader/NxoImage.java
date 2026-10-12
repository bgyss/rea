package rea.switchloader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Parsed NSO0 or NRO0 image: segments placed relative to the image base. */
final class NxoImage {
    enum Kind { NSO, NRO }

    record Segment(String name, long offset, byte[] bytes, boolean write, boolean execute) {
    }

    /** Admission bound for any one segment (not a target limit). */
    static final long MAX_SEGMENT_BYTES = 256L * 1024 * 1024;
    /**
     * Admission bound for the memory one image may claim: every decoded segment
     * plus bss. Declared sizes are checked against it before anything is allocated.
     */
    static final long MAX_IMAGE_BYTES = 512L * 1024 * 1024;
    /** LZ4 cannot expand a block beyond about 255:1; the slack covers tiny blocks. */
    private static final long LZ4_MAX_RATIO = 255;
    private static final long LZ4_RATIO_SLACK = 64;

    final Kind kind;
    final List<Segment> segments;
    final long entryOffset;
    final long bssOffset;
    final long bssSize;
    final long modOffset;
    final long dynamicOffset;

    private NxoImage(Kind kind, List<Segment> segments, long entryOffset, long bssOffset, long bssSize,
        long modOffset, long dynamicOffset) {
        this.kind = kind;
        this.segments = List.copyOf(segments);
        this.entryOffset = entryOffset;
        this.bssOffset = bssOffset;
        this.bssSize = bssSize;
        this.modOffset = modOffset;
        this.dynamicOffset = dynamicOffset;
    }

    private static final String[] NAMES = {".text", ".rodata", ".data"};

    static NxoImage parse(byte[] file) {
        ByteBuffer buffer = ByteBuffer.wrap(file).order(ByteOrder.LITTLE_ENDIAN);
        if (file.length >= 0x100 && magic(buffer, 0, "NSO0")) {
            return parseNso(file, buffer);
        }
        if (file.length >= 0x80 && magic(buffer, 0x10, "NRO0")) {
            return parseNro(file, buffer);
        }
        throw new IllegalArgumentException("not an NSO0 or NRO0 image");
    }

    private static boolean magic(ByteBuffer buffer, int at, String text) {
        for (int i = 0; i < 4; i++) {
            if (buffer.get(at + i) != (byte) text.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static long u32(ByteBuffer buffer, int at) {
        return Integer.toUnsignedLong(buffer.getInt(at));
    }

    private static NxoImage parseNso(byte[] file, ByteBuffer buffer) {
        long flags = u32(buffer, 0x0c);
        long bssSize = u32(buffer, 0x3c);
        long[] fileOffsets = new long[3];
        long[] memoryOffsets = new long[3];
        long[] sizes = new long[3];
        long[] lengths = new long[3];
        boolean[] compressed = new boolean[3];
        // Validate every declared size before decoding or allocating anything.
        long claimed = bssSize;
        long previousEnd = 0;
        for (int i = 0; i < 3; i++) {
            int record = 0x10 + 0x10 * i;
            fileOffsets[i] = u32(buffer, record);
            memoryOffsets[i] = u32(buffer, record + 4);
            sizes[i] = u32(buffer, record + 8);
            compressed[i] = ((flags >>> i) & 1) != 0;
            lengths[i] = compressed[i] ? u32(buffer, 0x60 + 4 * i) : sizes[i];
            if (sizes[i] > MAX_SEGMENT_BYTES || lengths[i] > MAX_SEGMENT_BYTES) {
                throw new IllegalArgumentException("NSO segment " + NAMES[i] + " exceeds the admitted size");
            }
            if (fileOffsets[i] < 0x100 || fileOffsets[i] + lengths[i] > file.length) {
                throw new IllegalArgumentException("NSO segment " + NAMES[i] + " lies outside the file");
            }
            if (memoryOffsets[i] < previousEnd) {
                throw new IllegalArgumentException("NSO segment " + NAMES[i] + " overlaps the previous segment");
            }
            if (compressed[i] && sizes[i] > lengths[i] * LZ4_MAX_RATIO + LZ4_RATIO_SLACK) {
                throw new IllegalArgumentException(
                    "NSO segment " + NAMES[i] + " expands beyond LZ4's maximum ratio");
            }
            previousEnd = memoryOffsets[i] + sizes[i];
            claimed += sizes[i];
        }
        if (bssSize > MAX_SEGMENT_BYTES) {
            throw new IllegalArgumentException("NSO bss exceeds the admitted size");
        }
        if (claimed > MAX_IMAGE_BYTES) {
            throw new IllegalArgumentException("NSO image exceeds the admitted memory budget");
        }
        List<Segment> segments = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            byte[] bytes = compressed[i]
                ? Lz4Block.decode(file, (int) fileOffsets[i], (int) lengths[i], (int) sizes[i])
                : Arrays.copyOfRange(file, (int) fileOffsets[i], (int) (fileOffsets[i] + lengths[i]));
            segments.add(new Segment(NAMES[i], memoryOffsets[i], bytes, i == 2, i == 0));
        }
        Segment text = segments.get(0);
        long modOffset = -1;
        long dynamicOffset = -1;
        if (text.bytes().length >= 8) {
            long candidate = u32(ByteBuffer.wrap(text.bytes()).order(ByteOrder.LITTLE_ENDIAN), 4);
            long[] mod = readMod(segments, text.offset() + candidate);
            if (mod != null) {
                modOffset = text.offset() + candidate;
                dynamicOffset = modOffset + mod[0];
            }
        }
        Segment data = segments.get(2);
        return new NxoImage(Kind.NSO, segments, text.offset(), data.offset() + data.bytes().length, bssSize,
            modOffset, dynamicOffset);
    }

    private static NxoImage parseNro(byte[] file, ByteBuffer buffer) {
        long fileSize = u32(buffer, 0x18);
        if (fileSize > file.length || fileSize > MAX_SEGMENT_BYTES) {
            throw new IllegalArgumentException("NRO file_size exceeds the file");
        }
        List<Segment> segments = new ArrayList<>();
        long previousEnd = 0;
        for (int i = 0; i < 3; i++) {
            long offset = u32(buffer, 0x20 + 8 * i);
            long size = u32(buffer, 0x24 + 8 * i);
            if (offset + size > fileSize) {
                throw new IllegalArgumentException("NRO segment " + NAMES[i] + " lies outside the file");
            }
            if (offset < previousEnd) {
                throw new IllegalArgumentException("NRO segment " + NAMES[i] + " overlaps the previous segment");
            }
            segments.add(new Segment(NAMES[i], offset, Arrays.copyOfRange(file, (int) offset,
                (int) (offset + size)), i == 2, i == 0));
            previousEnd = offset + size;
        }
        long bssSize = u32(buffer, 0x38);
        long modOffset = -1;
        long dynamicOffset = -1;
        long candidate = u32(buffer, 0x04);
        long[] mod = readMod(segments, candidate);
        if (mod != null) {
            modOffset = candidate;
            dynamicOffset = candidate + mod[0];
            if (mod[2] >= mod[1]) {
                bssSize = mod[2] - mod[1];
            }
        }
        if (bssSize > MAX_SEGMENT_BYTES) {
            throw new IllegalArgumentException("NRO bss exceeds the admitted size");
        }
        Segment data = segments.get(2);
        return new NxoImage(Kind.NRO, segments, segments.get(0).offset(), data.offset() + data.bytes().length,
            bssSize, modOffset, dynamicOffset);
    }

    /** {dynamic, bss_start, bss_end} of a MOD0 header at an image offset, or null if absent. */
    private static long[] readMod(List<Segment> segments, long at) {
        for (Segment segment : segments) {
            long start = segment.offset();
            long end = start + segment.bytes().length;
            if (at >= start && at + 0x1c <= end) {
                ByteBuffer view = ByteBuffer.wrap(segment.bytes()).order(ByteOrder.LITTLE_ENDIAN);
                int base = (int) (at - start);
                if (magic(view, base, "MOD0")) {
                    return new long[] {u32(view, base + 4), u32(view, base + 8), u32(view, base + 12)};
                }
                return null;
            }
        }
        return null;
    }
}
