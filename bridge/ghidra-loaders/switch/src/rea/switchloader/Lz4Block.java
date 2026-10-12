package rea.switchloader;

/** Decoder for a single LZ4 block (the public block format). */
final class Lz4Block {
    private Lz4Block() {
    }

    /** Decode one block into exactly {@code outLength} bytes. */
    static byte[] decode(byte[] in, int inOffset, int inLength, int outLength) {
        if (inOffset < 0 || inLength < 0 || inOffset > in.length - inLength || outLength < 0) {
            throw new IllegalArgumentException("LZ4 input range is outside its buffer");
        }
        byte[] out = new byte[outLength];
        int ip = inOffset;
        int end = inOffset + inLength;
        int op = 0;
        while (ip < end) {
            int token = in[ip++] & 0xff;
            int literals = token >>> 4;
            if (literals == 15) {
                int extra;
                do {
                    extra = next(in, ip++, end);
                    literals += extra;
                    if (literals < 0 || literals > outLength) {
                        throw new IllegalArgumentException("LZ4 literal run exceeds the output size");
                    }
                } while (extra == 255);
            }
            if (literals > end - ip || literals > outLength - op) {
                throw new IllegalArgumentException("LZ4 literal run overruns its block");
            }
            System.arraycopy(in, ip, out, op, literals);
            ip += literals;
            op += literals;
            if (ip == end) {
                break;
            }
            if (end - ip < 2) {
                throw new IllegalArgumentException("LZ4 match offset is truncated");
            }
            int offset = (in[ip] & 0xff) | ((in[ip + 1] & 0xff) << 8);
            ip += 2;
            if (offset == 0 || offset > op) {
                throw new IllegalArgumentException("LZ4 match offset points before the output");
            }
            int match = token & 0x0f;
            if (match == 15) {
                int extra;
                do {
                    extra = next(in, ip++, end);
                    match += extra;
                    if (match < 0 || match > outLength) {
                        throw new IllegalArgumentException("LZ4 match length exceeds the output size");
                    }
                } while (extra == 255);
            }
            match += 4;
            if (match > outLength - op) {
                throw new IllegalArgumentException("LZ4 match overruns the output");
            }
            for (int i = 0; i < match; i++) {
                out[op] = out[op - offset];
                op++;
            }
        }
        if (op != outLength) {
            throw new IllegalArgumentException("LZ4 block decoded to " + op + " bytes, expected " + outLength);
        }
        return out;
    }

    private static int next(byte[] in, int index, int end) {
        if (index >= end) {
            throw new IllegalArgumentException("LZ4 length runs past its block");
        }
        return in[index] & 0xff;
    }
}
