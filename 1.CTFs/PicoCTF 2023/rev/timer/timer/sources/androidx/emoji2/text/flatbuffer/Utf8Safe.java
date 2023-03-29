package androidx.emoji2.text.flatbuffer;

import androidx.emoji2.text.flatbuffer.Utf8;
import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class Utf8Safe extends Utf8 {
    private static int computeEncodedLength(CharSequence sequence) {
        int utf16Length = sequence.length();
        int utf8Length = utf16Length;
        int i = 0;
        while (i < utf16Length && sequence.charAt(i) < 128) {
            i++;
        }
        while (true) {
            if (i < utf16Length) {
                char c = sequence.charAt(i);
                if (c < 2048) {
                    utf8Length += (127 - c) >>> 31;
                    i++;
                } else {
                    utf8Length += encodedLengthGeneral(sequence, i);
                    break;
                }
            } else {
                break;
            }
        }
        if (utf8Length < utf16Length) {
            throw new IllegalArgumentException("UTF-8 length does not fit in int: " + (utf8Length + 4294967296L));
        }
        return utf8Length;
    }

    private static int encodedLengthGeneral(CharSequence sequence, int start) {
        int utf16Length = sequence.length();
        int utf8Length = 0;
        int i = start;
        while (i < utf16Length) {
            char c = sequence.charAt(i);
            if (c < 2048) {
                utf8Length += (127 - c) >>> 31;
            } else {
                utf8Length += 2;
                if (55296 <= c && c <= 57343) {
                    int cp = Character.codePointAt(sequence, i);
                    if (cp < 65536) {
                        throw new UnpairedSurrogateException(i, utf16Length);
                    }
                    i++;
                }
            }
            i++;
        }
        return utf8Length;
    }

    public static String decodeUtf8Array(byte[] bytes, int index, int size) {
        if ((index | size | ((bytes.length - index) - size)) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer length=%d, index=%d, size=%d", Integer.valueOf(bytes.length), Integer.valueOf(index), Integer.valueOf(size)));
        }
        int offset = index;
        int limit = offset + size;
        char[] resultArr = new char[size];
        int resultPos = 0;
        while (offset < limit) {
            byte b = bytes[offset];
            if (!Utf8.DecodeUtil.isOneByte(b)) {
                break;
            }
            offset++;
            Utf8.DecodeUtil.handleOneByte(b, resultArr, resultPos);
            resultPos++;
        }
        int resultPos2 = resultPos;
        while (offset < limit) {
            int offset2 = offset + 1;
            byte byte1 = bytes[offset];
            if (Utf8.DecodeUtil.isOneByte(byte1)) {
                int resultPos3 = resultPos2 + 1;
                Utf8.DecodeUtil.handleOneByte(byte1, resultArr, resultPos2);
                while (offset2 < limit) {
                    byte b2 = bytes[offset2];
                    if (!Utf8.DecodeUtil.isOneByte(b2)) {
                        break;
                    }
                    offset2++;
                    Utf8.DecodeUtil.handleOneByte(b2, resultArr, resultPos3);
                    resultPos3++;
                }
                offset = offset2;
                resultPos2 = resultPos3;
            } else if (Utf8.DecodeUtil.isTwoBytes(byte1)) {
                if (offset2 >= limit) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                Utf8.DecodeUtil.handleTwoBytes(byte1, bytes[offset2], resultArr, resultPos2);
                offset = offset2 + 1;
                resultPos2++;
            } else if (Utf8.DecodeUtil.isThreeBytes(byte1)) {
                if (offset2 >= limit - 1) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                int offset3 = offset2 + 1;
                Utf8.DecodeUtil.handleThreeBytes(byte1, bytes[offset2], bytes[offset3], resultArr, resultPos2);
                offset = offset3 + 1;
                resultPos2++;
            } else if (offset2 >= limit - 2) {
                throw new IllegalArgumentException("Invalid UTF-8");
            } else {
                int offset4 = offset2 + 1;
                byte b3 = bytes[offset2];
                int offset5 = offset4 + 1;
                Utf8.DecodeUtil.handleFourBytes(byte1, b3, bytes[offset4], bytes[offset5], resultArr, resultPos2);
                offset = offset5 + 1;
                resultPos2 = resultPos2 + 1 + 1;
            }
        }
        return new String(resultArr, 0, resultPos2);
    }

    public static String decodeUtf8Buffer(ByteBuffer buffer, int offset, int length) {
        if ((offset | length | ((buffer.limit() - offset) - length)) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer limit=%d, index=%d, limit=%d", Integer.valueOf(buffer.limit()), Integer.valueOf(offset), Integer.valueOf(length)));
        }
        int limit = offset + length;
        char[] resultArr = new char[length];
        int resultPos = 0;
        while (offset < limit) {
            byte b = buffer.get(offset);
            if (!Utf8.DecodeUtil.isOneByte(b)) {
                break;
            }
            offset++;
            Utf8.DecodeUtil.handleOneByte(b, resultArr, resultPos);
            resultPos++;
        }
        int resultPos2 = resultPos;
        while (offset < limit) {
            int offset2 = offset + 1;
            byte byte1 = buffer.get(offset);
            if (Utf8.DecodeUtil.isOneByte(byte1)) {
                int resultPos3 = resultPos2 + 1;
                Utf8.DecodeUtil.handleOneByte(byte1, resultArr, resultPos2);
                while (offset2 < limit) {
                    byte b2 = buffer.get(offset2);
                    if (!Utf8.DecodeUtil.isOneByte(b2)) {
                        break;
                    }
                    offset2++;
                    Utf8.DecodeUtil.handleOneByte(b2, resultArr, resultPos3);
                    resultPos3++;
                }
                offset = offset2;
                resultPos2 = resultPos3;
            } else if (Utf8.DecodeUtil.isTwoBytes(byte1)) {
                if (offset2 >= limit) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                Utf8.DecodeUtil.handleTwoBytes(byte1, buffer.get(offset2), resultArr, resultPos2);
                offset = offset2 + 1;
                resultPos2++;
            } else if (Utf8.DecodeUtil.isThreeBytes(byte1)) {
                if (offset2 >= limit - 1) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                int offset3 = offset2 + 1;
                Utf8.DecodeUtil.handleThreeBytes(byte1, buffer.get(offset2), buffer.get(offset3), resultArr, resultPos2);
                offset = offset3 + 1;
                resultPos2++;
            } else if (offset2 >= limit - 2) {
                throw new IllegalArgumentException("Invalid UTF-8");
            } else {
                int offset4 = offset2 + 1;
                byte b3 = buffer.get(offset2);
                int offset5 = offset4 + 1;
                Utf8.DecodeUtil.handleFourBytes(byte1, b3, buffer.get(offset4), buffer.get(offset5), resultArr, resultPos2);
                offset = offset5 + 1;
                resultPos2 = resultPos2 + 1 + 1;
            }
        }
        return new String(resultArr, 0, resultPos2);
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public int encodedLength(CharSequence in) {
        return computeEncodedLength(in);
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public String decodeUtf8(ByteBuffer buffer, int offset, int length) throws IllegalArgumentException {
        if (buffer.hasArray()) {
            return decodeUtf8Array(buffer.array(), buffer.arrayOffset() + offset, length);
        }
        return decodeUtf8Buffer(buffer, offset, length);
    }

    private static void encodeUtf8Buffer(CharSequence in, ByteBuffer out) {
        int inLength = in.length();
        int outIx = out.position();
        int inIx = 0;
        while (inIx < inLength) {
            try {
                char c = in.charAt(inIx);
                if (c >= 128) {
                    break;
                }
                out.put(outIx + inIx, (byte) c);
                inIx++;
            } catch (IndexOutOfBoundsException e) {
                int badWriteIndex = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex);
            }
        }
        if (inIx == inLength) {
            out.position(outIx + inIx);
            return;
        }
        int outIx2 = outIx + inIx;
        while (inIx < inLength) {
            char c2 = in.charAt(inIx);
            if (c2 < 128) {
                out.put(outIx2, (byte) c2);
            } else if (c2 < 2048) {
                int outIx3 = outIx2 + 1;
                try {
                    out.put(outIx2, (byte) ((c2 >>> 6) | 192));
                    out.put(outIx3, (byte) ((c2 & '?') | 128));
                    outIx2 = outIx3;
                } catch (IndexOutOfBoundsException e2) {
                    outIx = outIx3;
                    int badWriteIndex2 = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex2);
                }
            } else if (c2 < 55296 || 57343 < c2) {
                int outIx4 = outIx2 + 1;
                out.put(outIx2, (byte) ((c2 >>> '\f') | 224));
                outIx2 = outIx4 + 1;
                out.put(outIx4, (byte) (((c2 >>> 6) & 63) | 128));
                out.put(outIx2, (byte) ((c2 & '?') | 128));
            } else {
                if (inIx + 1 != inLength) {
                    inIx++;
                    char low = in.charAt(inIx);
                    if (Character.isSurrogatePair(c2, low)) {
                        int codePoint = Character.toCodePoint(c2, low);
                        int outIx5 = outIx2 + 1;
                        try {
                            out.put(outIx2, (byte) ((codePoint >>> 18) | 240));
                            int outIx6 = outIx5 + 1;
                            out.put(outIx5, (byte) (((codePoint >>> 12) & 63) | 128));
                            int outIx7 = outIx6 + 1;
                            out.put(outIx6, (byte) (((codePoint >>> 6) & 63) | 128));
                            out.put(outIx7, (byte) ((codePoint & 63) | 128));
                            outIx2 = outIx7;
                        } catch (IndexOutOfBoundsException e3) {
                            outIx = outIx5;
                            int badWriteIndex22 = out.position() + Math.max(inIx, (outIx - out.position()) + 1);
                            throw new ArrayIndexOutOfBoundsException("Failed writing " + in.charAt(inIx) + " at index " + badWriteIndex22);
                        }
                    }
                }
                throw new UnpairedSurrogateException(inIx, inLength);
            }
            inIx++;
            outIx2++;
        }
        out.position(outIx2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0023, code lost:
        return r12 + r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static int encodeUtf8Array(java.lang.CharSequence r10, byte[] r11, int r12, int r13) {
        /*
            Method dump skipped, instructions count: 265
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.emoji2.text.flatbuffer.Utf8Safe.encodeUtf8Array(java.lang.CharSequence, byte[], int, int):int");
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public void encodeUtf8(CharSequence in, ByteBuffer out) {
        if (out.hasArray()) {
            int start = out.arrayOffset();
            int end = encodeUtf8Array(in, out.array(), out.position() + start, out.remaining());
            out.position(end - start);
            return;
        }
        encodeUtf8Buffer(in, out);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class UnpairedSurrogateException extends IllegalArgumentException {
        UnpairedSurrogateException(int index, int length) {
            super("Unpaired surrogate at index " + index + " of " + length);
        }
    }
}
