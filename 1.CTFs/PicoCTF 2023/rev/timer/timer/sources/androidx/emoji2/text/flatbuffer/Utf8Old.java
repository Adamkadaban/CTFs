package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.StandardCharsets;
/* loaded from: classes.dex */
public class Utf8Old extends Utf8 {
    private static final ThreadLocal<Cache> CACHE = ThreadLocal.withInitial(Utf8Old$$ExternalSyntheticLambda0.INSTANCE);

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Cache {
        CharSequence lastInput = null;
        ByteBuffer lastOutput = null;
        final CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
        final CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();

        Cache() {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static /* synthetic */ Cache lambda$static$0() {
        return new Cache();
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public int encodedLength(CharSequence in) {
        Cache cache = CACHE.get();
        int estimated = (int) (in.length() * cache.encoder.maxBytesPerChar());
        if (cache.lastOutput == null || cache.lastOutput.capacity() < estimated) {
            cache.lastOutput = ByteBuffer.allocate(Math.max(128, estimated));
        }
        cache.lastOutput.clear();
        cache.lastInput = in;
        CharBuffer wrap = in instanceof CharBuffer ? (CharBuffer) in : CharBuffer.wrap(in);
        CoderResult result = cache.encoder.encode(wrap, cache.lastOutput, true);
        if (result.isError()) {
            try {
                result.throwException();
            } catch (CharacterCodingException e) {
                throw new IllegalArgumentException("bad character encoding", e);
            }
        }
        cache.lastOutput.flip();
        return cache.lastOutput.remaining();
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public void encodeUtf8(CharSequence in, ByteBuffer out) {
        Cache cache = CACHE.get();
        if (cache.lastInput != in) {
            encodedLength(in);
        }
        out.put(cache.lastOutput);
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public String decodeUtf8(ByteBuffer buffer, int offset, int length) {
        CharsetDecoder decoder = CACHE.get().decoder;
        decoder.reset();
        ByteBuffer buffer2 = buffer.duplicate();
        buffer2.position(offset);
        buffer2.limit(offset + length);
        try {
            CharBuffer result = decoder.decode(buffer2);
            return result.toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Bad encoding", e);
        }
    }
}
