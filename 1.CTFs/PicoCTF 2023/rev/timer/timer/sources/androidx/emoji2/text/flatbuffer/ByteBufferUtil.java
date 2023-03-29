package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public class ByteBufferUtil {
    public static int getSizePrefix(ByteBuffer bb) {
        return bb.getInt(bb.position());
    }

    public static ByteBuffer removeSizePrefix(ByteBuffer bb) {
        ByteBuffer s = bb.duplicate();
        s.position(s.position() + 4);
        return s;
    }
}
