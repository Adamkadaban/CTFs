package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class IntVector extends BaseVector {
    public IntVector __assign(int _vector, ByteBuffer _bb) {
        __reset(_vector, 4, _bb);
        return this;
    }

    public int get(int j) {
        return this.bb.getInt(__element(j));
    }

    public long getAsUnsigned(int j) {
        return get(j) & 4294967295L;
    }
}
