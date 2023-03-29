package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class DoubleVector extends BaseVector {
    public DoubleVector __assign(int _vector, ByteBuffer _bb) {
        __reset(_vector, 8, _bb);
        return this;
    }

    public double get(int j) {
        return this.bb.getDouble(__element(j));
    }
}
