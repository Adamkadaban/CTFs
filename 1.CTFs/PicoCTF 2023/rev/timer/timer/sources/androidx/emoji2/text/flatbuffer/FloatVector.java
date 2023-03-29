package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class FloatVector extends BaseVector {
    public FloatVector __assign(int _vector, ByteBuffer _bb) {
        __reset(_vector, 4, _bb);
        return this;
    }

    public float get(int j) {
        return this.bb.getFloat(__element(j));
    }
}
