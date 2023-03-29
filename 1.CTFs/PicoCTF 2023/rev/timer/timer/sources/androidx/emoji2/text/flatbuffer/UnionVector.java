package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
/* loaded from: classes.dex */
public final class UnionVector extends BaseVector {
    public UnionVector __assign(int _vector, int _element_size, ByteBuffer _bb) {
        __reset(_vector, _element_size, _bb);
        return this;
    }

    public Table get(Table obj, int j) {
        return Table.__union(obj, __element(j), this.bb);
    }
}
