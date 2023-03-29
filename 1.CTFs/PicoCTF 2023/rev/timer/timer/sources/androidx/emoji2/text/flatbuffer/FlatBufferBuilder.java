package androidx.emoji2.text.flatbuffer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import kotlin.UByte;
/* loaded from: classes.dex */
public class FlatBufferBuilder {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    ByteBuffer bb;
    ByteBufferFactory bb_factory;
    boolean finished;
    boolean force_defaults;
    int minalign;
    boolean nested;
    int num_vtables;
    int object_start;
    int space;
    final Utf8 utf8;
    int vector_num_elems;
    int[] vtable;
    int vtable_in_use;
    int[] vtables;

    public FlatBufferBuilder(int initial_size, ByteBufferFactory bb_factory) {
        this(initial_size, bb_factory, null, Utf8.getDefault());
    }

    public FlatBufferBuilder(int initial_size, ByteBufferFactory bb_factory, ByteBuffer existing_bb, Utf8 utf8) {
        this.minalign = 1;
        this.vtable = null;
        this.vtable_in_use = 0;
        this.nested = false;
        this.finished = false;
        this.vtables = new int[16];
        this.num_vtables = 0;
        this.vector_num_elems = 0;
        this.force_defaults = false;
        initial_size = initial_size <= 0 ? 1 : initial_size;
        this.bb_factory = bb_factory;
        if (existing_bb != null) {
            this.bb = existing_bb;
            existing_bb.clear();
            this.bb.order(ByteOrder.LITTLE_ENDIAN);
        } else {
            this.bb = bb_factory.newByteBuffer(initial_size);
        }
        this.utf8 = utf8;
        this.space = this.bb.capacity();
    }

    public FlatBufferBuilder(int initial_size) {
        this(initial_size, HeapByteBufferFactory.INSTANCE, null, Utf8.getDefault());
    }

    public FlatBufferBuilder() {
        this(1024);
    }

    public FlatBufferBuilder(ByteBuffer existing_bb, ByteBufferFactory bb_factory) {
        this(existing_bb.capacity(), bb_factory, existing_bb, Utf8.getDefault());
    }

    public FlatBufferBuilder(ByteBuffer existing_bb) {
        this(existing_bb, new HeapByteBufferFactory());
    }

    public FlatBufferBuilder init(ByteBuffer existing_bb, ByteBufferFactory bb_factory) {
        this.bb_factory = bb_factory;
        this.bb = existing_bb;
        existing_bb.clear();
        this.bb.order(ByteOrder.LITTLE_ENDIAN);
        this.minalign = 1;
        this.space = this.bb.capacity();
        this.vtable_in_use = 0;
        this.nested = false;
        this.finished = false;
        this.object_start = 0;
        this.num_vtables = 0;
        this.vector_num_elems = 0;
        return this;
    }

    /* loaded from: classes.dex */
    public static abstract class ByteBufferFactory {
        public abstract ByteBuffer newByteBuffer(int i);

        public void releaseByteBuffer(ByteBuffer bb) {
        }
    }

    /* loaded from: classes.dex */
    public static final class HeapByteBufferFactory extends ByteBufferFactory {
        public static final HeapByteBufferFactory INSTANCE = new HeapByteBufferFactory();

        @Override // androidx.emoji2.text.flatbuffer.FlatBufferBuilder.ByteBufferFactory
        public ByteBuffer newByteBuffer(int capacity) {
            return ByteBuffer.allocate(capacity).order(ByteOrder.LITTLE_ENDIAN);
        }
    }

    public static boolean isFieldPresent(Table table, int offset) {
        return table.__offset(offset) != 0;
    }

    public void clear() {
        this.space = this.bb.capacity();
        this.bb.clear();
        this.minalign = 1;
        while (true) {
            int i = this.vtable_in_use;
            if (i <= 0) {
                this.vtable_in_use = 0;
                this.nested = false;
                this.finished = false;
                this.object_start = 0;
                this.num_vtables = 0;
                this.vector_num_elems = 0;
                return;
            }
            int[] iArr = this.vtable;
            int i2 = i - 1;
            this.vtable_in_use = i2;
            iArr[i2] = 0;
        }
    }

    static ByteBuffer growByteBuffer(ByteBuffer bb, ByteBufferFactory bb_factory) {
        int old_buf_size = bb.capacity();
        if (((-1073741824) & old_buf_size) != 0) {
            throw new AssertionError("FlatBuffers: cannot grow buffer beyond 2 gigabytes.");
        }
        int new_buf_size = old_buf_size == 0 ? 1 : old_buf_size << 1;
        bb.position(0);
        ByteBuffer nbb = bb_factory.newByteBuffer(new_buf_size);
        int new_buf_size2 = nbb.clear().capacity();
        nbb.position(new_buf_size2 - old_buf_size);
        nbb.put(bb);
        return nbb;
    }

    public int offset() {
        return this.bb.capacity() - this.space;
    }

    public void pad(int byte_size) {
        for (int i = 0; i < byte_size; i++) {
            ByteBuffer byteBuffer = this.bb;
            int i2 = this.space - 1;
            this.space = i2;
            byteBuffer.put(i2, (byte) 0);
        }
    }

    public void prep(int size, int additional_bytes) {
        if (size > this.minalign) {
            this.minalign = size;
        }
        int align_size = ((~((this.bb.capacity() - this.space) + additional_bytes)) + 1) & (size - 1);
        while (this.space < align_size + size + additional_bytes) {
            int old_buf_size = this.bb.capacity();
            ByteBuffer old = this.bb;
            ByteBuffer growByteBuffer = growByteBuffer(old, this.bb_factory);
            this.bb = growByteBuffer;
            if (old != growByteBuffer) {
                this.bb_factory.releaseByteBuffer(old);
            }
            this.space += this.bb.capacity() - old_buf_size;
        }
        pad(align_size);
    }

    public void putBoolean(boolean x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 1;
        this.space = i;
        byteBuffer.put(i, x ? (byte) 1 : (byte) 0);
    }

    public void putByte(byte x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 1;
        this.space = i;
        byteBuffer.put(i, x);
    }

    public void putShort(short x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 2;
        this.space = i;
        byteBuffer.putShort(i, x);
    }

    public void putInt(int x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 4;
        this.space = i;
        byteBuffer.putInt(i, x);
    }

    public void putLong(long x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 8;
        this.space = i;
        byteBuffer.putLong(i, x);
    }

    public void putFloat(float x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 4;
        this.space = i;
        byteBuffer.putFloat(i, x);
    }

    public void putDouble(double x) {
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - 8;
        this.space = i;
        byteBuffer.putDouble(i, x);
    }

    public void addBoolean(boolean x) {
        prep(1, 0);
        putBoolean(x);
    }

    public void addByte(byte x) {
        prep(1, 0);
        putByte(x);
    }

    public void addShort(short x) {
        prep(2, 0);
        putShort(x);
    }

    public void addInt(int x) {
        prep(4, 0);
        putInt(x);
    }

    public void addLong(long x) {
        prep(8, 0);
        putLong(x);
    }

    public void addFloat(float x) {
        prep(4, 0);
        putFloat(x);
    }

    public void addDouble(double x) {
        prep(8, 0);
        putDouble(x);
    }

    public void addOffset(int off) {
        prep(4, 0);
        if (off > offset()) {
            throw new AssertionError();
        }
        putInt((offset() - off) + 4);
    }

    public void startVector(int elem_size, int num_elems, int alignment) {
        notNested();
        this.vector_num_elems = num_elems;
        prep(4, elem_size * num_elems);
        prep(alignment, elem_size * num_elems);
        this.nested = true;
    }

    public int endVector() {
        if (!this.nested) {
            throw new AssertionError("FlatBuffers: endVector called without startVector");
        }
        this.nested = false;
        putInt(this.vector_num_elems);
        return offset();
    }

    public ByteBuffer createUnintializedVector(int elem_size, int num_elems, int alignment) {
        int length = elem_size * num_elems;
        startVector(elem_size, num_elems, alignment);
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer.position(i);
        ByteBuffer copy = this.bb.slice().order(ByteOrder.LITTLE_ENDIAN);
        copy.limit(length);
        return copy;
    }

    public int createVectorOfTables(int[] offsets) {
        notNested();
        startVector(4, offsets.length, 4);
        for (int i = offsets.length - 1; i >= 0; i--) {
            addOffset(offsets[i]);
        }
        int i2 = endVector();
        return i2;
    }

    public <T extends Table> int createSortedVectorOfTables(T obj, int[] offsets) {
        obj.sortTables(offsets, this.bb);
        return createVectorOfTables(offsets);
    }

    public int createString(CharSequence s) {
        int length = this.utf8.encodedLength(s);
        addByte((byte) 0);
        startVector(1, length, 1);
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer.position(i);
        this.utf8.encodeUtf8(s, this.bb);
        return endVector();
    }

    public int createString(ByteBuffer s) {
        int length = s.remaining();
        addByte((byte) 0);
        startVector(1, length, 1);
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer.position(i);
        this.bb.put(s);
        return endVector();
    }

    public int createByteVector(byte[] arr) {
        int length = arr.length;
        startVector(1, length, 1);
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer.position(i);
        this.bb.put(arr);
        return endVector();
    }

    public int createByteVector(byte[] arr, int offset, int length) {
        startVector(1, length, 1);
        ByteBuffer byteBuffer = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer.position(i);
        this.bb.put(arr, offset, length);
        return endVector();
    }

    public int createByteVector(ByteBuffer byteBuffer) {
        int length = byteBuffer.remaining();
        startVector(1, length, 1);
        ByteBuffer byteBuffer2 = this.bb;
        int i = this.space - length;
        this.space = i;
        byteBuffer2.position(i);
        this.bb.put(byteBuffer);
        return endVector();
    }

    public void finished() {
        if (!this.finished) {
            throw new AssertionError("FlatBuffers: you can only access the serialized buffer after it has been finished by FlatBufferBuilder.finish().");
        }
    }

    public void notNested() {
        if (this.nested) {
            throw new AssertionError("FlatBuffers: object serialization must not be nested.");
        }
    }

    public void Nested(int obj) {
        if (obj != offset()) {
            throw new AssertionError("FlatBuffers: struct must be serialized inline.");
        }
    }

    public void startTable(int numfields) {
        notNested();
        int[] iArr = this.vtable;
        if (iArr == null || iArr.length < numfields) {
            this.vtable = new int[numfields];
        }
        this.vtable_in_use = numfields;
        Arrays.fill(this.vtable, 0, numfields, 0);
        this.nested = true;
        this.object_start = offset();
    }

    public void addBoolean(int o, boolean x, boolean d) {
        if (this.force_defaults || x != d) {
            addBoolean(x);
            slot(o);
        }
    }

    public void addByte(int o, byte x, int d) {
        if (this.force_defaults || x != d) {
            addByte(x);
            slot(o);
        }
    }

    public void addShort(int o, short x, int d) {
        if (this.force_defaults || x != d) {
            addShort(x);
            slot(o);
        }
    }

    public void addInt(int o, int x, int d) {
        if (this.force_defaults || x != d) {
            addInt(x);
            slot(o);
        }
    }

    public void addLong(int o, long x, long d) {
        if (this.force_defaults || x != d) {
            addLong(x);
            slot(o);
        }
    }

    public void addFloat(int o, float x, double d) {
        if (this.force_defaults || x != d) {
            addFloat(x);
            slot(o);
        }
    }

    public void addDouble(int o, double x, double d) {
        if (this.force_defaults || x != d) {
            addDouble(x);
            slot(o);
        }
    }

    public void addOffset(int o, int x, int d) {
        if (this.force_defaults || x != d) {
            addOffset(x);
            slot(o);
        }
    }

    public void addStruct(int voffset, int x, int d) {
        if (x != d) {
            Nested(x);
            slot(voffset);
        }
    }

    public void slot(int voffset) {
        this.vtable[voffset] = offset();
    }

    public int endTable() {
        if (this.vtable == null || !this.nested) {
            throw new AssertionError("FlatBuffers: endTable called without startTable");
        }
        addInt(0);
        int vtableloc = offset();
        int i = this.vtable_in_use - 1;
        while (i >= 0 && this.vtable[i] == 0) {
            i--;
        }
        int trimmed_size = i + 1;
        while (i >= 0) {
            int[] iArr = this.vtable;
            short off = (short) (iArr[i] != 0 ? vtableloc - iArr[i] : 0);
            addShort(off);
            i--;
        }
        addShort((short) (vtableloc - this.object_start));
        addShort((short) ((trimmed_size + 2) * 2));
        int existing_vtable = 0;
        int i2 = 0;
        loop2: while (true) {
            if (i2 >= this.num_vtables) {
                break;
            }
            int vt1 = this.bb.capacity() - this.vtables[i2];
            int vt2 = this.space;
            short len = this.bb.getShort(vt1);
            if (len == this.bb.getShort(vt2)) {
                for (int j = 2; j < len; j += 2) {
                    if (this.bb.getShort(vt1 + j) != this.bb.getShort(vt2 + j)) {
                        break;
                    }
                }
                existing_vtable = this.vtables[i2];
                break loop2;
            }
            i2++;
        }
        if (existing_vtable != 0) {
            int capacity = this.bb.capacity() - vtableloc;
            this.space = capacity;
            this.bb.putInt(capacity, existing_vtable - vtableloc);
        } else {
            int i3 = this.num_vtables;
            int[] iArr2 = this.vtables;
            if (i3 == iArr2.length) {
                this.vtables = Arrays.copyOf(iArr2, i3 * 2);
            }
            int[] iArr3 = this.vtables;
            int i4 = this.num_vtables;
            this.num_vtables = i4 + 1;
            iArr3[i4] = offset();
            ByteBuffer byteBuffer = this.bb;
            byteBuffer.putInt(byteBuffer.capacity() - vtableloc, offset() - vtableloc);
        }
        this.nested = false;
        return vtableloc;
    }

    public void required(int table, int field) {
        int table_start = this.bb.capacity() - table;
        int vtable_start = table_start - this.bb.getInt(table_start);
        boolean ok = this.bb.getShort(vtable_start + field) != 0;
        if (!ok) {
            throw new AssertionError("FlatBuffers: field " + field + " must be set");
        }
    }

    protected void finish(int root_table, boolean size_prefix) {
        prep(this.minalign, (size_prefix ? 4 : 0) + 4);
        addOffset(root_table);
        if (size_prefix) {
            addInt(this.bb.capacity() - this.space);
        }
        this.bb.position(this.space);
        this.finished = true;
    }

    public void finish(int root_table) {
        finish(root_table, false);
    }

    public void finishSizePrefixed(int root_table) {
        finish(root_table, true);
    }

    protected void finish(int root_table, String file_identifier, boolean size_prefix) {
        prep(this.minalign, (size_prefix ? 4 : 0) + 8);
        if (file_identifier.length() != 4) {
            throw new AssertionError("FlatBuffers: file identifier must be length 4");
        }
        for (int i = 3; i >= 0; i--) {
            addByte((byte) file_identifier.charAt(i));
        }
        finish(root_table, size_prefix);
    }

    public void finish(int root_table, String file_identifier) {
        finish(root_table, file_identifier, false);
    }

    public void finishSizePrefixed(int root_table, String file_identifier) {
        finish(root_table, file_identifier, true);
    }

    public FlatBufferBuilder forceDefaults(boolean forceDefaults) {
        this.force_defaults = forceDefaults;
        return this;
    }

    public ByteBuffer dataBuffer() {
        finished();
        return this.bb;
    }

    @Deprecated
    private int dataStart() {
        finished();
        return this.space;
    }

    public byte[] sizedByteArray(int start, int length) {
        finished();
        byte[] array = new byte[length];
        this.bb.position(start);
        this.bb.get(array);
        return array;
    }

    public byte[] sizedByteArray() {
        return sizedByteArray(this.space, this.bb.capacity() - this.space);
    }

    public InputStream sizedInputStream() {
        finished();
        ByteBuffer duplicate = this.bb.duplicate();
        duplicate.position(this.space);
        duplicate.limit(this.bb.capacity());
        return new ByteBufferBackedInputStream(duplicate);
    }

    /* loaded from: classes.dex */
    static class ByteBufferBackedInputStream extends InputStream {
        ByteBuffer buf;

        public ByteBufferBackedInputStream(ByteBuffer buf) {
            this.buf = buf;
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            try {
                return this.buf.get() & UByte.MAX_VALUE;
            } catch (BufferUnderflowException e) {
                return -1;
            }
        }
    }
}
