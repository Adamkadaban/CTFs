package androidx.emoji2.text.flatbuffer;

import androidx.emoji2.text.flatbuffer.FlexBuffers;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
/* loaded from: classes.dex */
public class FlexBuffersBuilder {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    public static final int BUILDER_FLAG_NONE = 0;
    public static final int BUILDER_FLAG_SHARE_ALL = 7;
    public static final int BUILDER_FLAG_SHARE_KEYS = 1;
    public static final int BUILDER_FLAG_SHARE_KEYS_AND_STRINGS = 3;
    public static final int BUILDER_FLAG_SHARE_KEY_VECTORS = 4;
    public static final int BUILDER_FLAG_SHARE_STRINGS = 2;
    private static final int WIDTH_16 = 1;
    private static final int WIDTH_32 = 2;
    private static final int WIDTH_64 = 3;
    private static final int WIDTH_8 = 0;
    private final ReadWriteBuf bb;
    private boolean finished;
    private final int flags;
    private Comparator<Value> keyComparator;
    private final HashMap<String, Integer> keyPool;
    private final ArrayList<Value> stack;
    private final HashMap<String, Integer> stringPool;

    public FlexBuffersBuilder(int bufSize) {
        this(new ArrayReadWriteBuf(bufSize), 1);
    }

    public FlexBuffersBuilder() {
        this(256);
    }

    @Deprecated
    public FlexBuffersBuilder(ByteBuffer bb, int flags) {
        this(new ArrayReadWriteBuf(bb.array()), flags);
    }

    public FlexBuffersBuilder(ReadWriteBuf bb, int flags) {
        this.stack = new ArrayList<>();
        this.keyPool = new HashMap<>();
        this.stringPool = new HashMap<>();
        this.finished = false;
        this.keyComparator = new Comparator<Value>() { // from class: androidx.emoji2.text.flatbuffer.FlexBuffersBuilder.1
            @Override // java.util.Comparator
            public int compare(Value o1, Value o2) {
                byte c1;
                byte c2;
                int ia = o1.key;
                int io = o2.key;
                do {
                    c1 = FlexBuffersBuilder.this.bb.get(ia);
                    c2 = FlexBuffersBuilder.this.bb.get(io);
                    if (c1 == 0) {
                        return c1 - c2;
                    }
                    ia++;
                    io++;
                } while (c1 == c2);
                return c1 - c2;
            }
        };
        this.bb = bb;
        this.flags = flags;
    }

    public FlexBuffersBuilder(ByteBuffer bb) {
        this(bb, 1);
    }

    public ReadWriteBuf getBuffer() {
        if (!this.finished) {
            throw new AssertionError();
        }
        return this.bb;
    }

    public void putBoolean(boolean val) {
        putBoolean(null, val);
    }

    public void putBoolean(String key, boolean val) {
        this.stack.add(Value.bool(putKey(key), val));
    }

    private int putKey(String key) {
        if (key == null) {
            return -1;
        }
        int pos = this.bb.writePosition();
        if ((this.flags & 1) != 0) {
            Integer keyFromPool = this.keyPool.get(key);
            if (keyFromPool == null) {
                byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
                this.bb.put(keyBytes, 0, keyBytes.length);
                this.bb.put((byte) 0);
                this.keyPool.put(key, Integer.valueOf(pos));
                return pos;
            }
            return keyFromPool.intValue();
        }
        byte[] keyBytes2 = key.getBytes(StandardCharsets.UTF_8);
        this.bb.put(keyBytes2, 0, keyBytes2.length);
        this.bb.put((byte) 0);
        this.keyPool.put(key, Integer.valueOf(pos));
        return pos;
    }

    public void putInt(int val) {
        putInt((String) null, val);
    }

    public void putInt(String key, int val) {
        putInt(key, val);
    }

    public void putInt(String key, long val) {
        int iKey = putKey(key);
        if (-128 <= val && val <= 127) {
            this.stack.add(Value.int8(iKey, (int) val));
        } else if (-32768 <= val && val <= 32767) {
            this.stack.add(Value.int16(iKey, (int) val));
        } else if (-2147483648L <= val && val <= 2147483647L) {
            this.stack.add(Value.int32(iKey, (int) val));
        } else {
            this.stack.add(Value.int64(iKey, val));
        }
    }

    public void putInt(long value) {
        putInt((String) null, value);
    }

    public void putUInt(int value) {
        putUInt(null, value);
    }

    public void putUInt(long value) {
        putUInt(null, value);
    }

    public void putUInt64(BigInteger value) {
        putUInt64(null, value.longValue());
    }

    private void putUInt64(String key, long value) {
        this.stack.add(Value.uInt64(putKey(key), value));
    }

    private void putUInt(String key, long value) {
        Value vVal;
        int iKey = putKey(key);
        int width = widthUInBits(value);
        if (width == 0) {
            vVal = Value.uInt8(iKey, (int) value);
        } else if (width == 1) {
            vVal = Value.uInt16(iKey, (int) value);
        } else if (width == 2) {
            vVal = Value.uInt32(iKey, (int) value);
        } else {
            vVal = Value.uInt64(iKey, value);
        }
        this.stack.add(vVal);
    }

    public void putFloat(float value) {
        putFloat((String) null, value);
    }

    public void putFloat(String key, float val) {
        this.stack.add(Value.float32(putKey(key), val));
    }

    public void putFloat(double value) {
        putFloat((String) null, value);
    }

    public void putFloat(String key, double val) {
        this.stack.add(Value.float64(putKey(key), val));
    }

    public int putString(String value) {
        return putString(null, value);
    }

    public int putString(String key, String val) {
        int iKey = putKey(key);
        if ((this.flags & 2) != 0) {
            Integer i = this.stringPool.get(val);
            if (i == null) {
                Value value = writeString(iKey, val);
                this.stringPool.put(val, Integer.valueOf((int) value.iValue));
                this.stack.add(value);
                return (int) value.iValue;
            }
            int bitWidth = widthUInBits(val.length());
            this.stack.add(Value.blob(iKey, i.intValue(), 5, bitWidth));
            return i.intValue();
        }
        Value value2 = writeString(iKey, val);
        this.stack.add(value2);
        return (int) value2.iValue;
    }

    private Value writeString(int key, String s) {
        return writeBlob(key, s.getBytes(StandardCharsets.UTF_8), 5, true);
    }

    static int widthUInBits(long len) {
        if (len <= FlexBuffers.Unsigned.byteToUnsignedInt((byte) -1)) {
            return 0;
        }
        if (len <= FlexBuffers.Unsigned.shortToUnsignedInt((short) -1)) {
            return 1;
        }
        return len <= FlexBuffers.Unsigned.intToUnsignedLong(-1) ? 2 : 3;
    }

    private Value writeBlob(int key, byte[] blob, int type, boolean trailing) {
        int bitWidth = widthUInBits(blob.length);
        int byteWidth = align(bitWidth);
        writeInt(blob.length, byteWidth);
        int sloc = this.bb.writePosition();
        this.bb.put(blob, 0, blob.length);
        if (trailing) {
            this.bb.put((byte) 0);
        }
        return Value.blob(key, sloc, type, bitWidth);
    }

    private int align(int alignment) {
        int byteWidth = 1 << alignment;
        int padBytes = Value.paddingBytes(this.bb.writePosition(), byteWidth);
        while (true) {
            int padBytes2 = padBytes - 1;
            if (padBytes != 0) {
                this.bb.put((byte) 0);
                padBytes = padBytes2;
            } else {
                return byteWidth;
            }
        }
    }

    private void writeInt(long value, int byteWidth) {
        switch (byteWidth) {
            case 1:
                this.bb.put((byte) value);
                return;
            case 2:
                this.bb.putShort((short) value);
                return;
            case 4:
                this.bb.putInt((int) value);
                return;
            case 8:
                this.bb.putLong(value);
                return;
            default:
                return;
        }
    }

    public int putBlob(byte[] value) {
        return putBlob(null, value);
    }

    public int putBlob(String key, byte[] val) {
        int iKey = putKey(key);
        Value value = writeBlob(iKey, val, 25, false);
        this.stack.add(value);
        return (int) value.iValue;
    }

    public int startVector() {
        return this.stack.size();
    }

    public int endVector(String key, int start, boolean typed, boolean fixed) {
        int iKey = putKey(key);
        Value vec = createVector(iKey, start, this.stack.size() - start, typed, fixed, null);
        while (this.stack.size() > start) {
            ArrayList<Value> arrayList = this.stack;
            arrayList.remove(arrayList.size() - 1);
        }
        this.stack.add(vec);
        return (int) vec.iValue;
    }

    public ByteBuffer finish() {
        if (this.stack.size() != 1) {
            throw new AssertionError();
        }
        int byteWidth = align(this.stack.get(0).elemWidth(this.bb.writePosition(), 0));
        writeAny(this.stack.get(0), byteWidth);
        this.bb.put(this.stack.get(0).storedPackedType());
        this.bb.put((byte) byteWidth);
        this.finished = true;
        return ByteBuffer.wrap(this.bb.data(), 0, this.bb.writePosition());
    }

    private Value createVector(int key, int start, int length, boolean typed, boolean fixed, Value keys) {
        int i;
        if (!fixed || typed) {
            int bitWidth = Math.max(0, widthUInBits(length));
            int prefixElems = 1;
            if (keys != null) {
                bitWidth = Math.max(bitWidth, keys.elemWidth(this.bb.writePosition(), 0));
                prefixElems = 1 + 2;
            }
            int vectorType = 4;
            for (int i2 = start; i2 < this.stack.size(); i2++) {
                int elemWidth = this.stack.get(i2).elemWidth(this.bb.writePosition(), i2 + prefixElems);
                bitWidth = Math.max(bitWidth, elemWidth);
                if (typed) {
                    if (i2 == start) {
                        vectorType = this.stack.get(i2).type;
                        if (!FlexBuffers.isTypedVectorElementType(vectorType)) {
                            throw new FlexBuffers.FlexBufferException("TypedVector does not support this element type");
                        }
                    } else if (vectorType != this.stack.get(i2).type) {
                        throw new AssertionError();
                    }
                }
            }
            if (!fixed || FlexBuffers.isTypedVectorElementType(vectorType)) {
                int byteWidth = align(bitWidth);
                if (keys != null) {
                    writeOffset(keys.iValue, byteWidth);
                    writeInt(1 << keys.minBitWidth, byteWidth);
                }
                if (!fixed) {
                    writeInt(length, byteWidth);
                }
                int vloc = this.bb.writePosition();
                for (int i3 = start; i3 < this.stack.size(); i3++) {
                    writeAny(this.stack.get(i3), byteWidth);
                }
                if (!typed) {
                    for (int i4 = start; i4 < this.stack.size(); i4++) {
                        this.bb.put(this.stack.get(i4).storedPackedType(bitWidth));
                    }
                }
                if (keys != null) {
                    i = 9;
                } else if (typed) {
                    i = FlexBuffers.toTypedVector(vectorType, fixed ? length : 0);
                } else {
                    i = 10;
                }
                return new Value(key, i, bitWidth, vloc);
            }
            throw new AssertionError();
        }
        throw new AssertionError();
    }

    private void writeOffset(long val, int byteWidth) {
        int reloff = (int) (this.bb.writePosition() - val);
        if (byteWidth != 8 && reloff >= (1 << (byteWidth * 8))) {
            throw new AssertionError();
        }
        writeInt(reloff, byteWidth);
    }

    private void writeAny(Value val, int byteWidth) {
        switch (val.type) {
            case 0:
            case 1:
            case 2:
            case 26:
                writeInt(val.iValue, byteWidth);
                return;
            case 3:
                writeDouble(val.dValue, byteWidth);
                return;
            default:
                writeOffset(val.iValue, byteWidth);
                return;
        }
    }

    private void writeDouble(double val, int byteWidth) {
        if (byteWidth == 4) {
            this.bb.putFloat((float) val);
        } else if (byteWidth == 8) {
            this.bb.putDouble(val);
        }
    }

    public int startMap() {
        return this.stack.size();
    }

    public int endMap(String key, int start) {
        int iKey = putKey(key);
        ArrayList<Value> arrayList = this.stack;
        Collections.sort(arrayList.subList(start, arrayList.size()), this.keyComparator);
        Value keys = createKeyVector(start, this.stack.size() - start);
        Value vec = createVector(iKey, start, this.stack.size() - start, false, false, keys);
        while (this.stack.size() > start) {
            ArrayList<Value> arrayList2 = this.stack;
            arrayList2.remove(arrayList2.size() - 1);
        }
        this.stack.add(vec);
        return (int) vec.iValue;
    }

    private Value createKeyVector(int start, int length) {
        int bitWidth = Math.max(0, widthUInBits(length));
        for (int i = start; i < this.stack.size(); i++) {
            int elemWidth = Value.elemWidth(4, 0, this.stack.get(i).key, this.bb.writePosition(), i + 1);
            bitWidth = Math.max(bitWidth, elemWidth);
        }
        int byteWidth = align(bitWidth);
        writeInt(length, byteWidth);
        int vloc = this.bb.writePosition();
        for (int i2 = start; i2 < this.stack.size(); i2++) {
            int pos = this.stack.get(i2).key;
            if (pos == -1) {
                throw new AssertionError();
            }
            writeOffset(this.stack.get(i2).key, byteWidth);
        }
        return new Value(-1, FlexBuffers.toTypedVector(4, 0), bitWidth, vloc);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Value {
        static final /* synthetic */ boolean $assertionsDisabled = false;
        final double dValue;
        long iValue;
        int key;
        final int minBitWidth;
        final int type;

        Value(int key, int type, int bitWidth, long iValue) {
            this.key = key;
            this.type = type;
            this.minBitWidth = bitWidth;
            this.iValue = iValue;
            this.dValue = Double.MIN_VALUE;
        }

        Value(int key, int type, int bitWidth, double dValue) {
            this.key = key;
            this.type = type;
            this.minBitWidth = bitWidth;
            this.dValue = dValue;
            this.iValue = Long.MIN_VALUE;
        }

        static Value bool(int key, boolean b) {
            return new Value(key, 26, 0, b ? 1L : 0L);
        }

        static Value blob(int key, int position, int type, int bitWidth) {
            return new Value(key, type, bitWidth, position);
        }

        static Value int8(int key, int value) {
            return new Value(key, 1, 0, value);
        }

        static Value int16(int key, int value) {
            return new Value(key, 1, 1, value);
        }

        static Value int32(int key, int value) {
            return new Value(key, 1, 2, value);
        }

        static Value int64(int key, long value) {
            return new Value(key, 1, 3, value);
        }

        static Value uInt8(int key, int value) {
            return new Value(key, 2, 0, value);
        }

        static Value uInt16(int key, int value) {
            return new Value(key, 2, 1, value);
        }

        static Value uInt32(int key, int value) {
            return new Value(key, 2, 2, value);
        }

        static Value uInt64(int key, long value) {
            return new Value(key, 2, 3, value);
        }

        static Value float32(int key, float value) {
            return new Value(key, 3, 2, value);
        }

        static Value float64(int key, double value) {
            return new Value(key, 3, 3, value);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public byte storedPackedType() {
            return storedPackedType(0);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public byte storedPackedType(int parentBitWidth) {
            return packedType(storedWidth(parentBitWidth), this.type);
        }

        private static byte packedType(int bitWidth, int type) {
            return (byte) ((type << 2) | bitWidth);
        }

        private int storedWidth(int parentBitWidth) {
            if (FlexBuffers.isTypeInline(this.type)) {
                return Math.max(this.minBitWidth, parentBitWidth);
            }
            return this.minBitWidth;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public int elemWidth(int bufSize, int elemIndex) {
            return elemWidth(this.type, this.minBitWidth, this.iValue, bufSize, elemIndex);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static int elemWidth(int type, int minBitWidth, long iValue, int bufSize, int elemIndex) {
            if (FlexBuffers.isTypeInline(type)) {
                return minBitWidth;
            }
            for (int byteWidth = 1; byteWidth <= 32; byteWidth *= 2) {
                int offsetLoc = paddingBytes(bufSize, byteWidth) + bufSize + (elemIndex * byteWidth);
                long offset = offsetLoc - iValue;
                int bitWidth = FlexBuffersBuilder.widthUInBits((int) offset);
                if ((1 << bitWidth) == byteWidth) {
                    return bitWidth;
                }
            }
            throw new AssertionError();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static int paddingBytes(int bufSize, int scalarSize) {
            return ((~bufSize) + 1) & (scalarSize - 1);
        }
    }
}
