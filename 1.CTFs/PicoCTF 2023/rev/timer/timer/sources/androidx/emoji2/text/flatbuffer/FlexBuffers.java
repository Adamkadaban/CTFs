package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import kotlin.UByte;
import kotlin.text.Typography;
/* loaded from: classes.dex */
public class FlexBuffers {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private static final ReadBuf EMPTY_BB = new ArrayReadWriteBuf(new byte[]{0}, 1);
    public static final int FBT_BLOB = 25;
    public static final int FBT_BOOL = 26;
    public static final int FBT_FLOAT = 3;
    public static final int FBT_INDIRECT_FLOAT = 8;
    public static final int FBT_INDIRECT_INT = 6;
    public static final int FBT_INDIRECT_UINT = 7;
    public static final int FBT_INT = 1;
    public static final int FBT_KEY = 4;
    public static final int FBT_MAP = 9;
    public static final int FBT_NULL = 0;
    public static final int FBT_STRING = 5;
    public static final int FBT_UINT = 2;
    public static final int FBT_VECTOR = 10;
    public static final int FBT_VECTOR_BOOL = 36;
    public static final int FBT_VECTOR_FLOAT = 13;
    public static final int FBT_VECTOR_FLOAT2 = 18;
    public static final int FBT_VECTOR_FLOAT3 = 21;
    public static final int FBT_VECTOR_FLOAT4 = 24;
    public static final int FBT_VECTOR_INT = 11;
    public static final int FBT_VECTOR_INT2 = 16;
    public static final int FBT_VECTOR_INT3 = 19;
    public static final int FBT_VECTOR_INT4 = 22;
    public static final int FBT_VECTOR_KEY = 14;
    public static final int FBT_VECTOR_STRING_DEPRECATED = 15;
    public static final int FBT_VECTOR_UINT = 12;
    public static final int FBT_VECTOR_UINT2 = 17;
    public static final int FBT_VECTOR_UINT3 = 20;
    public static final int FBT_VECTOR_UINT4 = 23;

    static boolean isTypedVector(int type) {
        return (type >= 11 && type <= 15) || type == 36;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isTypeInline(int type) {
        return type <= 3 || type == 26;
    }

    static int toTypedVectorElementType(int original_type) {
        return (original_type - 11) + 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int toTypedVector(int type, int fixedLength) {
        if (!isTypedVectorElementType(type)) {
            throw new AssertionError();
        }
        switch (fixedLength) {
            case 0:
                return (type - 1) + 11;
            case 1:
            default:
                throw new AssertionError();
            case 2:
                return (type - 1) + 16;
            case 3:
                return (type - 1) + 19;
            case 4:
                return (type - 1) + 22;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isTypedVectorElementType(int type) {
        return (type >= 1 && type <= 4) || type == 26;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int indirect(ReadBuf bb, int offset, int byteWidth) {
        return (int) (offset - readUInt(bb, offset, byteWidth));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static long readUInt(ReadBuf buff, int end, int byteWidth) {
        switch (byteWidth) {
            case 1:
                return Unsigned.byteToUnsignedInt(buff.get(end));
            case 2:
                return Unsigned.shortToUnsignedInt(buff.getShort(end));
            case 4:
                return Unsigned.intToUnsignedLong(buff.getInt(end));
            case 8:
                return buff.getLong(end);
            default:
                return -1L;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int readInt(ReadBuf buff, int end, int byteWidth) {
        return (int) readLong(buff, end, byteWidth);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static long readLong(ReadBuf buff, int end, int byteWidth) {
        switch (byteWidth) {
            case 1:
                return buff.get(end);
            case 2:
                return buff.getShort(end);
            case 4:
                return buff.getInt(end);
            case 8:
                return buff.getLong(end);
            default:
                return -1L;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static double readDouble(ReadBuf buff, int end, int byteWidth) {
        switch (byteWidth) {
            case 4:
                return buff.getFloat(end);
            case 8:
                return buff.getDouble(end);
            default:
                return -1.0d;
        }
    }

    @Deprecated
    public static Reference getRoot(ByteBuffer buffer) {
        return getRoot(buffer.hasArray() ? new ArrayReadWriteBuf(buffer.array(), buffer.limit()) : new ByteBufferReadWriteBuf(buffer));
    }

    public static Reference getRoot(ReadBuf buffer) {
        int end = buffer.limit() - 1;
        int byteWidth = buffer.get(end);
        int end2 = end - 1;
        int packetType = Unsigned.byteToUnsignedInt(buffer.get(end2));
        return new Reference(buffer, end2 - byteWidth, byteWidth, packetType);
    }

    /* loaded from: classes.dex */
    public static class Reference {
        private static final Reference NULL_REFERENCE = new Reference(FlexBuffers.EMPTY_BB, 0, 1, 0);
        private ReadBuf bb;
        private int byteWidth;
        private int end;
        private int parentWidth;
        private int type;

        Reference(ReadBuf bb, int end, int parentWidth, int packedType) {
            this(bb, end, parentWidth, 1 << (packedType & 3), packedType >> 2);
        }

        Reference(ReadBuf bb, int end, int parentWidth, int byteWidth, int type) {
            this.bb = bb;
            this.end = end;
            this.parentWidth = parentWidth;
            this.byteWidth = byteWidth;
            this.type = type;
        }

        public int getType() {
            return this.type;
        }

        public boolean isNull() {
            return this.type == 0;
        }

        public boolean isBoolean() {
            return this.type == 26;
        }

        public boolean isNumeric() {
            return isIntOrUInt() || isFloat();
        }

        public boolean isIntOrUInt() {
            return isInt() || isUInt();
        }

        public boolean isFloat() {
            int i = this.type;
            return i == 3 || i == 8;
        }

        public boolean isInt() {
            int i = this.type;
            return i == 1 || i == 6;
        }

        public boolean isUInt() {
            int i = this.type;
            return i == 2 || i == 7;
        }

        public boolean isString() {
            return this.type == 5;
        }

        public boolean isKey() {
            return this.type == 4;
        }

        public boolean isVector() {
            int i = this.type;
            return i == 10 || i == 9;
        }

        public boolean isTypedVector() {
            return FlexBuffers.isTypedVector(this.type);
        }

        public boolean isMap() {
            return this.type == 9;
        }

        public boolean isBlob() {
            return this.type == 25;
        }

        public int asInt() {
            int i = this.type;
            if (i == 1) {
                return FlexBuffers.readInt(this.bb, this.end, this.parentWidth);
            }
            switch (i) {
                case 0:
                    return 0;
                case 2:
                    return (int) FlexBuffers.readUInt(this.bb, this.end, this.parentWidth);
                case 3:
                    return (int) FlexBuffers.readDouble(this.bb, this.end, this.parentWidth);
                case 5:
                    return Integer.parseInt(asString());
                case 6:
                    ReadBuf readBuf = this.bb;
                    return FlexBuffers.readInt(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
                case 7:
                    ReadBuf readBuf2 = this.bb;
                    return (int) FlexBuffers.readUInt(readBuf2, FlexBuffers.indirect(readBuf2, this.end, this.parentWidth), this.parentWidth);
                case 8:
                    ReadBuf readBuf3 = this.bb;
                    return (int) FlexBuffers.readDouble(readBuf3, FlexBuffers.indirect(readBuf3, this.end, this.parentWidth), this.byteWidth);
                case 10:
                    return asVector().size();
                case 26:
                    return FlexBuffers.readInt(this.bb, this.end, this.parentWidth);
                default:
                    return 0;
            }
        }

        public long asUInt() {
            int i = this.type;
            if (i == 2) {
                return FlexBuffers.readUInt(this.bb, this.end, this.parentWidth);
            }
            switch (i) {
                case 0:
                    return 0L;
                case 1:
                    return FlexBuffers.readLong(this.bb, this.end, this.parentWidth);
                case 3:
                    return (long) FlexBuffers.readDouble(this.bb, this.end, this.parentWidth);
                case 5:
                    return Long.parseLong(asString());
                case 6:
                    ReadBuf readBuf = this.bb;
                    return FlexBuffers.readLong(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
                case 7:
                    ReadBuf readBuf2 = this.bb;
                    return FlexBuffers.readUInt(readBuf2, FlexBuffers.indirect(readBuf2, this.end, this.parentWidth), this.byteWidth);
                case 8:
                    ReadBuf readBuf3 = this.bb;
                    return (long) FlexBuffers.readDouble(readBuf3, FlexBuffers.indirect(readBuf3, this.end, this.parentWidth), this.parentWidth);
                case 10:
                    return asVector().size();
                case 26:
                    return FlexBuffers.readInt(this.bb, this.end, this.parentWidth);
                default:
                    return 0L;
            }
        }

        public long asLong() {
            int i = this.type;
            if (i == 1) {
                return FlexBuffers.readLong(this.bb, this.end, this.parentWidth);
            }
            switch (i) {
                case 0:
                    return 0L;
                case 2:
                    return FlexBuffers.readUInt(this.bb, this.end, this.parentWidth);
                case 3:
                    return (long) FlexBuffers.readDouble(this.bb, this.end, this.parentWidth);
                case 5:
                    try {
                        return Long.parseLong(asString());
                    } catch (NumberFormatException e) {
                        return 0L;
                    }
                case 6:
                    ReadBuf readBuf = this.bb;
                    return FlexBuffers.readLong(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
                case 7:
                    ReadBuf readBuf2 = this.bb;
                    return FlexBuffers.readUInt(readBuf2, FlexBuffers.indirect(readBuf2, this.end, this.parentWidth), this.parentWidth);
                case 8:
                    ReadBuf readBuf3 = this.bb;
                    return (long) FlexBuffers.readDouble(readBuf3, FlexBuffers.indirect(readBuf3, this.end, this.parentWidth), this.byteWidth);
                case 10:
                    return asVector().size();
                case 26:
                    return FlexBuffers.readInt(this.bb, this.end, this.parentWidth);
                default:
                    return 0L;
            }
        }

        public double asFloat() {
            int i = this.type;
            if (i == 3) {
                return FlexBuffers.readDouble(this.bb, this.end, this.parentWidth);
            }
            switch (i) {
                case 0:
                    return 0.0d;
                case 1:
                    return FlexBuffers.readInt(this.bb, this.end, this.parentWidth);
                case 2:
                case 26:
                    return FlexBuffers.readUInt(this.bb, this.end, this.parentWidth);
                case 5:
                    return Double.parseDouble(asString());
                case 6:
                    ReadBuf readBuf = this.bb;
                    return FlexBuffers.readInt(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
                case 7:
                    ReadBuf readBuf2 = this.bb;
                    return FlexBuffers.readUInt(readBuf2, FlexBuffers.indirect(readBuf2, this.end, this.parentWidth), this.byteWidth);
                case 8:
                    ReadBuf readBuf3 = this.bb;
                    return FlexBuffers.readDouble(readBuf3, FlexBuffers.indirect(readBuf3, this.end, this.parentWidth), this.byteWidth);
                case 10:
                    return asVector().size();
                default:
                    return 0.0d;
            }
        }

        public Key asKey() {
            if (isKey()) {
                ReadBuf readBuf = this.bb;
                return new Key(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
            }
            return Key.empty();
        }

        public String asString() {
            if (isString()) {
                int start = FlexBuffers.indirect(this.bb, this.end, this.parentWidth);
                ReadBuf readBuf = this.bb;
                int i = this.byteWidth;
                int size = (int) FlexBuffers.readUInt(readBuf, start - i, i);
                return this.bb.getString(start, size);
            } else if (isKey()) {
                int start2 = FlexBuffers.indirect(this.bb, this.end, this.byteWidth);
                int i2 = start2;
                while (this.bb.get(i2) != 0) {
                    i2++;
                }
                return this.bb.getString(start2, i2 - start2);
            } else {
                return "";
            }
        }

        public Map asMap() {
            if (isMap()) {
                ReadBuf readBuf = this.bb;
                return new Map(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
            }
            return Map.empty();
        }

        public Vector asVector() {
            if (isVector()) {
                ReadBuf readBuf = this.bb;
                return new Vector(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
            }
            int i = this.type;
            if (i == 15) {
                ReadBuf readBuf2 = this.bb;
                return new TypedVector(readBuf2, FlexBuffers.indirect(readBuf2, this.end, this.parentWidth), this.byteWidth, 4);
            } else if (FlexBuffers.isTypedVector(i)) {
                ReadBuf readBuf3 = this.bb;
                return new TypedVector(readBuf3, FlexBuffers.indirect(readBuf3, this.end, this.parentWidth), this.byteWidth, FlexBuffers.toTypedVectorElementType(this.type));
            } else {
                return Vector.empty();
            }
        }

        public Blob asBlob() {
            if (isBlob() || isString()) {
                ReadBuf readBuf = this.bb;
                return new Blob(readBuf, FlexBuffers.indirect(readBuf, this.end, this.parentWidth), this.byteWidth);
            }
            return Blob.empty();
        }

        public boolean asBoolean() {
            return isBoolean() ? this.bb.get(this.end) != 0 : asUInt() != 0;
        }

        public String toString() {
            return toString(new StringBuilder(128)).toString();
        }

        StringBuilder toString(StringBuilder sb) {
            switch (this.type) {
                case 0:
                    sb.append("null");
                    return sb;
                case 1:
                case 6:
                    sb.append(asLong());
                    return sb;
                case 2:
                case 7:
                    sb.append(asUInt());
                    return sb;
                case 3:
                case 8:
                    sb.append(asFloat());
                    return sb;
                case 4:
                    Key asKey = asKey();
                    sb.append(Typography.quote);
                    StringBuilder key = asKey.toString(sb);
                    key.append(Typography.quote);
                    return key;
                case 5:
                    sb.append(Typography.quote);
                    sb.append(asString());
                    sb.append(Typography.quote);
                    return sb;
                case 9:
                    return asMap().toString(sb);
                case 10:
                    return asVector().toString(sb);
                case 11:
                case 12:
                case 13:
                case 14:
                case 15:
                case 36:
                    sb.append(asVector());
                    return sb;
                case 16:
                case 17:
                case 18:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                case 24:
                    throw new FlexBufferException("not_implemented:" + this.type);
                case 25:
                    return asBlob().toString(sb);
                case 26:
                    sb.append(asBoolean());
                    return sb;
                case 27:
                case 28:
                case 29:
                case 30:
                case 31:
                case 32:
                case 33:
                case 34:
                case 35:
                default:
                    return sb;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static abstract class Object {
        ReadBuf bb;
        int byteWidth;
        int end;

        public abstract StringBuilder toString(StringBuilder sb);

        Object(ReadBuf buff, int end, int byteWidth) {
            this.bb = buff;
            this.end = end;
            this.byteWidth = byteWidth;
        }

        public String toString() {
            return toString(new StringBuilder(128)).toString();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static abstract class Sized extends Object {
        protected final int size;

        Sized(ReadBuf buff, int end, int byteWidth) {
            super(buff, end, byteWidth);
            this.size = FlexBuffers.readInt(this.bb, end - byteWidth, byteWidth);
        }

        public int size() {
            return this.size;
        }
    }

    /* loaded from: classes.dex */
    public static class Blob extends Sized {
        static final /* synthetic */ boolean $assertionsDisabled = false;
        static final Blob EMPTY = new Blob(FlexBuffers.EMPTY_BB, 1, 1);

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Sized
        public /* bridge */ /* synthetic */ int size() {
            return super.size();
        }

        Blob(ReadBuf buff, int end, int byteWidth) {
            super(buff, end, byteWidth);
        }

        public static Blob empty() {
            return EMPTY;
        }

        public ByteBuffer data() {
            ByteBuffer dup = ByteBuffer.wrap(this.bb.data());
            dup.position(this.end);
            dup.limit(this.end + size());
            return dup.asReadOnlyBuffer().slice();
        }

        public byte[] getBytes() {
            int size = size();
            byte[] result = new byte[size];
            for (int i = 0; i < size; i++) {
                result[i] = this.bb.get(this.end + i);
            }
            return result;
        }

        public byte get(int pos) {
            if (pos < 0 || pos > size()) {
                throw new AssertionError();
            }
            return this.bb.get(this.end + pos);
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public String toString() {
            return this.bb.getString(this.end, size());
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public StringBuilder toString(StringBuilder sb) {
            sb.append(Typography.quote);
            sb.append(this.bb.getString(this.end, size()));
            sb.append(Typography.quote);
            return sb;
        }
    }

    /* loaded from: classes.dex */
    public static class Key extends Object {
        private static final Key EMPTY = new Key(FlexBuffers.EMPTY_BB, 0, 0);

        Key(ReadBuf buff, int end, int byteWidth) {
            super(buff, end, byteWidth);
        }

        public static Key empty() {
            return EMPTY;
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public StringBuilder toString(StringBuilder sb) {
            sb.append(toString());
            return sb;
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public String toString() {
            int i = this.end;
            while (this.bb.get(i) != 0) {
                i++;
            }
            int size = i - this.end;
            return this.bb.getString(this.end, size);
        }

        int compareTo(byte[] other) {
            byte c1;
            byte c2;
            int ia = this.end;
            int io = 0;
            do {
                c1 = this.bb.get(ia);
                c2 = other[io];
                if (c1 == 0) {
                    return c1 - c2;
                }
                ia++;
                io++;
                if (io == other.length) {
                    return c1 - c2;
                }
            } while (c1 == c2);
            return c1 - c2;
        }

        public boolean equals(java.lang.Object obj) {
            return (obj instanceof Key) && ((Key) obj).end == this.end && ((Key) obj).byteWidth == this.byteWidth;
        }

        public int hashCode() {
            return this.end ^ this.byteWidth;
        }
    }

    /* loaded from: classes.dex */
    public static class Map extends Vector {
        private static final Map EMPTY_MAP = new Map(FlexBuffers.EMPTY_BB, 1, 1);

        Map(ReadBuf bb, int end, int byteWidth) {
            super(bb, end, byteWidth);
        }

        public static Map empty() {
            return EMPTY_MAP;
        }

        public Reference get(String key) {
            return get(key.getBytes(StandardCharsets.UTF_8));
        }

        public Reference get(byte[] key) {
            KeyVector keys = keys();
            int size = keys.size();
            int index = binarySearch(keys, key);
            if (index < 0 || index >= size) {
                return Reference.NULL_REFERENCE;
            }
            return get(index);
        }

        public KeyVector keys() {
            int keysOffset = this.end - (this.byteWidth * 3);
            return new KeyVector(new TypedVector(this.bb, FlexBuffers.indirect(this.bb, keysOffset, this.byteWidth), FlexBuffers.readInt(this.bb, this.byteWidth + keysOffset, this.byteWidth), 4));
        }

        public Vector values() {
            return new Vector(this.bb, this.end, this.byteWidth);
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Vector, androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public StringBuilder toString(StringBuilder builder) {
            builder.append("{ ");
            KeyVector keys = keys();
            int size = size();
            Vector vals = values();
            for (int i = 0; i < size; i++) {
                builder.append(Typography.quote);
                builder.append(keys.get(i).toString());
                builder.append("\" : ");
                builder.append(vals.get(i).toString());
                if (i != size - 1) {
                    builder.append(", ");
                }
            }
            builder.append(" }");
            return builder;
        }

        private int binarySearch(KeyVector keys, byte[] searchedKey) {
            int low = 0;
            int high = keys.size() - 1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                Key k = keys.get(mid);
                int cmp = k.compareTo(searchedKey);
                if (cmp < 0) {
                    low = mid + 1;
                } else if (cmp > 0) {
                    high = mid - 1;
                } else {
                    return mid;
                }
            }
            return -(low + 1);
        }
    }

    /* loaded from: classes.dex */
    public static class Vector extends Sized {
        private static final Vector EMPTY_VECTOR = new Vector(FlexBuffers.EMPTY_BB, 1, 1);

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Sized
        public /* bridge */ /* synthetic */ int size() {
            return super.size();
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public /* bridge */ /* synthetic */ String toString() {
            return super.toString();
        }

        Vector(ReadBuf bb, int end, int byteWidth) {
            super(bb, end, byteWidth);
        }

        public static Vector empty() {
            return EMPTY_VECTOR;
        }

        public boolean isEmpty() {
            return this == EMPTY_VECTOR;
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Object
        public StringBuilder toString(StringBuilder sb) {
            sb.append("[ ");
            int size = size();
            for (int i = 0; i < size; i++) {
                get(i).toString(sb);
                if (i != size - 1) {
                    sb.append(", ");
                }
            }
            sb.append(" ]");
            return sb;
        }

        public Reference get(int index) {
            long len = size();
            if (index >= len) {
                return Reference.NULL_REFERENCE;
            }
            int packedType = Unsigned.byteToUnsignedInt(this.bb.get((int) (this.end + (this.byteWidth * len) + index)));
            int obj_end = this.end + (this.byteWidth * index);
            return new Reference(this.bb, obj_end, this.byteWidth, packedType);
        }
    }

    /* loaded from: classes.dex */
    public static class TypedVector extends Vector {
        private static final TypedVector EMPTY_VECTOR = new TypedVector(FlexBuffers.EMPTY_BB, 1, 1, 1);
        private final int elemType;

        TypedVector(ReadBuf bb, int end, int byteWidth, int elemType) {
            super(bb, end, byteWidth);
            this.elemType = elemType;
        }

        public static TypedVector empty() {
            return EMPTY_VECTOR;
        }

        public boolean isEmptyVector() {
            return this == EMPTY_VECTOR;
        }

        public int getElemType() {
            return this.elemType;
        }

        @Override // androidx.emoji2.text.flatbuffer.FlexBuffers.Vector
        public Reference get(int pos) {
            int len = size();
            if (pos >= len) {
                return Reference.NULL_REFERENCE;
            }
            int childPos = this.end + (this.byteWidth * pos);
            return new Reference(this.bb, childPos, this.byteWidth, 1, this.elemType);
        }
    }

    /* loaded from: classes.dex */
    public static class KeyVector {
        private final TypedVector vec;

        KeyVector(TypedVector vec) {
            this.vec = vec;
        }

        public Key get(int pos) {
            int len = size();
            if (pos >= len) {
                return Key.EMPTY;
            }
            int childPos = this.vec.end + (this.vec.byteWidth * pos);
            return new Key(this.vec.bb, FlexBuffers.indirect(this.vec.bb, childPos, this.vec.byteWidth), 1);
        }

        public int size() {
            return this.vec.size();
        }

        public String toString() {
            StringBuilder b = new StringBuilder();
            b.append('[');
            for (int i = 0; i < this.vec.size(); i++) {
                this.vec.get(i).toString(b);
                if (i != this.vec.size() - 1) {
                    b.append(", ");
                }
            }
            b.append("]");
            return b.toString();
        }
    }

    /* loaded from: classes.dex */
    public static class FlexBufferException extends RuntimeException {
        /* JADX INFO: Access modifiers changed from: package-private */
        public FlexBufferException(String msg) {
            super(msg);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Unsigned {
        Unsigned() {
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static int byteToUnsignedInt(byte x) {
            return x & UByte.MAX_VALUE;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static int shortToUnsignedInt(short x) {
            return 65535 & x;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static long intToUnsignedLong(int x) {
            return x & 4294967295L;
        }
    }
}
