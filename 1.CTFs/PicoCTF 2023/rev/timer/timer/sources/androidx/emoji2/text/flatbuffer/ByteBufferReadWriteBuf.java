package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
/* loaded from: classes.dex */
public class ByteBufferReadWriteBuf implements ReadWriteBuf {
    private final ByteBuffer buffer;

    public ByteBufferReadWriteBuf(ByteBuffer bb) {
        this.buffer = bb;
        bb.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public boolean getBoolean(int index) {
        return get(index) != 0;
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public byte get(int index) {
        return this.buffer.get(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public short getShort(int index) {
        return this.buffer.getShort(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public int getInt(int index) {
        return this.buffer.getInt(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public long getLong(int index) {
        return this.buffer.getLong(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public float getFloat(int index) {
        return this.buffer.getFloat(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public double getDouble(int index) {
        return this.buffer.getDouble(index);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public String getString(int start, int size) {
        return Utf8Safe.decodeUtf8Buffer(this.buffer, start, size);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    public byte[] data() {
        return this.buffer.array();
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putBoolean(boolean value) {
        this.buffer.put(value ? (byte) 1 : (byte) 0);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void put(byte[] value, int start, int length) {
        this.buffer.put(value, start, length);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void put(byte value) {
        this.buffer.put(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putShort(short value) {
        this.buffer.putShort(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putInt(int value) {
        this.buffer.putInt(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putLong(long value) {
        this.buffer.putLong(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putFloat(float value) {
        this.buffer.putFloat(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void putDouble(double value) {
        this.buffer.putDouble(value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setBoolean(int index, boolean value) {
        set(index, value ? (byte) 1 : (byte) 0);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void set(int index, byte value) {
        requestCapacity(index + 1);
        this.buffer.put(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void set(int index, byte[] value, int start, int length) {
        requestCapacity((length - start) + index);
        int curPos = this.buffer.position();
        this.buffer.position(index);
        this.buffer.put(value, start, length);
        this.buffer.position(curPos);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setShort(int index, short value) {
        requestCapacity(index + 2);
        this.buffer.putShort(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setInt(int index, int value) {
        requestCapacity(index + 4);
        this.buffer.putInt(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setLong(int index, long value) {
        requestCapacity(index + 8);
        this.buffer.putLong(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setFloat(int index, float value) {
        requestCapacity(index + 4);
        this.buffer.putFloat(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public void setDouble(int index, double value) {
        requestCapacity(index + 8);
        this.buffer.putDouble(index, value);
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public int writePosition() {
        return this.buffer.position();
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf, androidx.emoji2.text.flatbuffer.ReadBuf
    public int limit() {
        return this.buffer.limit();
    }

    @Override // androidx.emoji2.text.flatbuffer.ReadWriteBuf
    public boolean requestCapacity(int capacity) {
        return capacity <= this.buffer.limit();
    }
}
