package androidx.emoji2.text.flatbuffer;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public interface ReadWriteBuf extends ReadBuf {
    @Override // androidx.emoji2.text.flatbuffer.ReadBuf
    int limit();

    void put(byte b);

    void put(byte[] bArr, int i, int i2);

    void putBoolean(boolean z);

    void putDouble(double d);

    void putFloat(float f);

    void putInt(int i);

    void putLong(long j);

    void putShort(short s);

    boolean requestCapacity(int i);

    void set(int i, byte b);

    void set(int i, byte[] bArr, int i2, int i3);

    void setBoolean(int i, boolean z);

    void setDouble(int i, double d);

    void setFloat(int i, float f);

    void setInt(int i, int i2);

    void setLong(int i, long j);

    void setShort(int i, short s);

    int writePosition();
}
