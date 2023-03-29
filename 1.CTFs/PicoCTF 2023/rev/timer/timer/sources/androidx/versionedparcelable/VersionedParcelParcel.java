package androidx.versionedparcelable;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.SparseIntArray;
import androidx.collection.ArrayMap;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
class VersionedParcelParcel extends VersionedParcel {
    private static final boolean DEBUG = false;
    private static final String TAG = "VersionedParcelParcel";
    private int mCurrentField;
    private final int mEnd;
    private int mFieldId;
    private int mNextRead;
    private final int mOffset;
    private final Parcel mParcel;
    private final SparseIntArray mPositionLookup;
    private final String mPrefix;

    /* JADX INFO: Access modifiers changed from: package-private */
    public VersionedParcelParcel(Parcel p) {
        this(p, p.dataPosition(), p.dataSize(), "", new ArrayMap(), new ArrayMap(), new ArrayMap());
    }

    private VersionedParcelParcel(Parcel p, int offset, int end, String prefix, ArrayMap<String, Method> readCache, ArrayMap<String, Method> writeCache, ArrayMap<String, Class> parcelizerCache) {
        super(readCache, writeCache, parcelizerCache);
        this.mPositionLookup = new SparseIntArray();
        this.mCurrentField = -1;
        this.mNextRead = 0;
        this.mFieldId = -1;
        this.mParcel = p;
        this.mOffset = offset;
        this.mEnd = end;
        this.mNextRead = offset;
        this.mPrefix = prefix;
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public boolean readField(int fieldId) {
        while (this.mNextRead < this.mEnd) {
            int i = this.mFieldId;
            if (i == fieldId) {
                return true;
            }
            if (String.valueOf(i).compareTo(String.valueOf(fieldId)) > 0) {
                return false;
            }
            this.mParcel.setDataPosition(this.mNextRead);
            int size = this.mParcel.readInt();
            this.mFieldId = this.mParcel.readInt();
            this.mNextRead += size;
        }
        return this.mFieldId == fieldId;
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void setOutputField(int fieldId) {
        closeField();
        this.mCurrentField = fieldId;
        this.mPositionLookup.put(fieldId, this.mParcel.dataPosition());
        writeInt(0);
        writeInt(fieldId);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void closeField() {
        int i = this.mCurrentField;
        if (i >= 0) {
            int currentFieldPosition = this.mPositionLookup.get(i);
            int position = this.mParcel.dataPosition();
            int size = position - currentFieldPosition;
            this.mParcel.setDataPosition(currentFieldPosition);
            this.mParcel.writeInt(size);
            this.mParcel.setDataPosition(position);
        }
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    protected VersionedParcel createSubParcel() {
        Parcel parcel = this.mParcel;
        int dataPosition = parcel.dataPosition();
        int i = this.mNextRead;
        if (i == this.mOffset) {
            i = this.mEnd;
        }
        int i2 = i;
        return new VersionedParcelParcel(parcel, dataPosition, i2, this.mPrefix + "  ", this.mReadCache, this.mWriteCache, this.mParcelizerCache);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeByteArray(byte[] b) {
        if (b != null) {
            this.mParcel.writeInt(b.length);
            this.mParcel.writeByteArray(b);
            return;
        }
        this.mParcel.writeInt(-1);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeByteArray(byte[] b, int offset, int len) {
        if (b != null) {
            this.mParcel.writeInt(b.length);
            this.mParcel.writeByteArray(b, offset, len);
            return;
        }
        this.mParcel.writeInt(-1);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeInt(int val) {
        this.mParcel.writeInt(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeLong(long val) {
        this.mParcel.writeLong(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeFloat(float val) {
        this.mParcel.writeFloat(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeDouble(double val) {
        this.mParcel.writeDouble(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeString(String val) {
        this.mParcel.writeString(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeStrongBinder(IBinder val) {
        this.mParcel.writeStrongBinder(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeParcelable(Parcelable p) {
        this.mParcel.writeParcelable(p, 0);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeBoolean(boolean val) {
        this.mParcel.writeInt(val ? 1 : 0);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeStrongInterface(IInterface val) {
        this.mParcel.writeStrongInterface(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public void writeBundle(Bundle val) {
        this.mParcel.writeBundle(val);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    protected void writeCharSequence(CharSequence charSequence) {
        TextUtils.writeToParcel(charSequence, this.mParcel, 0);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    protected CharSequence readCharSequence() {
        return (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(this.mParcel);
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public int readInt() {
        return this.mParcel.readInt();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public long readLong() {
        return this.mParcel.readLong();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public float readFloat() {
        return this.mParcel.readFloat();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public double readDouble() {
        return this.mParcel.readDouble();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public String readString() {
        return this.mParcel.readString();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public IBinder readStrongBinder() {
        return this.mParcel.readStrongBinder();
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public byte[] readByteArray() {
        int len = this.mParcel.readInt();
        if (len < 0) {
            return null;
        }
        byte[] bytes = new byte[len];
        this.mParcel.readByteArray(bytes);
        return bytes;
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public <T extends Parcelable> T readParcelable() {
        return (T) this.mParcel.readParcelable(getClass().getClassLoader());
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public Bundle readBundle() {
        return this.mParcel.readBundle(getClass().getClassLoader());
    }

    @Override // androidx.versionedparcelable.VersionedParcel
    public boolean readBoolean() {
        return this.mParcel.readInt() != 0;
    }
}
