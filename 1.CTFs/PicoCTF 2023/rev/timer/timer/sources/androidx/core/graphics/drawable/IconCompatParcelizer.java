package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import androidx.versionedparcelable.VersionedParcel;
/* loaded from: classes.dex */
public class IconCompatParcelizer {
    public static IconCompat read(VersionedParcel parcel) {
        IconCompat obj = new IconCompat();
        obj.mType = parcel.readInt(obj.mType, 1);
        obj.mData = parcel.readByteArray(obj.mData, 2);
        obj.mParcelable = parcel.readParcelable(obj.mParcelable, 3);
        obj.mInt1 = parcel.readInt(obj.mInt1, 4);
        obj.mInt2 = parcel.readInt(obj.mInt2, 5);
        obj.mTintList = (ColorStateList) parcel.readParcelable(obj.mTintList, 6);
        obj.mTintModeStr = parcel.readString(obj.mTintModeStr, 7);
        obj.mString1 = parcel.readString(obj.mString1, 8);
        obj.onPostParceling();
        return obj;
    }

    public static void write(IconCompat obj, VersionedParcel parcel) {
        parcel.setSerializationFlags(true, true);
        obj.onPreParceling(parcel.isStream());
        if (-1 != obj.mType) {
            parcel.writeInt(obj.mType, 1);
        }
        if (obj.mData != null) {
            parcel.writeByteArray(obj.mData, 2);
        }
        if (obj.mParcelable != null) {
            parcel.writeParcelable(obj.mParcelable, 3);
        }
        if (obj.mInt1 != 0) {
            parcel.writeInt(obj.mInt1, 4);
        }
        if (obj.mInt2 != 0) {
            parcel.writeInt(obj.mInt2, 5);
        }
        if (obj.mTintList != null) {
            parcel.writeParcelable(obj.mTintList, 6);
        }
        if (obj.mTintModeStr != null) {
            parcel.writeString(obj.mTintModeStr, 7);
        }
        if (obj.mString1 != null) {
            parcel.writeString(obj.mString1, 8);
        }
    }
}
