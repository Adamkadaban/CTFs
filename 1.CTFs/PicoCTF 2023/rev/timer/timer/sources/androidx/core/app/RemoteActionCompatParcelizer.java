package androidx.core.app;

import android.app.PendingIntent;
import androidx.core.graphics.drawable.IconCompat;
import androidx.versionedparcelable.VersionedParcel;
/* loaded from: classes.dex */
public class RemoteActionCompatParcelizer {
    public static RemoteActionCompat read(VersionedParcel parcel) {
        RemoteActionCompat obj = new RemoteActionCompat();
        obj.mIcon = (IconCompat) parcel.readVersionedParcelable(obj.mIcon, 1);
        obj.mTitle = parcel.readCharSequence(obj.mTitle, 2);
        obj.mContentDescription = parcel.readCharSequence(obj.mContentDescription, 3);
        obj.mActionIntent = (PendingIntent) parcel.readParcelable(obj.mActionIntent, 4);
        obj.mEnabled = parcel.readBoolean(obj.mEnabled, 5);
        obj.mShouldShowIcon = parcel.readBoolean(obj.mShouldShowIcon, 6);
        return obj;
    }

    public static void write(RemoteActionCompat obj, VersionedParcel parcel) {
        parcel.setSerializationFlags(false, false);
        parcel.writeVersionedParcelable(obj.mIcon, 1);
        parcel.writeCharSequence(obj.mTitle, 2);
        parcel.writeCharSequence(obj.mContentDescription, 3);
        parcel.writeParcelable(obj.mActionIntent, 4);
        parcel.writeBoolean(obj.mEnabled, 5);
        parcel.writeBoolean(obj.mShouldShowIcon, 6);
    }
}
