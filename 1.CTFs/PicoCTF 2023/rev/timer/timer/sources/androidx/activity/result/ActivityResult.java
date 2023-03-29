package androidx.activity.result;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
/* loaded from: classes.dex */
public final class ActivityResult implements Parcelable {
    public static final Parcelable.Creator<ActivityResult> CREATOR = new Parcelable.Creator<ActivityResult>() { // from class: androidx.activity.result.ActivityResult.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ActivityResult createFromParcel(Parcel in) {
            return new ActivityResult(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ActivityResult[] newArray(int size) {
            return new ActivityResult[size];
        }
    };
    private final Intent mData;
    private final int mResultCode;

    public ActivityResult(int resultCode, Intent data) {
        this.mResultCode = resultCode;
        this.mData = data;
    }

    ActivityResult(Parcel in) {
        this.mResultCode = in.readInt();
        this.mData = in.readInt() == 0 ? null : (Intent) Intent.CREATOR.createFromParcel(in);
    }

    public int getResultCode() {
        return this.mResultCode;
    }

    public Intent getData() {
        return this.mData;
    }

    public String toString() {
        return "ActivityResult{resultCode=" + resultCodeToString(this.mResultCode) + ", data=" + this.mData + '}';
    }

    public static String resultCodeToString(int resultCode) {
        switch (resultCode) {
            case -1:
                return "RESULT_OK";
            case 0:
                return "RESULT_CANCELED";
            default:
                return String.valueOf(resultCode);
        }
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.mResultCode);
        dest.writeInt(this.mData == null ? 0 : 1);
        Intent intent = this.mData;
        if (intent != null) {
            intent.writeToParcel(dest, flags);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }
}
