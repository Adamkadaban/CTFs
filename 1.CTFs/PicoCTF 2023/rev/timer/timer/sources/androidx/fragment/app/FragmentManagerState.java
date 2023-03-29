package androidx.fragment.app;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.fragment.app.FragmentManager;
import java.util.ArrayList;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class FragmentManagerState implements Parcelable {
    public static final Parcelable.Creator<FragmentManagerState> CREATOR = new Parcelable.Creator<FragmentManagerState>() { // from class: androidx.fragment.app.FragmentManagerState.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FragmentManagerState createFromParcel(Parcel in) {
            return new FragmentManagerState(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FragmentManagerState[] newArray(int size) {
            return new FragmentManagerState[size];
        }
    };
    ArrayList<FragmentState> mActive;
    ArrayList<String> mAdded;
    BackStackState[] mBackStack;
    int mBackStackIndex;
    ArrayList<FragmentManager.LaunchedFragmentInfo> mLaunchedFragments;
    String mPrimaryNavActiveWho;
    ArrayList<String> mResultKeys;
    ArrayList<Bundle> mResults;

    public FragmentManagerState() {
        this.mPrimaryNavActiveWho = null;
        this.mResultKeys = new ArrayList<>();
        this.mResults = new ArrayList<>();
    }

    public FragmentManagerState(Parcel in) {
        this.mPrimaryNavActiveWho = null;
        this.mResultKeys = new ArrayList<>();
        this.mResults = new ArrayList<>();
        this.mActive = in.createTypedArrayList(FragmentState.CREATOR);
        this.mAdded = in.createStringArrayList();
        this.mBackStack = (BackStackState[]) in.createTypedArray(BackStackState.CREATOR);
        this.mBackStackIndex = in.readInt();
        this.mPrimaryNavActiveWho = in.readString();
        this.mResultKeys = in.createStringArrayList();
        this.mResults = in.createTypedArrayList(Bundle.CREATOR);
        this.mLaunchedFragments = in.createTypedArrayList(FragmentManager.LaunchedFragmentInfo.CREATOR);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeTypedList(this.mActive);
        dest.writeStringList(this.mAdded);
        dest.writeTypedArray(this.mBackStack, flags);
        dest.writeInt(this.mBackStackIndex);
        dest.writeString(this.mPrimaryNavActiveWho);
        dest.writeStringList(this.mResultKeys);
        dest.writeTypedList(this.mResults);
        dest.writeTypedList(this.mLaunchedFragments);
    }
}
