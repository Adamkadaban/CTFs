package androidx.fragment.app;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.Log;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.Lifecycle;
import java.util.ArrayList;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class BackStackState implements Parcelable {
    public static final Parcelable.Creator<BackStackState> CREATOR = new Parcelable.Creator<BackStackState>() { // from class: androidx.fragment.app.BackStackState.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public BackStackState createFromParcel(Parcel in) {
            return new BackStackState(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public BackStackState[] newArray(int size) {
            return new BackStackState[size];
        }
    };
    private static final String TAG = "FragmentManager";
    final int mBreadCrumbShortTitleRes;
    final CharSequence mBreadCrumbShortTitleText;
    final int mBreadCrumbTitleRes;
    final CharSequence mBreadCrumbTitleText;
    final int[] mCurrentMaxLifecycleStates;
    final ArrayList<String> mFragmentWhos;
    final int mIndex;
    final String mName;
    final int[] mOldMaxLifecycleStates;
    final int[] mOps;
    final boolean mReorderingAllowed;
    final ArrayList<String> mSharedElementSourceNames;
    final ArrayList<String> mSharedElementTargetNames;
    final int mTransition;

    public BackStackState(BackStackRecord bse) {
        int numOps = bse.mOps.size();
        this.mOps = new int[numOps * 5];
        if (!bse.mAddToBackStack) {
            throw new IllegalStateException("Not on back stack");
        }
        this.mFragmentWhos = new ArrayList<>(numOps);
        this.mOldMaxLifecycleStates = new int[numOps];
        this.mCurrentMaxLifecycleStates = new int[numOps];
        int pos = 0;
        int opNum = 0;
        while (opNum < numOps) {
            FragmentTransaction.Op op = bse.mOps.get(opNum);
            int pos2 = pos + 1;
            this.mOps[pos] = op.mCmd;
            this.mFragmentWhos.add(op.mFragment != null ? op.mFragment.mWho : null);
            int pos3 = pos2 + 1;
            this.mOps[pos2] = op.mEnterAnim;
            int pos4 = pos3 + 1;
            this.mOps[pos3] = op.mExitAnim;
            int pos5 = pos4 + 1;
            this.mOps[pos4] = op.mPopEnterAnim;
            this.mOps[pos5] = op.mPopExitAnim;
            this.mOldMaxLifecycleStates[opNum] = op.mOldMaxState.ordinal();
            this.mCurrentMaxLifecycleStates[opNum] = op.mCurrentMaxState.ordinal();
            opNum++;
            pos = pos5 + 1;
        }
        int opNum2 = bse.mTransition;
        this.mTransition = opNum2;
        this.mName = bse.mName;
        this.mIndex = bse.mIndex;
        this.mBreadCrumbTitleRes = bse.mBreadCrumbTitleRes;
        this.mBreadCrumbTitleText = bse.mBreadCrumbTitleText;
        this.mBreadCrumbShortTitleRes = bse.mBreadCrumbShortTitleRes;
        this.mBreadCrumbShortTitleText = bse.mBreadCrumbShortTitleText;
        this.mSharedElementSourceNames = bse.mSharedElementSourceNames;
        this.mSharedElementTargetNames = bse.mSharedElementTargetNames;
        this.mReorderingAllowed = bse.mReorderingAllowed;
    }

    public BackStackState(Parcel in) {
        this.mOps = in.createIntArray();
        this.mFragmentWhos = in.createStringArrayList();
        this.mOldMaxLifecycleStates = in.createIntArray();
        this.mCurrentMaxLifecycleStates = in.createIntArray();
        this.mTransition = in.readInt();
        this.mName = in.readString();
        this.mIndex = in.readInt();
        this.mBreadCrumbTitleRes = in.readInt();
        this.mBreadCrumbTitleText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        this.mBreadCrumbShortTitleRes = in.readInt();
        this.mBreadCrumbShortTitleText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        this.mSharedElementSourceNames = in.createStringArrayList();
        this.mSharedElementTargetNames = in.createStringArrayList();
        this.mReorderingAllowed = in.readInt() != 0;
    }

    public BackStackRecord instantiate(FragmentManager fm) {
        BackStackRecord bse = new BackStackRecord(fm);
        int pos = 0;
        int num = 0;
        while (pos < this.mOps.length) {
            FragmentTransaction.Op op = new FragmentTransaction.Op();
            int pos2 = pos + 1;
            op.mCmd = this.mOps[pos];
            if (FragmentManager.isLoggingEnabled(2)) {
                Log.v(TAG, "Instantiate " + bse + " op #" + num + " base fragment #" + this.mOps[pos2]);
            }
            String fWho = this.mFragmentWhos.get(num);
            if (fWho != null) {
                Fragment f = fm.findActiveFragment(fWho);
                op.mFragment = f;
            } else {
                op.mFragment = null;
            }
            op.mOldMaxState = Lifecycle.State.values()[this.mOldMaxLifecycleStates[num]];
            op.mCurrentMaxState = Lifecycle.State.values()[this.mCurrentMaxLifecycleStates[num]];
            int pos3 = pos2 + 1;
            op.mEnterAnim = this.mOps[pos2];
            int pos4 = pos3 + 1;
            op.mExitAnim = this.mOps[pos3];
            int pos5 = pos4 + 1;
            op.mPopEnterAnim = this.mOps[pos4];
            op.mPopExitAnim = this.mOps[pos5];
            bse.mEnterAnim = op.mEnterAnim;
            bse.mExitAnim = op.mExitAnim;
            bse.mPopEnterAnim = op.mPopEnterAnim;
            bse.mPopExitAnim = op.mPopExitAnim;
            bse.addOp(op);
            num++;
            pos = pos5 + 1;
        }
        bse.mTransition = this.mTransition;
        bse.mName = this.mName;
        bse.mIndex = this.mIndex;
        bse.mAddToBackStack = true;
        bse.mBreadCrumbTitleRes = this.mBreadCrumbTitleRes;
        bse.mBreadCrumbTitleText = this.mBreadCrumbTitleText;
        bse.mBreadCrumbShortTitleRes = this.mBreadCrumbShortTitleRes;
        bse.mBreadCrumbShortTitleText = this.mBreadCrumbShortTitleText;
        bse.mSharedElementSourceNames = this.mSharedElementSourceNames;
        bse.mSharedElementTargetNames = this.mSharedElementTargetNames;
        bse.mReorderingAllowed = this.mReorderingAllowed;
        bse.bumpBackStackNesting(1);
        return bse;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeIntArray(this.mOps);
        dest.writeStringList(this.mFragmentWhos);
        dest.writeIntArray(this.mOldMaxLifecycleStates);
        dest.writeIntArray(this.mCurrentMaxLifecycleStates);
        dest.writeInt(this.mTransition);
        dest.writeString(this.mName);
        dest.writeInt(this.mIndex);
        dest.writeInt(this.mBreadCrumbTitleRes);
        TextUtils.writeToParcel(this.mBreadCrumbTitleText, dest, 0);
        dest.writeInt(this.mBreadCrumbShortTitleRes);
        TextUtils.writeToParcel(this.mBreadCrumbShortTitleText, dest, 0);
        dest.writeStringList(this.mSharedElementSourceNames);
        dest.writeStringList(this.mSharedElementTargetNames);
        dest.writeInt(this.mReorderingAllowed ? 1 : 0);
    }
}
