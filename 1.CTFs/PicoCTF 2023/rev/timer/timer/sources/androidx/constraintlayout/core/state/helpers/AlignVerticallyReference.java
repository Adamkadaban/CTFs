package androidx.constraintlayout.core.state.helpers;

import androidx.constraintlayout.core.state.ConstraintReference;
import androidx.constraintlayout.core.state.HelperReference;
import androidx.constraintlayout.core.state.State;
import java.util.Iterator;
/* loaded from: classes.dex */
public class AlignVerticallyReference extends HelperReference {
    private float mBias;

    public AlignVerticallyReference(State state) {
        super(state, State.Helper.ALIGN_VERTICALLY);
        this.mBias = 0.5f;
    }

    @Override // androidx.constraintlayout.core.state.HelperReference, androidx.constraintlayout.core.state.ConstraintReference, androidx.constraintlayout.core.state.Reference
    public void apply() {
        Iterator<Object> it = this.mReferences.iterator();
        while (it.hasNext()) {
            Object key = it.next();
            ConstraintReference reference = this.mState.constraints(key);
            reference.clearVertical();
            if (this.mTopToTop != null) {
                reference.topToTop(this.mTopToTop);
            } else if (this.mTopToBottom != null) {
                reference.topToBottom(this.mTopToBottom);
            } else {
                reference.topToTop(State.PARENT);
            }
            if (this.mBottomToTop != null) {
                reference.bottomToTop(this.mBottomToTop);
            } else if (this.mBottomToBottom != null) {
                reference.bottomToBottom(this.mBottomToBottom);
            } else {
                reference.bottomToBottom(State.PARENT);
            }
            float f = this.mBias;
            if (f != 0.5f) {
                reference.verticalBias(f);
            }
        }
    }
}
