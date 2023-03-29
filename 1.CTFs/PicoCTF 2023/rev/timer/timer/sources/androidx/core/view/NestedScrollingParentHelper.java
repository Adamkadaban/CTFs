package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
/* loaded from: classes.dex */
public class NestedScrollingParentHelper {
    private int mNestedScrollAxesNonTouch;
    private int mNestedScrollAxesTouch;

    public NestedScrollingParentHelper(ViewGroup viewGroup) {
    }

    public void onNestedScrollAccepted(View child, View target, int axes) {
        onNestedScrollAccepted(child, target, axes, 0);
    }

    public void onNestedScrollAccepted(View child, View target, int axes, int type) {
        if (type == 1) {
            this.mNestedScrollAxesNonTouch = axes;
        } else {
            this.mNestedScrollAxesTouch = axes;
        }
    }

    public int getNestedScrollAxes() {
        return this.mNestedScrollAxesTouch | this.mNestedScrollAxesNonTouch;
    }

    public void onStopNestedScroll(View target) {
        onStopNestedScroll(target, 0);
    }

    public void onStopNestedScroll(View target, int type) {
        if (type == 1) {
            this.mNestedScrollAxesNonTouch = 0;
        } else {
            this.mNestedScrollAxesTouch = 0;
        }
    }
}
