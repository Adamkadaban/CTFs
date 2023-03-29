package androidx.constraintlayout.motion.utils;

import android.view.View;
/* loaded from: classes.dex */
public class ViewState {
    public int bottom;
    public int left;
    public int right;
    public float rotation;
    public int top;

    public void getState(View v) {
        this.left = v.getLeft();
        this.top = v.getTop();
        this.right = v.getRight();
        this.bottom = v.getBottom();
        this.rotation = v.getRotation();
    }

    public int width() {
        return this.right - this.left;
    }

    public int height() {
        return this.bottom - this.top;
    }
}
