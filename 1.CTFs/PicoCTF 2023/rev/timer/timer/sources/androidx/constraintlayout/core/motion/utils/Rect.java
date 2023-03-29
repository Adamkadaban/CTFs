package androidx.constraintlayout.core.motion.utils;
/* loaded from: classes.dex */
public class Rect {
    public int bottom;
    public int left;
    public int right;
    public int top;

    public int width() {
        return this.right - this.left;
    }

    public int height() {
        return this.bottom - this.top;
    }
}
