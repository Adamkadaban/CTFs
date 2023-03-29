package androidx.transition;

import android.animation.TypeEvaluator;
import android.graphics.Rect;
/* loaded from: classes.dex */
class RectEvaluator implements TypeEvaluator<Rect> {
    private Rect mRect;

    /* JADX INFO: Access modifiers changed from: package-private */
    public RectEvaluator() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RectEvaluator(Rect reuseRect) {
        this.mRect = reuseRect;
    }

    @Override // android.animation.TypeEvaluator
    public Rect evaluate(float fraction, Rect startValue, Rect endValue) {
        int left = startValue.left + ((int) ((endValue.left - startValue.left) * fraction));
        int top = startValue.top + ((int) ((endValue.top - startValue.top) * fraction));
        int right = startValue.right + ((int) ((endValue.right - startValue.right) * fraction));
        int bottom = startValue.bottom + ((int) ((endValue.bottom - startValue.bottom) * fraction));
        Rect rect = this.mRect;
        if (rect == null) {
            return new Rect(left, top, right, bottom);
        }
        rect.set(left, top, right, bottom);
        return this.mRect;
    }
}
