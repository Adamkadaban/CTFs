package com.google.android.material.progressindicator;

import android.graphics.Canvas;
import android.graphics.Paint;
import com.google.android.material.progressindicator.BaseProgressIndicatorSpec;
/* loaded from: classes.dex */
abstract class DrawingDelegate<S extends BaseProgressIndicatorSpec> {
    protected DrawableWithAnimatedVisibilityChange drawable;
    S spec;

    abstract void adjustCanvas(Canvas canvas, float f);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void fillIndicator(Canvas canvas, Paint paint, float f, float f2, int i);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void fillTrack(Canvas canvas, Paint paint);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract int getPreferredHeight();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract int getPreferredWidth();

    public DrawingDelegate(S spec) {
        this.spec = spec;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void registerDrawable(DrawableWithAnimatedVisibilityChange drawable) {
        this.drawable = drawable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void validateSpecAndAdjustCanvas(Canvas canvas, float trackThicknessFraction) {
        this.spec.validateSpec();
        adjustCanvas(canvas, trackThicknessFraction);
    }
}
