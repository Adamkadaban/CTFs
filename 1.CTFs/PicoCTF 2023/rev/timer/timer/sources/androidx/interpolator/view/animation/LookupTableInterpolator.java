package androidx.interpolator.view.animation;

import android.view.animation.Interpolator;
/* loaded from: classes.dex */
abstract class LookupTableInterpolator implements Interpolator {
    private final float mStepSize;
    private final float[] mValues;

    /* JADX INFO: Access modifiers changed from: protected */
    public LookupTableInterpolator(float[] values) {
        this.mValues = values;
        this.mStepSize = 1.0f / (values.length - 1);
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float input) {
        if (input >= 1.0f) {
            return 1.0f;
        }
        if (input <= 0.0f) {
            return 0.0f;
        }
        float[] fArr = this.mValues;
        int position = Math.min((int) ((fArr.length - 1) * input), fArr.length - 2);
        float f = this.mStepSize;
        float quantized = position * f;
        float diff = input - quantized;
        float weight = diff / f;
        float[] fArr2 = this.mValues;
        return fArr2[position] + ((fArr2[position + 1] - fArr2[position]) * weight);
    }
}
