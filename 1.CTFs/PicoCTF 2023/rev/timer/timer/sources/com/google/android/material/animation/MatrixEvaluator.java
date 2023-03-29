package com.google.android.material.animation;

import android.animation.TypeEvaluator;
import android.graphics.Matrix;
/* loaded from: classes.dex */
public class MatrixEvaluator implements TypeEvaluator<Matrix> {
    private final float[] tempStartValues = new float[9];
    private final float[] tempEndValues = new float[9];
    private final Matrix tempMatrix = new Matrix();

    @Override // android.animation.TypeEvaluator
    public Matrix evaluate(float fraction, Matrix startValue, Matrix endValue) {
        startValue.getValues(this.tempStartValues);
        endValue.getValues(this.tempEndValues);
        for (int i = 0; i < 9; i++) {
            float[] fArr = this.tempEndValues;
            float f = fArr[i];
            float[] fArr2 = this.tempStartValues;
            float diff = f - fArr2[i];
            fArr[i] = fArr2[i] + (fraction * diff);
        }
        this.tempMatrix.setValues(this.tempEndValues);
        return this.tempMatrix;
    }
}
