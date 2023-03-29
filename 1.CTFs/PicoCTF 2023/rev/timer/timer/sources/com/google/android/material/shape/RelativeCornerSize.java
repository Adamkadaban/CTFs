package com.google.android.material.shape;

import android.graphics.RectF;
import java.util.Arrays;
/* loaded from: classes.dex */
public final class RelativeCornerSize implements CornerSize {
    private final float percent;

    public RelativeCornerSize(float percent) {
        this.percent = percent;
    }

    public float getRelativePercent() {
        return this.percent;
    }

    @Override // com.google.android.material.shape.CornerSize
    public float getCornerSize(RectF bounds) {
        return this.percent * bounds.height();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof RelativeCornerSize) {
            RelativeCornerSize that = (RelativeCornerSize) o;
            return this.percent == that.percent;
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {Float.valueOf(this.percent)};
        return Arrays.hashCode(hashedFields);
    }
}
