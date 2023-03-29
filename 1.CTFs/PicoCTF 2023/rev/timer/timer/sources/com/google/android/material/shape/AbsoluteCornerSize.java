package com.google.android.material.shape;

import android.graphics.RectF;
import java.util.Arrays;
/* loaded from: classes.dex */
public final class AbsoluteCornerSize implements CornerSize {
    private final float size;

    public AbsoluteCornerSize(float size) {
        this.size = size;
    }

    @Override // com.google.android.material.shape.CornerSize
    public float getCornerSize(RectF bounds) {
        return this.size;
    }

    public float getCornerSize() {
        return this.size;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof AbsoluteCornerSize) {
            AbsoluteCornerSize that = (AbsoluteCornerSize) o;
            return this.size == that.size;
        }
        return false;
    }

    public int hashCode() {
        Object[] hashedFields = {Float.valueOf(this.size)};
        return Arrays.hashCode(hashedFields);
    }
}
