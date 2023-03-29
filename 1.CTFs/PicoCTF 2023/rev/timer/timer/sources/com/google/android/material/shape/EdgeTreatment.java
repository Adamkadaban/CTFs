package com.google.android.material.shape;
/* loaded from: classes.dex */
public class EdgeTreatment {
    @Deprecated
    public void getEdgePath(float length, float interpolation, ShapePath shapePath) {
        float center = length / 2.0f;
        getEdgePath(length, center, interpolation, shapePath);
    }

    public void getEdgePath(float length, float center, float interpolation, ShapePath shapePath) {
        shapePath.lineTo(length, 0.0f);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean forceIntersection() {
        return false;
    }
}
