package com.google.android.material.shape;
/* loaded from: classes.dex */
public class CutCornerTreatment extends CornerTreatment {
    float size;

    public CutCornerTreatment() {
        this.size = -1.0f;
    }

    @Deprecated
    public CutCornerTreatment(float size) {
        this.size = -1.0f;
        this.size = size;
    }

    @Override // com.google.android.material.shape.CornerTreatment
    public void getCornerPath(ShapePath shapePath, float angle, float interpolation, float radius) {
        shapePath.reset(0.0f, radius * interpolation, 180.0f, 180.0f - angle);
        shapePath.lineTo((float) (Math.sin(Math.toRadians(angle)) * radius * interpolation), (float) (Math.sin(Math.toRadians(90.0f - angle)) * radius * interpolation));
    }
}
