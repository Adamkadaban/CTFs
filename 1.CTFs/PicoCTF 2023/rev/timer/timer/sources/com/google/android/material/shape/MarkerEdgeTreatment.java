package com.google.android.material.shape;
/* loaded from: classes.dex */
public final class MarkerEdgeTreatment extends EdgeTreatment {
    private final float radius;

    public MarkerEdgeTreatment(float radius) {
        this.radius = radius - 0.001f;
    }

    @Override // com.google.android.material.shape.EdgeTreatment
    public void getEdgePath(float length, float center, float interpolation, ShapePath shapePath) {
        float side = (float) ((this.radius * Math.sqrt(2.0d)) / 2.0d);
        float side2 = (float) Math.sqrt(Math.pow(this.radius, 2.0d) - Math.pow(side, 2.0d));
        shapePath.reset(center - side, ((float) (-((this.radius * Math.sqrt(2.0d)) - this.radius))) + side2);
        shapePath.lineTo(center, (float) (-((this.radius * Math.sqrt(2.0d)) - this.radius)));
        shapePath.lineTo(center + side, ((float) (-((this.radius * Math.sqrt(2.0d)) - this.radius))) + side2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.shape.EdgeTreatment
    public boolean forceIntersection() {
        return true;
    }
}
