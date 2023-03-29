package com.google.android.material.transition.platform;

import android.graphics.Path;
import android.graphics.PointF;
import android.transition.PathMotion;
/* loaded from: classes.dex */
public final class MaterialArcMotion extends PathMotion {
    @Override // android.transition.PathMotion
    public Path getPath(float startX, float startY, float endX, float endY) {
        Path path = new Path();
        path.moveTo(startX, startY);
        PointF controlPoint = getControlPoint(startX, startY, endX, endY);
        path.quadTo(controlPoint.x, controlPoint.y, endX, endY);
        return path;
    }

    private static PointF getControlPoint(float startX, float startY, float endX, float endY) {
        if (startY > endY) {
            return new PointF(endX, startY);
        }
        return new PointF(startX, endY);
    }
}
