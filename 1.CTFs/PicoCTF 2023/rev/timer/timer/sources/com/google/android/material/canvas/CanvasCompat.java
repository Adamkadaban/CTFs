package com.google.android.material.canvas;

import android.graphics.Canvas;
import android.graphics.RectF;
import android.os.Build;
/* loaded from: classes.dex */
public class CanvasCompat {
    private CanvasCompat() {
    }

    public static int saveLayerAlpha(Canvas canvas, RectF bounds, int alpha) {
        if (Build.VERSION.SDK_INT > 21) {
            return canvas.saveLayerAlpha(bounds, alpha);
        }
        return canvas.saveLayerAlpha(bounds, alpha, 31);
    }

    public static int saveLayerAlpha(Canvas canvas, float left, float top, float right, float bottom, int alpha) {
        if (Build.VERSION.SDK_INT > 21) {
            return canvas.saveLayerAlpha(left, top, right, bottom, alpha);
        }
        return canvas.saveLayerAlpha(left, top, right, bottom, alpha, 31);
    }
}
