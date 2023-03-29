package androidx.core.view;

import android.graphics.Rect;
import android.os.Build;
import android.view.Gravity;
/* loaded from: classes.dex */
public final class GravityCompat {
    public static final int END = 8388613;
    public static final int RELATIVE_HORIZONTAL_GRAVITY_MASK = 8388615;
    public static final int RELATIVE_LAYOUT_DIRECTION = 8388608;
    public static final int START = 8388611;

    public static void apply(int gravity, int w, int h, Rect container, Rect outRect, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            Gravity.apply(gravity, w, h, container, outRect, layoutDirection);
        } else {
            Gravity.apply(gravity, w, h, container, outRect);
        }
    }

    public static void apply(int gravity, int w, int h, Rect container, int xAdj, int yAdj, Rect outRect, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            Gravity.apply(gravity, w, h, container, xAdj, yAdj, outRect, layoutDirection);
        } else {
            Gravity.apply(gravity, w, h, container, xAdj, yAdj, outRect);
        }
    }

    public static void applyDisplay(int gravity, Rect display, Rect inoutObj, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            Gravity.applyDisplay(gravity, display, inoutObj, layoutDirection);
        } else {
            Gravity.applyDisplay(gravity, display, inoutObj);
        }
    }

    public static int getAbsoluteGravity(int gravity, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            return Gravity.getAbsoluteGravity(gravity, layoutDirection);
        }
        return (-8388609) & gravity;
    }

    private GravityCompat() {
    }
}
