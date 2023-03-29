package androidx.core.view;

import android.os.Build;
import android.view.ViewGroup;
/* loaded from: classes.dex */
public final class MarginLayoutParamsCompat {
    public static int getMarginStart(ViewGroup.MarginLayoutParams lp) {
        if (Build.VERSION.SDK_INT >= 17) {
            return lp.getMarginStart();
        }
        return lp.leftMargin;
    }

    public static int getMarginEnd(ViewGroup.MarginLayoutParams lp) {
        if (Build.VERSION.SDK_INT >= 17) {
            return lp.getMarginEnd();
        }
        return lp.rightMargin;
    }

    public static void setMarginStart(ViewGroup.MarginLayoutParams lp, int marginStart) {
        if (Build.VERSION.SDK_INT >= 17) {
            lp.setMarginStart(marginStart);
        } else {
            lp.leftMargin = marginStart;
        }
    }

    public static void setMarginEnd(ViewGroup.MarginLayoutParams lp, int marginEnd) {
        if (Build.VERSION.SDK_INT >= 17) {
            lp.setMarginEnd(marginEnd);
        } else {
            lp.rightMargin = marginEnd;
        }
    }

    public static boolean isMarginRelative(ViewGroup.MarginLayoutParams lp) {
        if (Build.VERSION.SDK_INT >= 17) {
            return lp.isMarginRelative();
        }
        return false;
    }

    public static int getLayoutDirection(ViewGroup.MarginLayoutParams lp) {
        int result;
        if (Build.VERSION.SDK_INT >= 17) {
            result = lp.getLayoutDirection();
        } else {
            result = 0;
        }
        if (result != 0 && result != 1) {
            return 0;
        }
        return result;
    }

    public static void setLayoutDirection(ViewGroup.MarginLayoutParams lp, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            lp.setLayoutDirection(layoutDirection);
        }
    }

    public static void resolveLayoutDirection(ViewGroup.MarginLayoutParams lp, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= 17) {
            lp.resolveLayoutDirection(layoutDirection);
        }
    }

    private MarginLayoutParamsCompat() {
    }
}
