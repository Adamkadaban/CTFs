package androidx.core.view.animation;

import android.graphics.Path;
import android.os.Build;
import android.view.animation.Interpolator;
import android.view.animation.PathInterpolator;
/* loaded from: classes.dex */
public final class PathInterpolatorCompat {
    private PathInterpolatorCompat() {
    }

    public static Interpolator create(Path path) {
        if (Build.VERSION.SDK_INT >= 21) {
            return new PathInterpolator(path);
        }
        return new PathInterpolatorApi14(path);
    }

    public static Interpolator create(float controlX, float controlY) {
        if (Build.VERSION.SDK_INT >= 21) {
            return new PathInterpolator(controlX, controlY);
        }
        return new PathInterpolatorApi14(controlX, controlY);
    }

    public static Interpolator create(float controlX1, float controlY1, float controlX2, float controlY2) {
        if (Build.VERSION.SDK_INT >= 21) {
            return new PathInterpolator(controlX1, controlY1, controlX2, controlY2);
        }
        return new PathInterpolatorApi14(controlX1, controlY1, controlX2, controlY2);
    }
}
