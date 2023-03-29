package androidx.transition;

import android.animation.ObjectAnimator;
import android.animation.TypeConverter;
import android.graphics.Path;
import android.graphics.PointF;
import android.os.Build;
import android.util.Property;
/* loaded from: classes.dex */
class ObjectAnimatorUtils {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static <T> ObjectAnimator ofPointF(T target, Property<T, PointF> property, Path path) {
        if (Build.VERSION.SDK_INT >= 21) {
            return ObjectAnimator.ofObject(target, property, (TypeConverter) null, path);
        }
        return ObjectAnimator.ofFloat(target, new PathProperty(property, path), 0.0f, 1.0f);
    }

    private ObjectAnimatorUtils() {
    }
}
