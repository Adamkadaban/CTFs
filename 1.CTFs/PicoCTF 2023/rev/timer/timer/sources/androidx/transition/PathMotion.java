package androidx.transition;

import android.content.Context;
import android.graphics.Path;
import android.util.AttributeSet;
/* loaded from: classes.dex */
public abstract class PathMotion {
    public abstract Path getPath(float f, float f2, float f3, float f4);

    public PathMotion() {
    }

    public PathMotion(Context context, AttributeSet attrs) {
    }
}
