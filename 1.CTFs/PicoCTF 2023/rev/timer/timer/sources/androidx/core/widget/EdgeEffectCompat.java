package androidx.core.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.os.Build;
import android.util.AttributeSet;
import android.widget.EdgeEffect;
import androidx.core.os.BuildCompat;
/* loaded from: classes.dex */
public final class EdgeEffectCompat {
    private EdgeEffect mEdgeEffect;

    @Deprecated
    public EdgeEffectCompat(Context context) {
        this.mEdgeEffect = new EdgeEffect(context);
    }

    public static EdgeEffect create(Context context, AttributeSet attrs) {
        if (BuildCompat.isAtLeastS()) {
            return Api31Impl.create(context, attrs);
        }
        return new EdgeEffect(context);
    }

    public static float getDistance(EdgeEffect edgeEffect) {
        if (BuildCompat.isAtLeastS()) {
            return Api31Impl.getDistance(edgeEffect);
        }
        return 0.0f;
    }

    @Deprecated
    public void setSize(int width, int height) {
        this.mEdgeEffect.setSize(width, height);
    }

    @Deprecated
    public boolean isFinished() {
        return this.mEdgeEffect.isFinished();
    }

    @Deprecated
    public void finish() {
        this.mEdgeEffect.finish();
    }

    @Deprecated
    public boolean onPull(float deltaDistance) {
        this.mEdgeEffect.onPull(deltaDistance);
        return true;
    }

    @Deprecated
    public boolean onPull(float deltaDistance, float displacement) {
        onPull(this.mEdgeEffect, deltaDistance, displacement);
        return true;
    }

    public static void onPull(EdgeEffect edgeEffect, float deltaDistance, float displacement) {
        if (Build.VERSION.SDK_INT >= 21) {
            edgeEffect.onPull(deltaDistance, displacement);
        } else {
            edgeEffect.onPull(deltaDistance);
        }
    }

    public static float onPullDistance(EdgeEffect edgeEffect, float deltaDistance, float displacement) {
        if (BuildCompat.isAtLeastS()) {
            return Api31Impl.onPullDistance(edgeEffect, deltaDistance, displacement);
        }
        onPull(edgeEffect, deltaDistance, displacement);
        return deltaDistance;
    }

    @Deprecated
    public boolean onRelease() {
        this.mEdgeEffect.onRelease();
        return this.mEdgeEffect.isFinished();
    }

    @Deprecated
    public boolean onAbsorb(int velocity) {
        this.mEdgeEffect.onAbsorb(velocity);
        return true;
    }

    @Deprecated
    public boolean draw(Canvas canvas) {
        return this.mEdgeEffect.draw(canvas);
    }

    /* loaded from: classes.dex */
    private static class Api31Impl {
        private Api31Impl() {
        }

        public static EdgeEffect create(Context context, AttributeSet attrs) {
            try {
                return new EdgeEffect(context, attrs);
            } catch (Throwable th) {
                return new EdgeEffect(context);
            }
        }

        public static float onPullDistance(EdgeEffect edgeEffect, float deltaDistance, float displacement) {
            try {
                return edgeEffect.onPullDistance(deltaDistance, displacement);
            } catch (Throwable th) {
                edgeEffect.onPull(deltaDistance, displacement);
                return 0.0f;
            }
        }

        public static float getDistance(EdgeEffect edgeEffect) {
            try {
                return edgeEffect.getDistance();
            } catch (Throwable th) {
                return 0.0f;
            }
        }
    }
}
