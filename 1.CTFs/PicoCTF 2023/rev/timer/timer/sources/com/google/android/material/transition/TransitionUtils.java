package com.google.android.material.transition;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.os.Build;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewParent;
import androidx.core.graphics.PathParser;
import androidx.transition.PathMotion;
import androidx.transition.PatternPathMotion;
import androidx.transition.Transition;
import androidx.transition.TransitionSet;
import com.google.android.material.motion.MotionUtils;
import com.google.android.material.shape.AbsoluteCornerSize;
import com.google.android.material.shape.CornerSize;
import com.google.android.material.shape.RelativeCornerSize;
import com.google.android.material.shape.ShapeAppearanceModel;
/* loaded from: classes.dex */
class TransitionUtils {
    static final int NO_ATTR_RES_ID = 0;
    static final int NO_DURATION = -1;
    private static final int PATH_TYPE_ARC = 1;
    private static final int PATH_TYPE_LINEAR = 0;
    private static final RectF transformAlphaRectF = new RectF();

    /* loaded from: classes.dex */
    interface CanvasOperation {
        void run(Canvas canvas);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface CornerSizeBinaryOperator {
        CornerSize apply(CornerSize cornerSize, CornerSize cornerSize2);
    }

    private TransitionUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean maybeApplyThemeInterpolator(Transition transition, Context context, int attrResId, TimeInterpolator defaultInterpolator) {
        if (attrResId != 0 && transition.getInterpolator() == null) {
            TimeInterpolator interpolator = MotionUtils.resolveThemeInterpolator(context, attrResId, defaultInterpolator);
            transition.setInterpolator(interpolator);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean maybeApplyThemeDuration(Transition transition, Context context, int attrResId) {
        int duration;
        if (attrResId != 0 && transition.getDuration() == -1 && (duration = MotionUtils.resolveThemeDuration(context, attrResId, -1)) != -1) {
            transition.setDuration(duration);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean maybeApplyThemePath(Transition transition, Context context, int attrResId) {
        PathMotion pathMotion;
        if (attrResId != 0 && (pathMotion = resolveThemePath(context, attrResId)) != null) {
            transition.setPathMotion(pathMotion);
            return true;
        }
        return false;
    }

    static PathMotion resolveThemePath(Context context, int attrResId) {
        TypedValue pathValue = new TypedValue();
        if (context.getTheme().resolveAttribute(attrResId, pathValue, true)) {
            if (pathValue.type == 16) {
                int pathInt = pathValue.data;
                if (pathInt == 0) {
                    return null;
                }
                if (pathInt == 1) {
                    return new MaterialArcMotion();
                }
                throw new IllegalArgumentException("Invalid motion path type: " + pathInt);
            } else if (pathValue.type == 3) {
                String pathString = String.valueOf(pathValue.string);
                return new PatternPathMotion(PathParser.createPathFromPathData(pathString));
            } else {
                throw new IllegalArgumentException("Motion path theme attribute must either be an enum value or path data string");
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ShapeAppearanceModel convertToRelativeCornerSizes(ShapeAppearanceModel shapeAppearanceModel, final RectF bounds) {
        return shapeAppearanceModel.withTransformedCornerSizes(new ShapeAppearanceModel.CornerSizeUnaryOperator() { // from class: com.google.android.material.transition.TransitionUtils.1
            @Override // com.google.android.material.shape.ShapeAppearanceModel.CornerSizeUnaryOperator
            public CornerSize apply(CornerSize cornerSize) {
                if (cornerSize instanceof RelativeCornerSize) {
                    return cornerSize;
                }
                return new RelativeCornerSize(cornerSize.getCornerSize(bounds) / bounds.height());
            }
        });
    }

    static ShapeAppearanceModel transformCornerSizes(ShapeAppearanceModel shapeAppearanceModel1, ShapeAppearanceModel shapeAppearanceModel2, RectF shapeAppearanceModel1Bounds, CornerSizeBinaryOperator op) {
        ShapeAppearanceModel shapeAppearanceModel;
        if (isShapeAppearanceSignificant(shapeAppearanceModel1, shapeAppearanceModel1Bounds)) {
            shapeAppearanceModel = shapeAppearanceModel1;
        } else {
            shapeAppearanceModel = shapeAppearanceModel2;
        }
        return shapeAppearanceModel.toBuilder().setTopLeftCornerSize(op.apply(shapeAppearanceModel1.getTopLeftCornerSize(), shapeAppearanceModel2.getTopLeftCornerSize())).setTopRightCornerSize(op.apply(shapeAppearanceModel1.getTopRightCornerSize(), shapeAppearanceModel2.getTopRightCornerSize())).setBottomLeftCornerSize(op.apply(shapeAppearanceModel1.getBottomLeftCornerSize(), shapeAppearanceModel2.getBottomLeftCornerSize())).setBottomRightCornerSize(op.apply(shapeAppearanceModel1.getBottomRightCornerSize(), shapeAppearanceModel2.getBottomRightCornerSize())).build();
    }

    private static boolean isShapeAppearanceSignificant(ShapeAppearanceModel shapeAppearanceModel, RectF bounds) {
        return (shapeAppearanceModel.getTopLeftCornerSize().getCornerSize(bounds) == 0.0f && shapeAppearanceModel.getTopRightCornerSize().getCornerSize(bounds) == 0.0f && shapeAppearanceModel.getBottomRightCornerSize().getCornerSize(bounds) == 0.0f && shapeAppearanceModel.getBottomLeftCornerSize().getCornerSize(bounds) == 0.0f) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lerp(float startValue, float endValue, float fraction) {
        return ((endValue - startValue) * fraction) + startValue;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lerp(float startValue, float endValue, float startFraction, float endFraction, float fraction) {
        return lerp(startValue, endValue, startFraction, endFraction, fraction, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lerp(float startValue, float endValue, float startFraction, float endFraction, float fraction, boolean allowOvershoot) {
        if (allowOvershoot && (fraction < 0.0f || fraction > 1.0f)) {
            return lerp(startValue, endValue, fraction);
        }
        if (fraction < startFraction) {
            return startValue;
        }
        if (fraction > endFraction) {
            return endValue;
        }
        return lerp(startValue, endValue, (fraction - startFraction) / (endFraction - startFraction));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int lerp(int startValue, int endValue, float startFraction, float endFraction, float fraction) {
        if (fraction < startFraction) {
            return startValue;
        }
        if (fraction > endFraction) {
            return endValue;
        }
        return (int) lerp(startValue, endValue, (fraction - startFraction) / (endFraction - startFraction));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static ShapeAppearanceModel lerp(ShapeAppearanceModel startValue, ShapeAppearanceModel endValue, final RectF startBounds, final RectF endBounds, final float startFraction, final float endFraction, final float fraction) {
        if (fraction < startFraction) {
            return startValue;
        }
        if (fraction > endFraction) {
            return endValue;
        }
        return transformCornerSizes(startValue, endValue, startBounds, new CornerSizeBinaryOperator() { // from class: com.google.android.material.transition.TransitionUtils.2
            @Override // com.google.android.material.transition.TransitionUtils.CornerSizeBinaryOperator
            public CornerSize apply(CornerSize cornerSize1, CornerSize cornerSize2) {
                float startCornerSize = cornerSize1.getCornerSize(startBounds);
                float endCornerSize = cornerSize2.getCornerSize(endBounds);
                float cornerSize = TransitionUtils.lerp(startCornerSize, endCornerSize, startFraction, endFraction, fraction);
                return new AbsoluteCornerSize(cornerSize);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Shader createColorShader(int color) {
        return new LinearGradient(0.0f, 0.0f, 0.0f, 0.0f, color, color, Shader.TileMode.CLAMP);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static View findDescendantOrAncestorById(View view, int viewId) {
        View descendant = view.findViewById(viewId);
        if (descendant != null) {
            return descendant;
        }
        return findAncestorById(view, viewId);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static View findAncestorById(View view, int ancestorId) {
        String resourceName = view.getResources().getResourceName(ancestorId);
        while (view != null) {
            if (view.getId() == ancestorId) {
                return view;
            }
            ViewParent parent = view.getParent();
            if (!(parent instanceof View)) {
                break;
            }
            view = (View) parent;
        }
        throw new IllegalArgumentException(resourceName + " is not a valid ancestor");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RectF getRelativeBounds(View view) {
        return new RectF(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
    }

    static Rect getRelativeBoundsRect(View view) {
        return new Rect(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RectF getLocationOnScreen(View view) {
        int[] location = new int[2];
        view.getLocationOnScreen(location);
        int left = location[0];
        int top = location[1];
        int right = view.getWidth() + left;
        int bottom = view.getHeight() + top;
        return new RectF(left, top, right, bottom);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static <T> T defaultIfNull(T value, T defaultValue) {
        return value != null ? value : defaultValue;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float calculateArea(RectF bounds) {
        return bounds.width() * bounds.height();
    }

    private static int saveLayerAlphaCompat(Canvas canvas, Rect bounds, int alpha) {
        RectF rectF = transformAlphaRectF;
        rectF.set(bounds);
        if (Build.VERSION.SDK_INT >= 21) {
            return canvas.saveLayerAlpha(rectF, alpha);
        }
        return canvas.saveLayerAlpha(rectF.left, rectF.top, rectF.right, rectF.bottom, alpha, 31);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void transform(Canvas canvas, Rect bounds, float dx, float dy, float scale, int alpha, CanvasOperation op) {
        if (alpha <= 0) {
            return;
        }
        int checkpoint = canvas.save();
        canvas.translate(dx, dy);
        canvas.scale(scale, scale);
        if (alpha < 255) {
            saveLayerAlphaCompat(canvas, bounds, alpha);
        }
        op.run(canvas);
        canvas.restoreToCount(checkpoint);
    }

    static void maybeAddTransition(TransitionSet transitionSet, Transition transition) {
        if (transition != null) {
            transitionSet.addTransition(transition);
        }
    }

    static void maybeRemoveTransition(TransitionSet transitionSet, Transition transition) {
        if (transition != null) {
            transitionSet.removeTransition(transition);
        }
    }
}
