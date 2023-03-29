package com.google.android.material.transition.platform;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.PointF;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.transition.ArcMotion;
import android.transition.PathMotion;
import android.transition.Transition;
import android.transition.TransitionValues;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.core.util.Preconditions;
import androidx.core.view.InputDeviceCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.shape.Shapeable;
import com.google.android.material.transition.platform.TransitionUtils;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
/* loaded from: classes.dex */
public final class MaterialContainerTransform extends Transition {
    private static final float ELEVATION_NOT_SET = -1.0f;
    public static final int FADE_MODE_CROSS = 2;
    public static final int FADE_MODE_IN = 0;
    public static final int FADE_MODE_OUT = 1;
    public static final int FADE_MODE_THROUGH = 3;
    public static final int FIT_MODE_AUTO = 0;
    public static final int FIT_MODE_HEIGHT = 2;
    public static final int FIT_MODE_WIDTH = 1;
    public static final int TRANSITION_DIRECTION_AUTO = 0;
    public static final int TRANSITION_DIRECTION_ENTER = 1;
    public static final int TRANSITION_DIRECTION_RETURN = 2;
    private boolean appliedThemeValues;
    private int containerColor;
    private boolean drawDebugEnabled;
    private int drawingViewId;
    private boolean elevationShadowEnabled;
    private int endContainerColor;
    private float endElevation;
    private ShapeAppearanceModel endShapeAppearanceModel;
    private View endView;
    private int endViewId;
    private int fadeMode;
    private ProgressThresholds fadeProgressThresholds;
    private int fitMode;
    private boolean holdAtEndEnabled;
    private boolean pathMotionCustom;
    private ProgressThresholds scaleMaskProgressThresholds;
    private ProgressThresholds scaleProgressThresholds;
    private int scrimColor;
    private ProgressThresholds shapeMaskProgressThresholds;
    private int startContainerColor;
    private float startElevation;
    private ShapeAppearanceModel startShapeAppearanceModel;
    private View startView;
    private int startViewId;
    private int transitionDirection;
    private static final String TAG = MaterialContainerTransform.class.getSimpleName();
    private static final String PROP_BOUNDS = "materialContainerTransition:bounds";
    private static final String PROP_SHAPE_APPEARANCE = "materialContainerTransition:shapeAppearance";
    private static final String[] TRANSITION_PROPS = {PROP_BOUNDS, PROP_SHAPE_APPEARANCE};
    private static final ProgressThresholdsGroup DEFAULT_ENTER_THRESHOLDS = new ProgressThresholdsGroup(new ProgressThresholds(0.0f, 0.25f), new ProgressThresholds(0.0f, 1.0f), new ProgressThresholds(0.0f, 1.0f), new ProgressThresholds(0.0f, 0.75f));
    private static final ProgressThresholdsGroup DEFAULT_RETURN_THRESHOLDS = new ProgressThresholdsGroup(new ProgressThresholds(0.6f, 0.9f), new ProgressThresholds(0.0f, 1.0f), new ProgressThresholds(0.0f, 0.9f), new ProgressThresholds(0.3f, 0.9f));
    private static final ProgressThresholdsGroup DEFAULT_ENTER_THRESHOLDS_ARC = new ProgressThresholdsGroup(new ProgressThresholds(0.1f, 0.4f), new ProgressThresholds(0.1f, 1.0f), new ProgressThresholds(0.1f, 1.0f), new ProgressThresholds(0.1f, 0.9f));
    private static final ProgressThresholdsGroup DEFAULT_RETURN_THRESHOLDS_ARC = new ProgressThresholdsGroup(new ProgressThresholds(0.6f, 0.9f), new ProgressThresholds(0.0f, 0.9f), new ProgressThresholds(0.0f, 0.9f), new ProgressThresholds(0.2f, 0.9f));

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface FadeMode {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface FitMode {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface TransitionDirection {
    }

    public MaterialContainerTransform() {
        this.drawDebugEnabled = false;
        this.holdAtEndEnabled = false;
        this.pathMotionCustom = false;
        this.appliedThemeValues = false;
        this.drawingViewId = 16908290;
        this.startViewId = -1;
        this.endViewId = -1;
        this.containerColor = 0;
        this.startContainerColor = 0;
        this.endContainerColor = 0;
        this.scrimColor = 1375731712;
        this.transitionDirection = 0;
        this.fadeMode = 0;
        this.fitMode = 0;
        this.elevationShadowEnabled = Build.VERSION.SDK_INT >= 28;
        this.startElevation = ELEVATION_NOT_SET;
        this.endElevation = ELEVATION_NOT_SET;
    }

    public MaterialContainerTransform(Context context, boolean entering) {
        this.drawDebugEnabled = false;
        this.holdAtEndEnabled = false;
        this.pathMotionCustom = false;
        this.appliedThemeValues = false;
        this.drawingViewId = 16908290;
        this.startViewId = -1;
        this.endViewId = -1;
        this.containerColor = 0;
        this.startContainerColor = 0;
        this.endContainerColor = 0;
        this.scrimColor = 1375731712;
        this.transitionDirection = 0;
        this.fadeMode = 0;
        this.fitMode = 0;
        this.elevationShadowEnabled = Build.VERSION.SDK_INT >= 28;
        this.startElevation = ELEVATION_NOT_SET;
        this.endElevation = ELEVATION_NOT_SET;
        maybeApplyThemeValues(context, entering);
        this.appliedThemeValues = true;
    }

    public int getStartViewId() {
        return this.startViewId;
    }

    public void setStartViewId(int startViewId) {
        this.startViewId = startViewId;
    }

    public int getEndViewId() {
        return this.endViewId;
    }

    public void setEndViewId(int endViewId) {
        this.endViewId = endViewId;
    }

    public View getStartView() {
        return this.startView;
    }

    public void setStartView(View startView) {
        this.startView = startView;
    }

    public View getEndView() {
        return this.endView;
    }

    public void setEndView(View endView) {
        this.endView = endView;
    }

    public ShapeAppearanceModel getStartShapeAppearanceModel() {
        return this.startShapeAppearanceModel;
    }

    public void setStartShapeAppearanceModel(ShapeAppearanceModel startShapeAppearanceModel) {
        this.startShapeAppearanceModel = startShapeAppearanceModel;
    }

    public ShapeAppearanceModel getEndShapeAppearanceModel() {
        return this.endShapeAppearanceModel;
    }

    public void setEndShapeAppearanceModel(ShapeAppearanceModel endShapeAppearanceModel) {
        this.endShapeAppearanceModel = endShapeAppearanceModel;
    }

    public boolean isElevationShadowEnabled() {
        return this.elevationShadowEnabled;
    }

    public void setElevationShadowEnabled(boolean elevationShadowEnabled) {
        this.elevationShadowEnabled = elevationShadowEnabled;
    }

    public float getStartElevation() {
        return this.startElevation;
    }

    public void setStartElevation(float startElevation) {
        this.startElevation = startElevation;
    }

    public float getEndElevation() {
        return this.endElevation;
    }

    public void setEndElevation(float endElevation) {
        this.endElevation = endElevation;
    }

    public int getDrawingViewId() {
        return this.drawingViewId;
    }

    public void setDrawingViewId(int drawingViewId) {
        this.drawingViewId = drawingViewId;
    }

    public int getContainerColor() {
        return this.containerColor;
    }

    public void setContainerColor(int containerColor) {
        this.containerColor = containerColor;
    }

    public int getStartContainerColor() {
        return this.startContainerColor;
    }

    public void setStartContainerColor(int containerColor) {
        this.startContainerColor = containerColor;
    }

    public int getEndContainerColor() {
        return this.endContainerColor;
    }

    public void setEndContainerColor(int containerColor) {
        this.endContainerColor = containerColor;
    }

    public void setAllContainerColors(int containerColor) {
        this.containerColor = containerColor;
        this.startContainerColor = containerColor;
        this.endContainerColor = containerColor;
    }

    public int getScrimColor() {
        return this.scrimColor;
    }

    public void setScrimColor(int scrimColor) {
        this.scrimColor = scrimColor;
    }

    public int getTransitionDirection() {
        return this.transitionDirection;
    }

    public void setTransitionDirection(int transitionDirection) {
        this.transitionDirection = transitionDirection;
    }

    public int getFadeMode() {
        return this.fadeMode;
    }

    public void setFadeMode(int fadeMode) {
        this.fadeMode = fadeMode;
    }

    public int getFitMode() {
        return this.fitMode;
    }

    public void setFitMode(int fitMode) {
        this.fitMode = fitMode;
    }

    public ProgressThresholds getFadeProgressThresholds() {
        return this.fadeProgressThresholds;
    }

    public void setFadeProgressThresholds(ProgressThresholds fadeProgressThresholds) {
        this.fadeProgressThresholds = fadeProgressThresholds;
    }

    public ProgressThresholds getScaleProgressThresholds() {
        return this.scaleProgressThresholds;
    }

    public void setScaleProgressThresholds(ProgressThresholds scaleProgressThresholds) {
        this.scaleProgressThresholds = scaleProgressThresholds;
    }

    public ProgressThresholds getScaleMaskProgressThresholds() {
        return this.scaleMaskProgressThresholds;
    }

    public void setScaleMaskProgressThresholds(ProgressThresholds scaleMaskProgressThresholds) {
        this.scaleMaskProgressThresholds = scaleMaskProgressThresholds;
    }

    public ProgressThresholds getShapeMaskProgressThresholds() {
        return this.shapeMaskProgressThresholds;
    }

    public void setShapeMaskProgressThresholds(ProgressThresholds shapeMaskProgressThresholds) {
        this.shapeMaskProgressThresholds = shapeMaskProgressThresholds;
    }

    public boolean isHoldAtEndEnabled() {
        return this.holdAtEndEnabled;
    }

    public void setHoldAtEndEnabled(boolean holdAtEndEnabled) {
        this.holdAtEndEnabled = holdAtEndEnabled;
    }

    public boolean isDrawDebugEnabled() {
        return this.drawDebugEnabled;
    }

    public void setDrawDebugEnabled(boolean drawDebugEnabled) {
        this.drawDebugEnabled = drawDebugEnabled;
    }

    @Override // android.transition.Transition
    public void setPathMotion(PathMotion pathMotion) {
        super.setPathMotion(pathMotion);
        this.pathMotionCustom = true;
    }

    @Override // android.transition.Transition
    public String[] getTransitionProperties() {
        return TRANSITION_PROPS;
    }

    @Override // android.transition.Transition
    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues, this.startView, this.startViewId, this.startShapeAppearanceModel);
    }

    @Override // android.transition.Transition
    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues, this.endView, this.endViewId, this.endShapeAppearanceModel);
    }

    private static void captureValues(TransitionValues transitionValues, View viewOverride, int viewIdOverride, ShapeAppearanceModel shapeAppearanceModelOverride) {
        if (viewIdOverride != -1) {
            transitionValues.view = TransitionUtils.findDescendantOrAncestorById(transitionValues.view, viewIdOverride);
        } else if (viewOverride != null) {
            transitionValues.view = viewOverride;
        } else if (transitionValues.view.getTag(R.id.mtrl_motion_snapshot_view) instanceof View) {
            transitionValues.view.setTag(R.id.mtrl_motion_snapshot_view, null);
            transitionValues.view = (View) transitionValues.view.getTag(R.id.mtrl_motion_snapshot_view);
        }
        View snapshotView = transitionValues.view;
        if (ViewCompat.isLaidOut(snapshotView) || snapshotView.getWidth() != 0 || snapshotView.getHeight() != 0) {
            RectF bounds = snapshotView.getParent() == null ? TransitionUtils.getRelativeBounds(snapshotView) : TransitionUtils.getLocationOnScreen(snapshotView);
            transitionValues.values.put(PROP_BOUNDS, bounds);
            transitionValues.values.put(PROP_SHAPE_APPEARANCE, captureShapeAppearance(snapshotView, bounds, shapeAppearanceModelOverride));
        }
    }

    private static ShapeAppearanceModel captureShapeAppearance(View view, RectF bounds, ShapeAppearanceModel shapeAppearanceModelOverride) {
        ShapeAppearanceModel shapeAppearanceModel = getShapeAppearance(view, shapeAppearanceModelOverride);
        return TransitionUtils.convertToRelativeCornerSizes(shapeAppearanceModel, bounds);
    }

    private static ShapeAppearanceModel getShapeAppearance(View view, ShapeAppearanceModel shapeAppearanceModelOverride) {
        if (shapeAppearanceModelOverride != null) {
            return shapeAppearanceModelOverride;
        }
        if (view.getTag(R.id.mtrl_motion_snapshot_view) instanceof ShapeAppearanceModel) {
            return (ShapeAppearanceModel) view.getTag(R.id.mtrl_motion_snapshot_view);
        }
        Context context = view.getContext();
        int transitionShapeAppearanceResId = getTransitionShapeAppearanceResId(context);
        if (transitionShapeAppearanceResId != -1) {
            return ShapeAppearanceModel.builder(context, transitionShapeAppearanceResId, 0).build();
        }
        if (view instanceof Shapeable) {
            return ((Shapeable) view).getShapeAppearanceModel();
        }
        return ShapeAppearanceModel.builder().build();
    }

    private static int getTransitionShapeAppearanceResId(Context context) {
        TypedArray a = context.obtainStyledAttributes(new int[]{R.attr.transitionShapeAppearance});
        int transitionShapeAppearanceResId = a.getResourceId(0, -1);
        a.recycle();
        return transitionShapeAppearanceResId;
    }

    @Override // android.transition.Transition
    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        View drawingView;
        View boundingView;
        if (startValues == null || endValues == null) {
            return null;
        }
        RectF startBounds = (RectF) startValues.values.get(PROP_BOUNDS);
        ShapeAppearanceModel startShapeAppearanceModel = (ShapeAppearanceModel) startValues.values.get(PROP_SHAPE_APPEARANCE);
        if (startBounds != null && startShapeAppearanceModel != null) {
            RectF endBounds = (RectF) endValues.values.get(PROP_BOUNDS);
            ShapeAppearanceModel endShapeAppearanceModel = (ShapeAppearanceModel) endValues.values.get(PROP_SHAPE_APPEARANCE);
            if (endBounds != null && endShapeAppearanceModel != null) {
                final View startView = startValues.view;
                final View endView = endValues.view;
                View drawingBaseView = endView.getParent() != null ? endView : startView;
                if (this.drawingViewId == drawingBaseView.getId()) {
                    drawingView = (View) drawingBaseView.getParent();
                    boundingView = drawingBaseView;
                } else {
                    drawingView = TransitionUtils.findAncestorById(drawingBaseView, this.drawingViewId);
                    boundingView = null;
                }
                RectF drawingViewBounds = TransitionUtils.getLocationOnScreen(drawingView);
                float offsetX = -drawingViewBounds.left;
                float offsetY = -drawingViewBounds.top;
                RectF drawableBounds = calculateDrawableBounds(drawingView, boundingView, offsetX, offsetY);
                startBounds.offset(offsetX, offsetY);
                endBounds.offset(offsetX, offsetY);
                boolean entering = isEntering(startBounds, endBounds);
                if (!this.appliedThemeValues) {
                    maybeApplyThemeValues(drawingBaseView.getContext(), entering);
                }
                final View drawingView2 = drawingView;
                final TransitionDrawable transitionDrawable = new TransitionDrawable(getPathMotion(), startView, startBounds, startShapeAppearanceModel, getElevationOrDefault(this.startElevation, startView), endView, endBounds, endShapeAppearanceModel, getElevationOrDefault(this.endElevation, endView), this.containerColor, this.startContainerColor, this.endContainerColor, this.scrimColor, entering, this.elevationShadowEnabled, FadeModeEvaluators.get(this.fadeMode, entering), FitModeEvaluators.get(this.fitMode, entering, startBounds, endBounds), buildThresholdsGroup(entering), this.drawDebugEnabled);
                transitionDrawable.setBounds(Math.round(drawableBounds.left), Math.round(drawableBounds.top), Math.round(drawableBounds.right), Math.round(drawableBounds.bottom));
                ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
                animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.transition.platform.MaterialContainerTransform.1
                    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                    public void onAnimationUpdate(ValueAnimator animation) {
                        transitionDrawable.setProgress(animation.getAnimatedFraction());
                    }
                });
                addListener(new TransitionListenerAdapter() { // from class: com.google.android.material.transition.platform.MaterialContainerTransform.2
                    @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                    public void onTransitionStart(Transition transition) {
                        ViewUtils.getOverlay(drawingView2).add(transitionDrawable);
                        startView.setAlpha(0.0f);
                        endView.setAlpha(0.0f);
                    }

                    @Override // com.google.android.material.transition.platform.TransitionListenerAdapter, android.transition.Transition.TransitionListener
                    public void onTransitionEnd(Transition transition) {
                        MaterialContainerTransform.this.removeListener(this);
                        if (MaterialContainerTransform.this.holdAtEndEnabled) {
                            return;
                        }
                        startView.setAlpha(1.0f);
                        endView.setAlpha(1.0f);
                        ViewUtils.getOverlay(drawingView2).remove(transitionDrawable);
                    }
                });
                return animator;
            }
            Log.w(TAG, "Skipping due to null end bounds. Ensure end view is laid out and measured.");
            return null;
        }
        Log.w(TAG, "Skipping due to null start bounds. Ensure start view is laid out and measured.");
        return null;
    }

    private void maybeApplyThemeValues(Context context, boolean entering) {
        TransitionUtils.maybeApplyThemeInterpolator(this, context, R.attr.motionEasingStandard, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
        TransitionUtils.maybeApplyThemeDuration(this, context, entering ? R.attr.motionDurationLong1 : R.attr.motionDurationMedium2);
        if (!this.pathMotionCustom) {
            TransitionUtils.maybeApplyThemePath(this, context, R.attr.motionPath);
        }
    }

    private static float getElevationOrDefault(float elevation, View view) {
        return elevation != ELEVATION_NOT_SET ? elevation : ViewCompat.getElevation(view);
    }

    private static RectF calculateDrawableBounds(View drawingView, View boundingView, float offsetX, float offsetY) {
        if (boundingView != null) {
            RectF drawableBounds = TransitionUtils.getLocationOnScreen(boundingView);
            drawableBounds.offset(offsetX, offsetY);
            return drawableBounds;
        }
        return new RectF(0.0f, 0.0f, drawingView.getWidth(), drawingView.getHeight());
    }

    private boolean isEntering(RectF startBounds, RectF endBounds) {
        switch (this.transitionDirection) {
            case 0:
                return TransitionUtils.calculateArea(endBounds) > TransitionUtils.calculateArea(startBounds);
            case 1:
                return true;
            case 2:
                return false;
            default:
                throw new IllegalArgumentException("Invalid transition direction: " + this.transitionDirection);
        }
    }

    private ProgressThresholdsGroup buildThresholdsGroup(boolean entering) {
        PathMotion pathMotion = getPathMotion();
        if ((pathMotion instanceof ArcMotion) || (pathMotion instanceof MaterialArcMotion)) {
            return getThresholdsOrDefault(entering, DEFAULT_ENTER_THRESHOLDS_ARC, DEFAULT_RETURN_THRESHOLDS_ARC);
        }
        return getThresholdsOrDefault(entering, DEFAULT_ENTER_THRESHOLDS, DEFAULT_RETURN_THRESHOLDS);
    }

    private ProgressThresholdsGroup getThresholdsOrDefault(boolean entering, ProgressThresholdsGroup defaultEnterThresholds, ProgressThresholdsGroup defaultReturnThresholds) {
        ProgressThresholdsGroup defaultThresholds = entering ? defaultEnterThresholds : defaultReturnThresholds;
        return new ProgressThresholdsGroup((ProgressThresholds) TransitionUtils.defaultIfNull(this.fadeProgressThresholds, defaultThresholds.fade), (ProgressThresholds) TransitionUtils.defaultIfNull(this.scaleProgressThresholds, defaultThresholds.scale), (ProgressThresholds) TransitionUtils.defaultIfNull(this.scaleMaskProgressThresholds, defaultThresholds.scaleMask), (ProgressThresholds) TransitionUtils.defaultIfNull(this.shapeMaskProgressThresholds, defaultThresholds.shapeMask));
    }

    /* loaded from: classes.dex */
    private static final class TransitionDrawable extends Drawable {
        private static final int COMPAT_SHADOW_COLOR = -7829368;
        private static final int SHADOW_COLOR = 754974720;
        private static final float SHADOW_DX_MULTIPLIER_ADJUSTMENT = 0.3f;
        private static final float SHADOW_DY_MULTIPLIER_ADJUSTMENT = 1.5f;
        private final MaterialShapeDrawable compatShadowDrawable;
        private final Paint containerPaint;
        private float currentElevation;
        private float currentElevationDy;
        private final RectF currentEndBounds;
        private final RectF currentEndBoundsMasked;
        private RectF currentMaskBounds;
        private final RectF currentStartBounds;
        private final RectF currentStartBoundsMasked;
        private final Paint debugPaint;
        private final Path debugPath;
        private final float displayHeight;
        private final float displayWidth;
        private final boolean drawDebugEnabled;
        private final boolean elevationShadowEnabled;
        private final RectF endBounds;
        private final Paint endContainerPaint;
        private final float endElevation;
        private final ShapeAppearanceModel endShapeAppearanceModel;
        private final View endView;
        private final boolean entering;
        private final FadeModeEvaluator fadeModeEvaluator;
        private FadeModeResult fadeModeResult;
        private final FitModeEvaluator fitModeEvaluator;
        private FitModeResult fitModeResult;
        private final MaskEvaluator maskEvaluator;
        private final float motionPathLength;
        private final PathMeasure motionPathMeasure;
        private final float[] motionPathPosition;
        private float progress;
        private final ProgressThresholdsGroup progressThresholds;
        private final Paint scrimPaint;
        private final Paint shadowPaint;
        private final RectF startBounds;
        private final Paint startContainerPaint;
        private final float startElevation;
        private final ShapeAppearanceModel startShapeAppearanceModel;
        private final View startView;

        private TransitionDrawable(PathMotion pathMotion, View startView, RectF startBounds, ShapeAppearanceModel startShapeAppearanceModel, float startElevation, View endView, RectF endBounds, ShapeAppearanceModel endShapeAppearanceModel, float endElevation, int containerColor, int startContainerColor, int endContainerColor, int scrimColor, boolean entering, boolean elevationShadowEnabled, FadeModeEvaluator fadeModeEvaluator, FitModeEvaluator fitModeEvaluator, ProgressThresholdsGroup progressThresholds, boolean drawDebugEnabled) {
            Paint paint = new Paint();
            this.containerPaint = paint;
            Paint paint2 = new Paint();
            this.startContainerPaint = paint2;
            Paint paint3 = new Paint();
            this.endContainerPaint = paint3;
            this.shadowPaint = new Paint();
            Paint paint4 = new Paint();
            this.scrimPaint = paint4;
            this.maskEvaluator = new MaskEvaluator();
            this.motionPathPosition = r7;
            MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable();
            this.compatShadowDrawable = materialShapeDrawable;
            Paint paint5 = new Paint();
            this.debugPaint = paint5;
            this.debugPath = new Path();
            this.startView = startView;
            this.startBounds = startBounds;
            this.startShapeAppearanceModel = startShapeAppearanceModel;
            this.startElevation = startElevation;
            this.endView = endView;
            this.endBounds = endBounds;
            this.endShapeAppearanceModel = endShapeAppearanceModel;
            this.endElevation = endElevation;
            this.entering = entering;
            this.elevationShadowEnabled = elevationShadowEnabled;
            this.fadeModeEvaluator = fadeModeEvaluator;
            this.fitModeEvaluator = fitModeEvaluator;
            this.progressThresholds = progressThresholds;
            this.drawDebugEnabled = drawDebugEnabled;
            WindowManager windowManager = (WindowManager) startView.getContext().getSystemService("window");
            DisplayMetrics displayMetrics = new DisplayMetrics();
            windowManager.getDefaultDisplay().getMetrics(displayMetrics);
            this.displayWidth = displayMetrics.widthPixels;
            this.displayHeight = displayMetrics.heightPixels;
            paint.setColor(containerColor);
            paint2.setColor(startContainerColor);
            paint3.setColor(endContainerColor);
            materialShapeDrawable.setFillColor(ColorStateList.valueOf(0));
            materialShapeDrawable.setShadowCompatibilityMode(2);
            materialShapeDrawable.setShadowBitmapDrawingEnable(false);
            materialShapeDrawable.setShadowColor(COMPAT_SHADOW_COLOR);
            RectF rectF = new RectF(startBounds);
            this.currentStartBounds = rectF;
            this.currentStartBoundsMasked = new RectF(rectF);
            RectF rectF2 = new RectF(rectF);
            this.currentEndBounds = rectF2;
            this.currentEndBoundsMasked = new RectF(rectF2);
            PointF startPoint = getMotionPathPoint(startBounds);
            PointF endPoint = getMotionPathPoint(endBounds);
            Path motionPath = pathMotion.getPath(startPoint.x, startPoint.y, endPoint.x, endPoint.y);
            PathMeasure pathMeasure = new PathMeasure(motionPath, false);
            this.motionPathMeasure = pathMeasure;
            this.motionPathLength = pathMeasure.getLength();
            float[] fArr = {startBounds.centerX(), startBounds.top};
            paint4.setStyle(Paint.Style.FILL);
            paint4.setShader(TransitionUtils.createColorShader(scrimColor));
            paint5.setStyle(Paint.Style.STROKE);
            paint5.setStrokeWidth(10.0f);
            updateProgress(0.0f);
        }

        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            if (this.scrimPaint.getAlpha() > 0) {
                canvas.drawRect(getBounds(), this.scrimPaint);
            }
            int debugCanvasSave = this.drawDebugEnabled ? canvas.save() : -1;
            if (this.elevationShadowEnabled && this.currentElevation > 0.0f) {
                drawElevationShadow(canvas);
            }
            this.maskEvaluator.clip(canvas);
            maybeDrawContainerColor(canvas, this.containerPaint);
            if (this.fadeModeResult.endOnTop) {
                drawStartView(canvas);
                drawEndView(canvas);
            } else {
                drawEndView(canvas);
                drawStartView(canvas);
            }
            if (this.drawDebugEnabled) {
                canvas.restoreToCount(debugCanvasSave);
                drawDebugCumulativePath(canvas, this.currentStartBounds, this.debugPath, -65281);
                drawDebugRect(canvas, this.currentStartBoundsMasked, InputDeviceCompat.SOURCE_ANY);
                drawDebugRect(canvas, this.currentStartBounds, -16711936);
                drawDebugRect(canvas, this.currentEndBoundsMasked, -16711681);
                drawDebugRect(canvas, this.currentEndBounds, -16776961);
            }
        }

        private void drawElevationShadow(Canvas canvas) {
            canvas.save();
            canvas.clipPath(this.maskEvaluator.getPath(), Region.Op.DIFFERENCE);
            if (Build.VERSION.SDK_INT > 28) {
                drawElevationShadowWithPaintShadowLayer(canvas);
            } else {
                drawElevationShadowWithMaterialShapeDrawable(canvas);
            }
            canvas.restore();
        }

        private void drawElevationShadowWithPaintShadowLayer(Canvas canvas) {
            ShapeAppearanceModel currentShapeAppearanceModel = this.maskEvaluator.getCurrentShapeAppearanceModel();
            if (currentShapeAppearanceModel.isRoundRect(this.currentMaskBounds)) {
                float radius = currentShapeAppearanceModel.getTopLeftCornerSize().getCornerSize(this.currentMaskBounds);
                canvas.drawRoundRect(this.currentMaskBounds, radius, radius, this.shadowPaint);
                return;
            }
            canvas.drawPath(this.maskEvaluator.getPath(), this.shadowPaint);
        }

        private void drawElevationShadowWithMaterialShapeDrawable(Canvas canvas) {
            this.compatShadowDrawable.setBounds((int) this.currentMaskBounds.left, (int) this.currentMaskBounds.top, (int) this.currentMaskBounds.right, (int) this.currentMaskBounds.bottom);
            this.compatShadowDrawable.setElevation(this.currentElevation);
            this.compatShadowDrawable.setShadowVerticalOffset((int) this.currentElevationDy);
            this.compatShadowDrawable.setShapeAppearanceModel(this.maskEvaluator.getCurrentShapeAppearanceModel());
            this.compatShadowDrawable.draw(canvas);
        }

        private void drawStartView(Canvas canvas) {
            maybeDrawContainerColor(canvas, this.startContainerPaint);
            TransitionUtils.transform(canvas, getBounds(), this.currentStartBounds.left, this.currentStartBounds.top, this.fitModeResult.startScale, this.fadeModeResult.startAlpha, new TransitionUtils.CanvasOperation() { // from class: com.google.android.material.transition.platform.MaterialContainerTransform.TransitionDrawable.1
                @Override // com.google.android.material.transition.platform.TransitionUtils.CanvasOperation
                public void run(Canvas canvas2) {
                    TransitionDrawable.this.startView.draw(canvas2);
                }
            });
        }

        private void drawEndView(Canvas canvas) {
            maybeDrawContainerColor(canvas, this.endContainerPaint);
            TransitionUtils.transform(canvas, getBounds(), this.currentEndBounds.left, this.currentEndBounds.top, this.fitModeResult.endScale, this.fadeModeResult.endAlpha, new TransitionUtils.CanvasOperation() { // from class: com.google.android.material.transition.platform.MaterialContainerTransform.TransitionDrawable.2
                @Override // com.google.android.material.transition.platform.TransitionUtils.CanvasOperation
                public void run(Canvas canvas2) {
                    TransitionDrawable.this.endView.draw(canvas2);
                }
            });
        }

        private void maybeDrawContainerColor(Canvas canvas, Paint containerPaint) {
            if (containerPaint.getColor() != 0 && containerPaint.getAlpha() > 0) {
                canvas.drawRect(getBounds(), containerPaint);
            }
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
            throw new UnsupportedOperationException("Setting alpha on is not supported");
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter colorFilter) {
            throw new UnsupportedOperationException("Setting a color filter is not supported");
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -3;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setProgress(float progress) {
            if (this.progress != progress) {
                updateProgress(progress);
            }
        }

        private void updateProgress(float progress) {
            float trajectoryProgress;
            float trajectoryMultiplier;
            float motionPathX;
            float motionPathY;
            this.progress = progress;
            this.scrimPaint.setAlpha((int) (this.entering ? TransitionUtils.lerp(0.0f, 255.0f, progress) : TransitionUtils.lerp(255.0f, 0.0f, progress)));
            this.motionPathMeasure.getPosTan(this.motionPathLength * progress, this.motionPathPosition, null);
            float[] fArr = this.motionPathPosition;
            float motionPathX2 = fArr[0];
            float motionPathY2 = fArr[1];
            if (progress > 1.0f || progress < 0.0f) {
                if (progress > 1.0f) {
                    trajectoryProgress = 0.99f;
                    trajectoryMultiplier = (progress - 1.0f) / (1.0f - 0.99f);
                } else {
                    trajectoryProgress = 0.01f;
                    trajectoryMultiplier = (progress / 0.01f) * MaterialContainerTransform.ELEVATION_NOT_SET;
                }
                this.motionPathMeasure.getPosTan(this.motionPathLength * trajectoryProgress, fArr, null);
                float[] fArr2 = this.motionPathPosition;
                float trajectoryMotionPathX = fArr2[0];
                float trajectoryMotionPathY = fArr2[1];
                motionPathX = motionPathX2 + ((motionPathX2 - trajectoryMotionPathX) * trajectoryMultiplier);
                motionPathY = motionPathY2 + ((motionPathY2 - trajectoryMotionPathY) * trajectoryMultiplier);
            } else {
                motionPathX = motionPathX2;
                motionPathY = motionPathY2;
            }
            float scaleStartFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.scale.start))).floatValue();
            float scaleEndFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.scale.end))).floatValue();
            FitModeResult evaluate = this.fitModeEvaluator.evaluate(progress, scaleStartFraction, scaleEndFraction, this.startBounds.width(), this.startBounds.height(), this.endBounds.width(), this.endBounds.height());
            this.fitModeResult = evaluate;
            this.currentStartBounds.set(motionPathX - (evaluate.currentStartWidth / 2.0f), motionPathY, (this.fitModeResult.currentStartWidth / 2.0f) + motionPathX, this.fitModeResult.currentStartHeight + motionPathY);
            this.currentEndBounds.set(motionPathX - (this.fitModeResult.currentEndWidth / 2.0f), motionPathY, (this.fitModeResult.currentEndWidth / 2.0f) + motionPathX, this.fitModeResult.currentEndHeight + motionPathY);
            this.currentStartBoundsMasked.set(this.currentStartBounds);
            this.currentEndBoundsMasked.set(this.currentEndBounds);
            float maskStartFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.scaleMask.start))).floatValue();
            float maskEndFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.scaleMask.end))).floatValue();
            boolean shouldMaskStartBounds = this.fitModeEvaluator.shouldMaskStartBounds(this.fitModeResult);
            RectF maskBounds = shouldMaskStartBounds ? this.currentStartBoundsMasked : this.currentEndBoundsMasked;
            float maskProgress = TransitionUtils.lerp(0.0f, 1.0f, maskStartFraction, maskEndFraction, progress);
            float maskMultiplier = shouldMaskStartBounds ? maskProgress : 1.0f - maskProgress;
            this.fitModeEvaluator.applyMask(maskBounds, maskMultiplier, this.fitModeResult);
            float min = Math.min(this.currentStartBoundsMasked.left, this.currentEndBoundsMasked.left);
            float min2 = Math.min(this.currentStartBoundsMasked.top, this.currentEndBoundsMasked.top);
            float max = Math.max(this.currentStartBoundsMasked.right, this.currentEndBoundsMasked.right);
            float f = this.currentStartBoundsMasked.bottom;
            RectF maskBounds2 = this.currentEndBoundsMasked;
            this.currentMaskBounds = new RectF(min, min2, max, Math.max(f, maskBounds2.bottom));
            this.maskEvaluator.evaluate(progress, this.startShapeAppearanceModel, this.endShapeAppearanceModel, this.currentStartBounds, this.currentStartBoundsMasked, this.currentEndBoundsMasked, this.progressThresholds.shapeMask);
            this.currentElevation = TransitionUtils.lerp(this.startElevation, this.endElevation, progress);
            float dxMultiplier = calculateElevationDxMultiplier(this.currentMaskBounds, this.displayWidth);
            float dyMultiplier = calculateElevationDyMultiplier(this.currentMaskBounds, this.displayHeight);
            float f2 = this.currentElevation;
            float currentElevationDx = (int) (f2 * dxMultiplier);
            float f3 = (int) (f2 * dyMultiplier);
            this.currentElevationDy = f3;
            this.shadowPaint.setShadowLayer(f2, currentElevationDx, f3, SHADOW_COLOR);
            float fadeStartFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.fade.start))).floatValue();
            float fadeEndFraction = ((Float) Preconditions.checkNotNull(Float.valueOf(this.progressThresholds.fade.end))).floatValue();
            this.fadeModeResult = this.fadeModeEvaluator.evaluate(progress, fadeStartFraction, fadeEndFraction, 0.35f);
            if (this.startContainerPaint.getColor() != 0) {
                this.startContainerPaint.setAlpha(this.fadeModeResult.startAlpha);
            }
            if (this.endContainerPaint.getColor() != 0) {
                this.endContainerPaint.setAlpha(this.fadeModeResult.endAlpha);
            }
            invalidateSelf();
        }

        private static PointF getMotionPathPoint(RectF bounds) {
            return new PointF(bounds.centerX(), bounds.top);
        }

        private static float calculateElevationDxMultiplier(RectF bounds, float displayWidth) {
            return ((bounds.centerX() / (displayWidth / 2.0f)) - 1.0f) * SHADOW_DX_MULTIPLIER_ADJUSTMENT;
        }

        private static float calculateElevationDyMultiplier(RectF bounds, float displayHeight) {
            return (bounds.centerY() / displayHeight) * SHADOW_DY_MULTIPLIER_ADJUSTMENT;
        }

        private void drawDebugCumulativePath(Canvas canvas, RectF bounds, Path path, int color) {
            PointF point = getMotionPathPoint(bounds);
            if (this.progress == 0.0f) {
                path.reset();
                path.moveTo(point.x, point.y);
                return;
            }
            path.lineTo(point.x, point.y);
            this.debugPaint.setColor(color);
            canvas.drawPath(path, this.debugPaint);
        }

        private void drawDebugRect(Canvas canvas, RectF bounds, int color) {
            this.debugPaint.setColor(color);
            canvas.drawRect(bounds, this.debugPaint);
        }
    }

    /* loaded from: classes.dex */
    public static class ProgressThresholds {
        private final float end;
        private final float start;

        public ProgressThresholds(float start, float end) {
            this.start = start;
            this.end = end;
        }

        public float getStart() {
            return this.start;
        }

        public float getEnd() {
            return this.end;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ProgressThresholdsGroup {
        private final ProgressThresholds fade;
        private final ProgressThresholds scale;
        private final ProgressThresholds scaleMask;
        private final ProgressThresholds shapeMask;

        private ProgressThresholdsGroup(ProgressThresholds fade, ProgressThresholds scale, ProgressThresholds scaleMask, ProgressThresholds shapeMask) {
            this.fade = fade;
            this.scale = scale;
            this.scaleMask = scaleMask;
            this.shapeMask = shapeMask;
        }
    }
}
