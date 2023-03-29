package com.google.android.material.progressindicator;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.util.Property;
import androidx.interpolator.view.animation.FastOutSlowInInterpolator;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;
import com.google.android.material.animation.ArgbEvaluatorCompat;
import com.google.android.material.color.MaterialColors;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class CircularIndeterminateAnimatorDelegate extends IndeterminateAnimatorDelegate<ObjectAnimator> {
    private static final int CONSTANT_ROTATION_DEGREES = 1520;
    private static final int DURATION_TO_COLLAPSE_IN_MS = 667;
    private static final int DURATION_TO_COMPLETE_END_IN_MS = 333;
    private static final int DURATION_TO_EXPAND_IN_MS = 667;
    private static final int DURATION_TO_FADE_IN_MS = 333;
    private static final int EXTRA_DEGREES_PER_CYCLE = 250;
    private static final int TAIL_DEGREES_OFFSET = -20;
    private static final int TOTAL_CYCLES = 4;
    private static final int TOTAL_DURATION_IN_MS = 5400;
    private float animationFraction;
    private ObjectAnimator animator;
    Animatable2Compat.AnimationCallback animatorCompleteCallback;
    private final BaseProgressIndicatorSpec baseSpec;
    private ObjectAnimator completeEndAnimator;
    private float completeEndFraction;
    private int indicatorColorIndexOffset;
    private final FastOutSlowInInterpolator interpolator;
    private static final int[] DELAY_TO_EXPAND_IN_MS = {0, 1350, 2700, 4050};
    private static final int[] DELAY_TO_COLLAPSE_IN_MS = {667, 2017, 3367, 4717};
    private static final int[] DELAY_TO_FADE_IN_MS = {1000, 2350, 3700, 5050};
    private static final Property<CircularIndeterminateAnimatorDelegate, Float> ANIMATION_FRACTION = new Property<CircularIndeterminateAnimatorDelegate, Float>(Float.class, "animationFraction") { // from class: com.google.android.material.progressindicator.CircularIndeterminateAnimatorDelegate.3
        @Override // android.util.Property
        public Float get(CircularIndeterminateAnimatorDelegate delegate) {
            return Float.valueOf(delegate.getAnimationFraction());
        }

        @Override // android.util.Property
        public void set(CircularIndeterminateAnimatorDelegate delegate, Float value) {
            delegate.setAnimationFraction(value.floatValue());
        }
    };
    private static final Property<CircularIndeterminateAnimatorDelegate, Float> COMPLETE_END_FRACTION = new Property<CircularIndeterminateAnimatorDelegate, Float>(Float.class, "completeEndFraction") { // from class: com.google.android.material.progressindicator.CircularIndeterminateAnimatorDelegate.4
        @Override // android.util.Property
        public Float get(CircularIndeterminateAnimatorDelegate delegate) {
            return Float.valueOf(delegate.getCompleteEndFraction());
        }

        @Override // android.util.Property
        public void set(CircularIndeterminateAnimatorDelegate delegate, Float value) {
            delegate.setCompleteEndFraction(value.floatValue());
        }
    };

    public CircularIndeterminateAnimatorDelegate(CircularProgressIndicatorSpec spec) {
        super(1);
        this.indicatorColorIndexOffset = 0;
        this.animatorCompleteCallback = null;
        this.baseSpec = spec;
        this.interpolator = new FastOutSlowInInterpolator();
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    void startAnimator() {
        maybeInitializeAnimators();
        resetPropertiesForNewStart();
        this.animator.start();
    }

    private void maybeInitializeAnimators() {
        if (this.animator == null) {
            ObjectAnimator ofFloat = ObjectAnimator.ofFloat(this, ANIMATION_FRACTION, 0.0f, 1.0f);
            this.animator = ofFloat;
            ofFloat.setDuration(5400L);
            this.animator.setInterpolator(null);
            this.animator.setRepeatCount(-1);
            this.animator.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.progressindicator.CircularIndeterminateAnimatorDelegate.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationRepeat(Animator animation) {
                    super.onAnimationRepeat(animation);
                    CircularIndeterminateAnimatorDelegate circularIndeterminateAnimatorDelegate = CircularIndeterminateAnimatorDelegate.this;
                    circularIndeterminateAnimatorDelegate.indicatorColorIndexOffset = (circularIndeterminateAnimatorDelegate.indicatorColorIndexOffset + 4) % CircularIndeterminateAnimatorDelegate.this.baseSpec.indicatorColors.length;
                }
            });
        }
        if (this.completeEndAnimator == null) {
            ObjectAnimator ofFloat2 = ObjectAnimator.ofFloat(this, COMPLETE_END_FRACTION, 0.0f, 1.0f);
            this.completeEndAnimator = ofFloat2;
            ofFloat2.setDuration(333L);
            this.completeEndAnimator.setInterpolator(this.interpolator);
            this.completeEndAnimator.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.progressindicator.CircularIndeterminateAnimatorDelegate.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    super.onAnimationEnd(animation);
                    CircularIndeterminateAnimatorDelegate.this.cancelAnimatorImmediately();
                    if (CircularIndeterminateAnimatorDelegate.this.animatorCompleteCallback != null) {
                        CircularIndeterminateAnimatorDelegate.this.animatorCompleteCallback.onAnimationEnd(CircularIndeterminateAnimatorDelegate.this.drawable);
                    }
                }
            });
        }
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    void cancelAnimatorImmediately() {
        ObjectAnimator objectAnimator = this.animator;
        if (objectAnimator != null) {
            objectAnimator.cancel();
        }
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    void requestCancelAnimatorAfterCurrentCycle() {
        ObjectAnimator objectAnimator = this.completeEndAnimator;
        if (objectAnimator == null || objectAnimator.isRunning()) {
            return;
        }
        if (this.drawable.isVisible()) {
            this.completeEndAnimator.start();
        } else {
            cancelAnimatorImmediately();
        }
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    public void invalidateSpecValues() {
        resetPropertiesForNewStart();
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    public void registerAnimatorsCompleteCallback(Animatable2Compat.AnimationCallback callback) {
        this.animatorCompleteCallback = callback;
    }

    @Override // com.google.android.material.progressindicator.IndeterminateAnimatorDelegate
    public void unregisterAnimatorsCompleteCallback() {
        this.animatorCompleteCallback = null;
    }

    private void updateSegmentPositions(int playtime) {
        this.segmentPositions[0] = (this.animationFraction * 1520.0f) - 20.0f;
        this.segmentPositions[1] = this.animationFraction * 1520.0f;
        for (int cycleIndex = 0; cycleIndex < 4; cycleIndex++) {
            float fraction = getFractionInRange(playtime, DELAY_TO_EXPAND_IN_MS[cycleIndex], 667);
            float[] fArr = this.segmentPositions;
            fArr[1] = fArr[1] + (this.interpolator.getInterpolation(fraction) * 250.0f);
            float fraction2 = getFractionInRange(playtime, DELAY_TO_COLLAPSE_IN_MS[cycleIndex], 667);
            float[] fArr2 = this.segmentPositions;
            fArr2[0] = fArr2[0] + (this.interpolator.getInterpolation(fraction2) * 250.0f);
        }
        float[] fArr3 = this.segmentPositions;
        fArr3[0] = fArr3[0] + ((this.segmentPositions[1] - this.segmentPositions[0]) * this.completeEndFraction);
        float[] fArr4 = this.segmentPositions;
        fArr4[0] = fArr4[0] / 360.0f;
        float[] fArr5 = this.segmentPositions;
        fArr5[1] = fArr5[1] / 360.0f;
    }

    private void maybeUpdateSegmentColors(int playtime) {
        for (int cycleIndex = 0; cycleIndex < 4; cycleIndex++) {
            float timeFraction = getFractionInRange(playtime, DELAY_TO_FADE_IN_MS[cycleIndex], 333);
            if (timeFraction >= 0.0f && timeFraction <= 1.0f) {
                int startColorIndex = (this.indicatorColorIndexOffset + cycleIndex) % this.baseSpec.indicatorColors.length;
                int endColorIndex = (startColorIndex + 1) % this.baseSpec.indicatorColors.length;
                int startColor = MaterialColors.compositeARGBWithAlpha(this.baseSpec.indicatorColors[startColorIndex], this.drawable.getAlpha());
                int endColor = MaterialColors.compositeARGBWithAlpha(this.baseSpec.indicatorColors[endColorIndex], this.drawable.getAlpha());
                float colorFraction = this.interpolator.getInterpolation(timeFraction);
                this.segmentColors[0] = ArgbEvaluatorCompat.getInstance().evaluate(colorFraction, Integer.valueOf(startColor), Integer.valueOf(endColor)).intValue();
                return;
            }
        }
    }

    void resetPropertiesForNewStart() {
        this.indicatorColorIndexOffset = 0;
        this.segmentColors[0] = MaterialColors.compositeARGBWithAlpha(this.baseSpec.indicatorColors[0], this.drawable.getAlpha());
        this.completeEndFraction = 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getAnimationFraction() {
        return this.animationFraction;
    }

    void setAnimationFraction(float fraction) {
        this.animationFraction = fraction;
        int playtime = (int) (5400.0f * fraction);
        updateSegmentPositions(playtime);
        maybeUpdateSegmentColors(playtime);
        this.drawable.invalidateSelf();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getCompleteEndFraction() {
        return this.completeEndFraction;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCompleteEndFraction(float fraction) {
        this.completeEndFraction = fraction;
    }
}
