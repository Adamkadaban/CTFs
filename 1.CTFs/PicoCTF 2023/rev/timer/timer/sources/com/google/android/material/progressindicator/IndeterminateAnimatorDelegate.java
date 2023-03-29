package com.google.android.material.progressindicator;

import android.animation.Animator;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public abstract class IndeterminateAnimatorDelegate<T extends Animator> {
    protected IndeterminateDrawable drawable;
    protected final int[] segmentColors;
    protected final float[] segmentPositions;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void cancelAnimatorImmediately();

    public abstract void invalidateSpecValues();

    public abstract void registerAnimatorsCompleteCallback(Animatable2Compat.AnimationCallback animationCallback);

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void requestCancelAnimatorAfterCurrentCycle();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void startAnimator();

    public abstract void unregisterAnimatorsCompleteCallback();

    /* JADX INFO: Access modifiers changed from: protected */
    public IndeterminateAnimatorDelegate(int segmentCount) {
        this.segmentPositions = new float[segmentCount * 2];
        this.segmentColors = new int[segmentCount];
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void registerDrawable(IndeterminateDrawable drawable) {
        this.drawable = drawable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public float getFractionInRange(int playtime, int start, int duration) {
        return (playtime - start) / duration;
    }
}
