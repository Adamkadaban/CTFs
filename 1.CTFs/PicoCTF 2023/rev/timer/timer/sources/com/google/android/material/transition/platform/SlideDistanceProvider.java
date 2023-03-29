package com.google.android.material.transition.platform;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
/* loaded from: classes.dex */
public final class SlideDistanceProvider implements VisibilityAnimatorProvider {
    private static final int DEFAULT_DISTANCE = -1;
    private int slideDistance = -1;
    private int slideEdge;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface GravityFlag {
    }

    public SlideDistanceProvider(int slideEdge) {
        this.slideEdge = slideEdge;
    }

    public int getSlideEdge() {
        return this.slideEdge;
    }

    public void setSlideEdge(int slideEdge) {
        this.slideEdge = slideEdge;
    }

    public int getSlideDistance() {
        return this.slideDistance;
    }

    public void setSlideDistance(int slideDistance) {
        if (slideDistance < 0) {
            throw new IllegalArgumentException("Slide distance must be positive. If attempting to reverse the direction of the slide, use setSlideEdge(int) instead.");
        }
        this.slideDistance = slideDistance;
    }

    @Override // com.google.android.material.transition.platform.VisibilityAnimatorProvider
    public Animator createAppear(ViewGroup sceneRoot, View view) {
        return createTranslationAppearAnimator(sceneRoot, view, this.slideEdge, getSlideDistanceOrDefault(view.getContext()));
    }

    @Override // com.google.android.material.transition.platform.VisibilityAnimatorProvider
    public Animator createDisappear(ViewGroup sceneRoot, View view) {
        return createTranslationDisappearAnimator(sceneRoot, view, this.slideEdge, getSlideDistanceOrDefault(view.getContext()));
    }

    private int getSlideDistanceOrDefault(Context context) {
        int i = this.slideDistance;
        if (i != -1) {
            return i;
        }
        return context.getResources().getDimensionPixelSize(R.dimen.mtrl_transition_shared_axis_slide_distance);
    }

    private static Animator createTranslationAppearAnimator(View sceneRoot, View view, int slideEdge, int slideDistance) {
        float originalX = view.getTranslationX();
        float originalY = view.getTranslationY();
        switch (slideEdge) {
            case 3:
                return createTranslationXAnimator(view, slideDistance + originalX, originalX, originalX);
            case 5:
                return createTranslationXAnimator(view, originalX - slideDistance, originalX, originalX);
            case 48:
                return createTranslationYAnimator(view, originalY - slideDistance, originalY, originalY);
            case 80:
                return createTranslationYAnimator(view, slideDistance + originalY, originalY, originalY);
            case GravityCompat.START /* 8388611 */:
                return createTranslationXAnimator(view, isRtl(sceneRoot) ? slideDistance + originalX : originalX - slideDistance, originalX, originalX);
            case GravityCompat.END /* 8388613 */:
                return createTranslationXAnimator(view, isRtl(sceneRoot) ? originalX - slideDistance : slideDistance + originalX, originalX, originalX);
            default:
                throw new IllegalArgumentException("Invalid slide direction: " + slideEdge);
        }
    }

    private static Animator createTranslationDisappearAnimator(View sceneRoot, View view, int slideEdge, int slideDistance) {
        float originalX = view.getTranslationX();
        float originalY = view.getTranslationY();
        switch (slideEdge) {
            case 3:
                return createTranslationXAnimator(view, originalX, originalX - slideDistance, originalX);
            case 5:
                return createTranslationXAnimator(view, originalX, slideDistance + originalX, originalX);
            case 48:
                return createTranslationYAnimator(view, originalY, slideDistance + originalY, originalY);
            case 80:
                return createTranslationYAnimator(view, originalY, originalY - slideDistance, originalY);
            case GravityCompat.START /* 8388611 */:
                return createTranslationXAnimator(view, originalX, isRtl(sceneRoot) ? originalX - slideDistance : slideDistance + originalX, originalX);
            case GravityCompat.END /* 8388613 */:
                return createTranslationXAnimator(view, originalX, isRtl(sceneRoot) ? slideDistance + originalX : originalX - slideDistance, originalX);
            default:
                throw new IllegalArgumentException("Invalid slide direction: " + slideEdge);
        }
    }

    private static Animator createTranslationXAnimator(final View view, float startTranslation, float endTranslation, final float originalTranslation) {
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(view, PropertyValuesHolder.ofFloat(View.TRANSLATION_X, startTranslation, endTranslation));
        animator.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.transition.platform.SlideDistanceProvider.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                view.setTranslationX(originalTranslation);
            }
        });
        return animator;
    }

    private static Animator createTranslationYAnimator(final View view, float startTranslation, float endTranslation, final float originalTranslation) {
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(view, PropertyValuesHolder.ofFloat(View.TRANSLATION_Y, startTranslation, endTranslation));
        animator.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.transition.platform.SlideDistanceProvider.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                view.setTranslationY(originalTranslation);
            }
        });
        return animator;
    }

    private static boolean isRtl(View view) {
        return ViewCompat.getLayoutDirection(view) == 1;
    }
}
