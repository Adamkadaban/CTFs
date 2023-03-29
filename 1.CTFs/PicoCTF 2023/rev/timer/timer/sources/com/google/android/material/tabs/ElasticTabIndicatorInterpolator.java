package com.google.android.material.tabs;

import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.google.android.material.animation.AnimationUtils;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class ElasticTabIndicatorInterpolator extends TabIndicatorInterpolator {
    private static float decInterp(float fraction) {
        return (float) Math.sin((fraction * 3.141592653589793d) / 2.0d);
    }

    private static float accInterp(float fraction) {
        return (float) (1.0d - Math.cos((fraction * 3.141592653589793d) / 2.0d));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.tabs.TabIndicatorInterpolator
    public void updateIndicatorForOffset(TabLayout tabLayout, View startTitle, View endTitle, float offset, Drawable indicator) {
        float leftFraction;
        float rightFraction;
        RectF startIndicator = calculateIndicatorWidthForTab(tabLayout, startTitle);
        RectF endIndicator = calculateIndicatorWidthForTab(tabLayout, endTitle);
        boolean isMovingRight = startIndicator.left < endIndicator.left;
        if (isMovingRight) {
            leftFraction = accInterp(offset);
            rightFraction = decInterp(offset);
        } else {
            leftFraction = decInterp(offset);
            rightFraction = accInterp(offset);
        }
        indicator.setBounds(AnimationUtils.lerp((int) startIndicator.left, (int) endIndicator.left, leftFraction), indicator.getBounds().top, AnimationUtils.lerp((int) startIndicator.right, (int) endIndicator.right, rightFraction), indicator.getBounds().bottom);
    }
}
