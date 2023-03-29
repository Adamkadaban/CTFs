package com.google.android.material.tabs;

import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.google.android.material.animation.AnimationUtils;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FadeTabIndicatorInterpolator extends TabIndicatorInterpolator {
    private static final float FADE_THRESHOLD = 0.5f;

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.tabs.TabIndicatorInterpolator
    public void updateIndicatorForOffset(TabLayout tabLayout, View startTitle, View endTitle, float offset, Drawable indicator) {
        float alpha;
        View tab = offset < 0.5f ? startTitle : endTitle;
        RectF bounds = calculateIndicatorWidthForTab(tabLayout, tab);
        if (offset < 0.5f) {
            alpha = AnimationUtils.lerp(1.0f, 0.0f, 0.0f, 0.5f, offset);
        } else {
            alpha = AnimationUtils.lerp(0.0f, 1.0f, 0.5f, 1.0f, offset);
        }
        indicator.setBounds((int) bounds.left, indicator.getBounds().top, (int) bounds.right, indicator.getBounds().bottom);
        indicator.setAlpha((int) (255.0f * alpha));
    }
}
