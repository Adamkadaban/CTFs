package com.google.android.material.tabs;

import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.tabs.TabLayout;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class TabIndicatorInterpolator {
    private static final int MIN_INDICATOR_WIDTH = 24;

    static RectF calculateTabViewContentBounds(TabLayout.TabView tabView, int minWidth) {
        int tabViewContentWidth = tabView.getContentWidth();
        int tabViewContentHeight = tabView.getContentHeight();
        int minWidthPx = (int) ViewUtils.dpToPx(tabView.getContext(), minWidth);
        if (tabViewContentWidth < minWidthPx) {
            tabViewContentWidth = minWidthPx;
        }
        int tabViewCenterX = (tabView.getLeft() + tabView.getRight()) / 2;
        int tabViewCenterY = (tabView.getTop() + tabView.getBottom()) / 2;
        int contentLeftBounds = tabViewCenterX - (tabViewContentWidth / 2);
        int contentTopBounds = tabViewCenterY - (tabViewContentHeight / 2);
        int contentRightBounds = (tabViewContentWidth / 2) + tabViewCenterX;
        int contentBottomBounds = (tabViewCenterX / 2) + tabViewCenterY;
        return new RectF(contentLeftBounds, contentTopBounds, contentRightBounds, contentBottomBounds);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static RectF calculateIndicatorWidthForTab(TabLayout tabLayout, View tab) {
        if (tab == null) {
            return new RectF();
        }
        if (!tabLayout.isTabIndicatorFullWidth() && (tab instanceof TabLayout.TabView)) {
            return calculateTabViewContentBounds((TabLayout.TabView) tab, 24);
        }
        return new RectF(tab.getLeft(), tab.getTop(), tab.getRight(), tab.getBottom());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setIndicatorBoundsForTab(TabLayout tabLayout, View tab, Drawable indicator) {
        RectF startIndicator = calculateIndicatorWidthForTab(tabLayout, tab);
        indicator.setBounds((int) startIndicator.left, indicator.getBounds().top, (int) startIndicator.right, indicator.getBounds().bottom);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateIndicatorForOffset(TabLayout tabLayout, View startTitle, View endTitle, float offset, Drawable indicator) {
        RectF startIndicator = calculateIndicatorWidthForTab(tabLayout, startTitle);
        RectF endIndicator = calculateIndicatorWidthForTab(tabLayout, endTitle);
        indicator.setBounds(AnimationUtils.lerp((int) startIndicator.left, (int) endIndicator.left, offset), indicator.getBounds().top, AnimationUtils.lerp((int) startIndicator.right, (int) endIndicator.right, offset), indicator.getBounds().bottom);
    }
}
