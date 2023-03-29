package com.google.android.material.navigationrail;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.material.navigation.NavigationBarItemView;
import com.google.android.material.navigation.NavigationBarMenuView;
/* loaded from: classes.dex */
public class NavigationRailMenuView extends NavigationBarMenuView {
    private int itemMinimumHeight;
    private final FrameLayout.LayoutParams layoutParams;

    public NavigationRailMenuView(Context context) {
        super(context);
        this.itemMinimumHeight = -1;
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -2);
        this.layoutParams = layoutParams;
        layoutParams.gravity = 49;
        setLayoutParams(layoutParams);
        setItemActiveIndicatorResizeable(true);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int measuredHeight;
        int maxHeight = View.MeasureSpec.getSize(heightMeasureSpec);
        int visibleCount = getMenu().getVisibleItems().size();
        if (visibleCount > 1 && isShifting(getLabelVisibilityMode(), visibleCount)) {
            measuredHeight = measureShiftingChildHeights(widthMeasureSpec, maxHeight, visibleCount);
        } else {
            measuredHeight = measureSharedChildHeights(widthMeasureSpec, maxHeight, visibleCount, null);
        }
        int parentWidth = View.MeasureSpec.getSize(widthMeasureSpec);
        setMeasuredDimension(View.resolveSizeAndState(parentWidth, widthMeasureSpec, 0), View.resolveSizeAndState(measuredHeight, heightMeasureSpec, 0));
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int count = getChildCount();
        int width = right - left;
        int used = 0;
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                int childHeight = child.getMeasuredHeight();
                child.layout(0, used, width, childHeight + used);
                used += childHeight;
            }
        }
    }

    @Override // com.google.android.material.navigation.NavigationBarMenuView
    protected NavigationBarItemView createNavigationBarItemView(Context context) {
        return new NavigationRailItemView(context);
    }

    private int makeSharedHeightSpec(int parentWidthSpec, int maxHeight, int shareCount) {
        int maxAvailable = maxHeight / Math.max(1, shareCount);
        int minHeight = this.itemMinimumHeight;
        if (minHeight == -1) {
            minHeight = View.MeasureSpec.getSize(parentWidthSpec);
        }
        return View.MeasureSpec.makeMeasureSpec(Math.min(minHeight, maxAvailable), 0);
    }

    private int measureShiftingChildHeights(int widthMeasureSpec, int maxHeight, int shareCount) {
        int selectedViewHeight = 0;
        View selectedView = getChildAt(getSelectedItemPosition());
        if (selectedView != null) {
            int childHeightSpec = makeSharedHeightSpec(widthMeasureSpec, maxHeight, shareCount);
            selectedViewHeight = measureChildHeight(selectedView, widthMeasureSpec, childHeightSpec);
            maxHeight -= selectedViewHeight;
            shareCount--;
        }
        return measureSharedChildHeights(widthMeasureSpec, maxHeight, shareCount, selectedView) + selectedViewHeight;
    }

    private int measureSharedChildHeights(int widthMeasureSpec, int maxHeight, int shareCount, View selectedView) {
        int childHeightSpec;
        makeSharedHeightSpec(widthMeasureSpec, maxHeight, shareCount);
        if (selectedView == null) {
            childHeightSpec = makeSharedHeightSpec(widthMeasureSpec, maxHeight, shareCount);
        } else {
            childHeightSpec = View.MeasureSpec.makeMeasureSpec(selectedView.getMeasuredHeight(), 0);
        }
        int childCount = getChildCount();
        int totalHeight = 0;
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (child != selectedView) {
                totalHeight += measureChildHeight(child, widthMeasureSpec, childHeightSpec);
            }
        }
        return totalHeight;
    }

    private int measureChildHeight(View child, int widthMeasureSpec, int heightMeasureSpec) {
        if (child.getVisibility() != 8) {
            child.measure(widthMeasureSpec, heightMeasureSpec);
            return child.getMeasuredHeight();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setMenuGravity(int gravity) {
        if (this.layoutParams.gravity != gravity) {
            this.layoutParams.gravity = gravity;
            setLayoutParams(this.layoutParams);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getMenuGravity() {
        return this.layoutParams.gravity;
    }

    public void setItemMinimumHeight(int minHeight) {
        if (this.itemMinimumHeight != minHeight) {
            this.itemMinimumHeight = minHeight;
            requestLayout();
        }
    }

    public int getItemMinimumHeight() {
        return this.itemMinimumHeight;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isTopGravity() {
        return (this.layoutParams.gravity & 112) == 48;
    }
}
