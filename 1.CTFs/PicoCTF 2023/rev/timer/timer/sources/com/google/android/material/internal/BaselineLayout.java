package com.google.android.material.internal;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
/* loaded from: classes.dex */
public class BaselineLayout extends ViewGroup {
    private int baseline;

    public BaselineLayout(Context context) {
        super(context, null, 0);
        this.baseline = -1;
    }

    public BaselineLayout(Context context, AttributeSet attrs) {
        super(context, attrs, 0);
        this.baseline = -1;
    }

    public BaselineLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.baseline = -1;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int count = getChildCount();
        int maxWidth = 0;
        int maxHeight = 0;
        int maxChildBaseline = -1;
        int maxChildDescent = -1;
        int childState = 0;
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                measureChild(child, widthMeasureSpec, heightMeasureSpec);
                int baseline = child.getBaseline();
                if (baseline != -1) {
                    maxChildBaseline = Math.max(maxChildBaseline, baseline);
                    maxChildDescent = Math.max(maxChildDescent, child.getMeasuredHeight() - baseline);
                }
                maxWidth = Math.max(maxWidth, child.getMeasuredWidth());
                maxHeight = Math.max(maxHeight, child.getMeasuredHeight());
                childState = View.combineMeasuredStates(childState, child.getMeasuredState());
            }
        }
        if (maxChildBaseline != -1) {
            maxHeight = Math.max(maxHeight, maxChildBaseline + Math.max(maxChildDescent, getPaddingBottom()));
            this.baseline = maxChildBaseline;
        }
        setMeasuredDimension(View.resolveSizeAndState(Math.max(maxWidth, getSuggestedMinimumWidth()), widthMeasureSpec, childState), View.resolveSizeAndState(Math.max(maxHeight, getSuggestedMinimumHeight()), heightMeasureSpec, childState << 16));
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int childTop;
        int count = getChildCount();
        int parentLeft = getPaddingLeft();
        int parentRight = (right - left) - getPaddingRight();
        int parentContentWidth = parentRight - parentLeft;
        int parentTop = getPaddingTop();
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                int width = child.getMeasuredWidth();
                int height = child.getMeasuredHeight();
                int childLeft = ((parentContentWidth - width) / 2) + parentLeft;
                if (this.baseline != -1 && child.getBaseline() != -1) {
                    childTop = (this.baseline + parentTop) - child.getBaseline();
                } else {
                    childTop = parentTop;
                }
                child.layout(childLeft, childTop, childLeft + width, childTop + height);
            }
        }
    }

    @Override // android.view.View
    public int getBaseline() {
        return this.baseline;
    }
}
