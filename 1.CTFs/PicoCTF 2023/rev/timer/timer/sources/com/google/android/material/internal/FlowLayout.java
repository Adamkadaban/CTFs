package com.google.android.material.internal;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
/* loaded from: classes.dex */
public class FlowLayout extends ViewGroup {
    private int itemSpacing;
    private int lineSpacing;
    private int rowCount;
    private boolean singleLine;

    public FlowLayout(Context context) {
        this(context, null);
    }

    public FlowLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public FlowLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.singleLine = false;
        loadFromAttributes(context, attrs);
    }

    public FlowLayout(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        this.singleLine = false;
        loadFromAttributes(context, attrs);
    }

    private void loadFromAttributes(Context context, AttributeSet attrs) {
        TypedArray array = context.getTheme().obtainStyledAttributes(attrs, R.styleable.FlowLayout, 0, 0);
        this.lineSpacing = array.getDimensionPixelSize(R.styleable.FlowLayout_lineSpacing, 0);
        this.itemSpacing = array.getDimensionPixelSize(R.styleable.FlowLayout_itemSpacing, 0);
        array.recycle();
    }

    protected int getLineSpacing() {
        return this.lineSpacing;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setLineSpacing(int lineSpacing) {
        this.lineSpacing = lineSpacing;
    }

    protected int getItemSpacing() {
        return this.itemSpacing;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setItemSpacing(int itemSpacing) {
        this.itemSpacing = itemSpacing;
    }

    public boolean isSingleLine() {
        return this.singleLine;
    }

    public void setSingleLine(boolean singleLine) {
        this.singleLine = singleLine;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int maxWidth;
        int maxWidth2;
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int height = View.MeasureSpec.getSize(heightMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        if (widthMode == Integer.MIN_VALUE || widthMode == 1073741824) {
            maxWidth = width;
        } else {
            maxWidth = Integer.MAX_VALUE;
        }
        int childLeft = getPaddingLeft();
        int childTop = getPaddingTop();
        int childBottom = childTop;
        int maxChildRight = 0;
        int maxRight = maxWidth - getPaddingRight();
        int i = 0;
        while (i < getChildCount()) {
            View child = getChildAt(i);
            if (child.getVisibility() == 8) {
                maxWidth2 = maxWidth;
            } else {
                measureChild(child, widthMeasureSpec, heightMeasureSpec);
                maxWidth2 = maxWidth;
                ViewGroup.LayoutParams lp = child.getLayoutParams();
                int leftMargin = 0;
                int rightMargin = 0;
                int childTop2 = childTop;
                if (lp instanceof ViewGroup.MarginLayoutParams) {
                    ViewGroup.MarginLayoutParams marginLp = (ViewGroup.MarginLayoutParams) lp;
                    leftMargin = 0 + marginLp.leftMargin;
                    rightMargin = 0 + marginLp.rightMargin;
                }
                if (childLeft + leftMargin + child.getMeasuredWidth() > maxRight && !isSingleLine()) {
                    childLeft = getPaddingLeft();
                    childTop = this.lineSpacing + childBottom;
                } else {
                    childTop = childTop2;
                }
                int childRight = childLeft + leftMargin + child.getMeasuredWidth();
                int childBottom2 = child.getMeasuredHeight() + childTop;
                if (childRight > maxChildRight) {
                    maxChildRight = childRight;
                }
                int childBottom3 = this.itemSpacing;
                childLeft += leftMargin + rightMargin + child.getMeasuredWidth() + childBottom3;
                if (i != getChildCount() - 1) {
                    childBottom = childBottom2;
                } else {
                    maxChildRight += rightMargin;
                    childBottom = childBottom2;
                }
            }
            i++;
            maxWidth = maxWidth2;
        }
        int maxWidth3 = getPaddingRight();
        int childBottom4 = childBottom + getPaddingBottom();
        int finalWidth = getMeasuredDimension(width, widthMode, maxChildRight + maxWidth3);
        int finalHeight = getMeasuredDimension(height, heightMode, childBottom4);
        setMeasuredDimension(finalWidth, finalHeight);
    }

    private static int getMeasuredDimension(int size, int mode, int childrenEdge) {
        switch (mode) {
            case Integer.MIN_VALUE:
                return Math.min(childrenEdge, size);
            case BasicMeasure.EXACTLY /* 1073741824 */:
                return size;
            default:
                return childrenEdge;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean sizeChanged, int left, int top, int right, int bottom) {
        int paddingStart;
        if (getChildCount() != 0) {
            this.rowCount = 1;
            boolean isRtl = ViewCompat.getLayoutDirection(this) == 1;
            int paddingStart2 = isRtl ? getPaddingRight() : getPaddingLeft();
            int paddingEnd = isRtl ? getPaddingLeft() : getPaddingRight();
            int childStart = paddingStart2;
            int childTop = getPaddingTop();
            int childBottom = childTop;
            int maxChildEnd = (right - left) - paddingEnd;
            int i = 0;
            while (i < getChildCount()) {
                View child = getChildAt(i);
                if (child.getVisibility() == 8) {
                    child.setTag(R.id.row_index_key, -1);
                    paddingStart = paddingStart2;
                } else {
                    ViewGroup.LayoutParams lp = child.getLayoutParams();
                    int startMargin = 0;
                    int endMargin = 0;
                    if (lp instanceof ViewGroup.MarginLayoutParams) {
                        ViewGroup.MarginLayoutParams marginLp = (ViewGroup.MarginLayoutParams) lp;
                        startMargin = MarginLayoutParamsCompat.getMarginStart(marginLp);
                        endMargin = MarginLayoutParamsCompat.getMarginEnd(marginLp);
                    }
                    int childEnd = childStart + startMargin + child.getMeasuredWidth();
                    if (!this.singleLine && childEnd > maxChildEnd) {
                        childStart = paddingStart2;
                        childTop = childBottom + this.lineSpacing;
                        this.rowCount++;
                    }
                    paddingStart = paddingStart2;
                    child.setTag(R.id.row_index_key, Integer.valueOf(this.rowCount - 1));
                    int childEnd2 = childStart + startMargin + child.getMeasuredWidth();
                    int childEnd3 = child.getMeasuredHeight();
                    int childBottom2 = childEnd3 + childTop;
                    if (isRtl) {
                        child.layout(maxChildEnd - childEnd2, childTop, (maxChildEnd - childStart) - startMargin, childBottom2);
                    } else {
                        child.layout(childStart + startMargin, childTop, childEnd2, childBottom2);
                    }
                    childStart += startMargin + endMargin + child.getMeasuredWidth() + this.itemSpacing;
                    childBottom = childBottom2;
                }
                i++;
                paddingStart2 = paddingStart;
            }
            return;
        }
        this.rowCount = 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getRowCount() {
        return this.rowCount;
    }

    public int getRowIndex(View child) {
        Object index = child.getTag(R.id.row_index_key);
        if (!(index instanceof Integer)) {
            return -1;
        }
        return ((Integer) index).intValue();
    }
}
