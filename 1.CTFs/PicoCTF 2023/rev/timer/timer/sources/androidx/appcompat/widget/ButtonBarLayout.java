package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.LinearLayout;
import androidx.appcompat.R;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
/* loaded from: classes.dex */
public class ButtonBarLayout extends LinearLayout {
    private static final int PEEK_BUTTON_DP = 16;
    private boolean mAllowStacking;
    private int mLastWidthSize;
    private boolean mStacked;

    public ButtonBarLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mLastWidthSize = -1;
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.ButtonBarLayout);
        ViewCompat.saveAttributeDataForStyleable(this, context, R.styleable.ButtonBarLayout, attrs, ta, 0, 0);
        this.mAllowStacking = ta.getBoolean(R.styleable.ButtonBarLayout_allowStacking, true);
        ta.recycle();
        if (getOrientation() == 1) {
            setStacked(this.mAllowStacking);
        }
    }

    public void setAllowStacking(boolean allowStacking) {
        if (this.mAllowStacking != allowStacking) {
            this.mAllowStacking = allowStacking;
            if (!allowStacking && isStacked()) {
                setStacked(false);
            }
            requestLayout();
        }
    }

    @Override // android.widget.LinearLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int initialWidthMeasureSpec;
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        if (this.mAllowStacking) {
            if (widthSize > this.mLastWidthSize && isStacked()) {
                setStacked(false);
            }
            this.mLastWidthSize = widthSize;
        }
        boolean needsRemeasure = false;
        if (!isStacked() && View.MeasureSpec.getMode(widthMeasureSpec) == 1073741824) {
            initialWidthMeasureSpec = View.MeasureSpec.makeMeasureSpec(widthSize, Integer.MIN_VALUE);
            needsRemeasure = true;
        } else {
            initialWidthMeasureSpec = widthMeasureSpec;
        }
        super.onMeasure(initialWidthMeasureSpec, heightMeasureSpec);
        if (this.mAllowStacking && !isStacked()) {
            int measuredWidth = getMeasuredWidthAndState();
            int measuredWidthState = (-16777216) & measuredWidth;
            boolean stack = measuredWidthState == 16777216;
            if (stack) {
                setStacked(true);
                needsRemeasure = true;
            }
        }
        if (needsRemeasure) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }
        int minHeight = 0;
        int firstVisible = getNextVisibleChildIndex(0);
        if (firstVisible >= 0) {
            View firstButton = getChildAt(firstVisible);
            LinearLayout.LayoutParams firstParams = (LinearLayout.LayoutParams) firstButton.getLayoutParams();
            minHeight = 0 + getPaddingTop() + firstButton.getMeasuredHeight() + firstParams.topMargin + firstParams.bottomMargin;
            if (isStacked()) {
                int secondVisible = getNextVisibleChildIndex(firstVisible + 1);
                if (secondVisible >= 0) {
                    minHeight += getChildAt(secondVisible).getPaddingTop() + ((int) (getResources().getDisplayMetrics().density * 16.0f));
                }
            } else {
                minHeight += getPaddingBottom();
            }
        }
        if (ViewCompat.getMinimumHeight(this) != minHeight) {
            setMinimumHeight(minHeight);
            if (heightMeasureSpec == 0) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            }
        }
    }

    private int getNextVisibleChildIndex(int index) {
        int count = getChildCount();
        for (int i = index; i < count; i++) {
            if (getChildAt(i).getVisibility() == 0) {
                return i;
            }
        }
        return -1;
    }

    private void setStacked(boolean stacked) {
        if (this.mStacked != stacked) {
            if (!stacked || this.mAllowStacking) {
                this.mStacked = stacked;
                setOrientation(stacked ? 1 : 0);
                setGravity(stacked ? GravityCompat.END : 80);
                View spacer = findViewById(R.id.spacer);
                if (spacer != null) {
                    spacer.setVisibility(stacked ? 8 : 4);
                }
                int childCount = getChildCount();
                for (int i = childCount - 2; i >= 0; i--) {
                    bringChildToFront(getChildAt(i));
                }
            }
        }
    }

    private boolean isStacked() {
        return this.mStacked;
    }
}
