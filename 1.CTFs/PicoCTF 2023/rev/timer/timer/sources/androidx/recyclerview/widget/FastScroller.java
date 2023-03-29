package androidx.recyclerview.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.StateListDrawable;
import android.view.MotionEvent;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FastScroller extends RecyclerView.ItemDecoration implements RecyclerView.OnItemTouchListener {
    private static final int ANIMATION_STATE_FADING_IN = 1;
    private static final int ANIMATION_STATE_FADING_OUT = 3;
    private static final int ANIMATION_STATE_IN = 2;
    private static final int ANIMATION_STATE_OUT = 0;
    private static final int DRAG_NONE = 0;
    private static final int DRAG_X = 1;
    private static final int DRAG_Y = 2;
    private static final int HIDE_DELAY_AFTER_DRAGGING_MS = 1200;
    private static final int HIDE_DELAY_AFTER_VISIBLE_MS = 1500;
    private static final int HIDE_DURATION_MS = 500;
    private static final int SCROLLBAR_FULL_OPAQUE = 255;
    private static final int SHOW_DURATION_MS = 500;
    private static final int STATE_DRAGGING = 2;
    private static final int STATE_HIDDEN = 0;
    private static final int STATE_VISIBLE = 1;
    int mAnimationState;
    private final Runnable mHideRunnable;
    float mHorizontalDragX;
    int mHorizontalThumbCenterX;
    private final StateListDrawable mHorizontalThumbDrawable;
    private final int mHorizontalThumbHeight;
    int mHorizontalThumbWidth;
    private final Drawable mHorizontalTrackDrawable;
    private final int mHorizontalTrackHeight;
    private final int mMargin;
    private final RecyclerView.OnScrollListener mOnScrollListener;
    private RecyclerView mRecyclerView;
    private final int mScrollbarMinimumRange;
    final ValueAnimator mShowHideAnimator;
    float mVerticalDragY;
    int mVerticalThumbCenterY;
    final StateListDrawable mVerticalThumbDrawable;
    int mVerticalThumbHeight;
    private final int mVerticalThumbWidth;
    final Drawable mVerticalTrackDrawable;
    private final int mVerticalTrackWidth;
    private static final int[] PRESSED_STATE_SET = {16842919};
    private static final int[] EMPTY_STATE_SET = new int[0];
    private int mRecyclerViewWidth = 0;
    private int mRecyclerViewHeight = 0;
    private boolean mNeedVerticalScrollbar = false;
    private boolean mNeedHorizontalScrollbar = false;
    private int mState = 0;
    private int mDragState = 0;
    private final int[] mVerticalRange = new int[2];
    private final int[] mHorizontalRange = new int[2];

    /* JADX INFO: Access modifiers changed from: package-private */
    public FastScroller(RecyclerView recyclerView, StateListDrawable verticalThumbDrawable, Drawable verticalTrackDrawable, StateListDrawable horizontalThumbDrawable, Drawable horizontalTrackDrawable, int defaultWidth, int scrollbarMinimumRange, int margin) {
        ValueAnimator ofFloat = ValueAnimator.ofFloat(0.0f, 1.0f);
        this.mShowHideAnimator = ofFloat;
        this.mAnimationState = 0;
        this.mHideRunnable = new Runnable() { // from class: androidx.recyclerview.widget.FastScroller.1
            @Override // java.lang.Runnable
            public void run() {
                FastScroller.this.hide(500);
            }
        };
        this.mOnScrollListener = new RecyclerView.OnScrollListener() { // from class: androidx.recyclerview.widget.FastScroller.2
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView2, int dx, int dy) {
                FastScroller.this.updateScrollPosition(recyclerView2.computeHorizontalScrollOffset(), recyclerView2.computeVerticalScrollOffset());
            }
        };
        this.mVerticalThumbDrawable = verticalThumbDrawable;
        this.mVerticalTrackDrawable = verticalTrackDrawable;
        this.mHorizontalThumbDrawable = horizontalThumbDrawable;
        this.mHorizontalTrackDrawable = horizontalTrackDrawable;
        this.mVerticalThumbWidth = Math.max(defaultWidth, verticalThumbDrawable.getIntrinsicWidth());
        this.mVerticalTrackWidth = Math.max(defaultWidth, verticalTrackDrawable.getIntrinsicWidth());
        this.mHorizontalThumbHeight = Math.max(defaultWidth, horizontalThumbDrawable.getIntrinsicWidth());
        this.mHorizontalTrackHeight = Math.max(defaultWidth, horizontalTrackDrawable.getIntrinsicWidth());
        this.mScrollbarMinimumRange = scrollbarMinimumRange;
        this.mMargin = margin;
        verticalThumbDrawable.setAlpha(255);
        verticalTrackDrawable.setAlpha(255);
        ofFloat.addListener(new AnimatorListener());
        ofFloat.addUpdateListener(new AnimatorUpdater());
        attachToRecyclerView(recyclerView);
    }

    public void attachToRecyclerView(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.mRecyclerView;
        if (recyclerView2 == recyclerView) {
            return;
        }
        if (recyclerView2 != null) {
            destroyCallbacks();
        }
        this.mRecyclerView = recyclerView;
        if (recyclerView != null) {
            setupCallbacks();
        }
    }

    private void setupCallbacks() {
        this.mRecyclerView.addItemDecoration(this);
        this.mRecyclerView.addOnItemTouchListener(this);
        this.mRecyclerView.addOnScrollListener(this.mOnScrollListener);
    }

    private void destroyCallbacks() {
        this.mRecyclerView.removeItemDecoration(this);
        this.mRecyclerView.removeOnItemTouchListener(this);
        this.mRecyclerView.removeOnScrollListener(this.mOnScrollListener);
        cancelHide();
    }

    void requestRedraw() {
        this.mRecyclerView.invalidate();
    }

    void setState(int state) {
        if (state == 2 && this.mState != 2) {
            this.mVerticalThumbDrawable.setState(PRESSED_STATE_SET);
            cancelHide();
        }
        if (state == 0) {
            requestRedraw();
        } else {
            show();
        }
        if (this.mState == 2 && state != 2) {
            this.mVerticalThumbDrawable.setState(EMPTY_STATE_SET);
            resetHideDelay(HIDE_DELAY_AFTER_DRAGGING_MS);
        } else if (state == 1) {
            resetHideDelay(HIDE_DELAY_AFTER_VISIBLE_MS);
        }
        this.mState = state;
    }

    private boolean isLayoutRTL() {
        return ViewCompat.getLayoutDirection(this.mRecyclerView) == 1;
    }

    public boolean isDragging() {
        return this.mState == 2;
    }

    boolean isVisible() {
        return this.mState == 1;
    }

    public void show() {
        switch (this.mAnimationState) {
            case 0:
                break;
            default:
                return;
            case 3:
                this.mShowHideAnimator.cancel();
                break;
        }
        this.mAnimationState = 1;
        ValueAnimator valueAnimator = this.mShowHideAnimator;
        valueAnimator.setFloatValues(((Float) valueAnimator.getAnimatedValue()).floatValue(), 1.0f);
        this.mShowHideAnimator.setDuration(500L);
        this.mShowHideAnimator.setStartDelay(0L);
        this.mShowHideAnimator.start();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    void hide(int duration) {
        switch (this.mAnimationState) {
            case 1:
                this.mShowHideAnimator.cancel();
                break;
            case 2:
                break;
            default:
                return;
        }
        this.mAnimationState = 3;
        ValueAnimator valueAnimator = this.mShowHideAnimator;
        valueAnimator.setFloatValues(((Float) valueAnimator.getAnimatedValue()).floatValue(), 0.0f);
        this.mShowHideAnimator.setDuration(duration);
        this.mShowHideAnimator.start();
    }

    private void cancelHide() {
        this.mRecyclerView.removeCallbacks(this.mHideRunnable);
    }

    private void resetHideDelay(int delay) {
        cancelHide();
        this.mRecyclerView.postDelayed(this.mHideRunnable, delay);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDrawOver(Canvas canvas, RecyclerView parent, RecyclerView.State state) {
        if (this.mRecyclerViewWidth != this.mRecyclerView.getWidth() || this.mRecyclerViewHeight != this.mRecyclerView.getHeight()) {
            this.mRecyclerViewWidth = this.mRecyclerView.getWidth();
            this.mRecyclerViewHeight = this.mRecyclerView.getHeight();
            setState(0);
        } else if (this.mAnimationState != 0) {
            if (this.mNeedVerticalScrollbar) {
                drawVerticalScrollbar(canvas);
            }
            if (this.mNeedHorizontalScrollbar) {
                drawHorizontalScrollbar(canvas);
            }
        }
    }

    private void drawVerticalScrollbar(Canvas canvas) {
        int viewWidth = this.mRecyclerViewWidth;
        int i = this.mVerticalThumbWidth;
        int left = viewWidth - i;
        int i2 = this.mVerticalThumbCenterY;
        int i3 = this.mVerticalThumbHeight;
        int top = i2 - (i3 / 2);
        this.mVerticalThumbDrawable.setBounds(0, 0, i, i3);
        this.mVerticalTrackDrawable.setBounds(0, 0, this.mVerticalTrackWidth, this.mRecyclerViewHeight);
        if (isLayoutRTL()) {
            this.mVerticalTrackDrawable.draw(canvas);
            canvas.translate(this.mVerticalThumbWidth, top);
            canvas.scale(-1.0f, 1.0f);
            this.mVerticalThumbDrawable.draw(canvas);
            canvas.scale(1.0f, 1.0f);
            canvas.translate(-this.mVerticalThumbWidth, -top);
            return;
        }
        canvas.translate(left, 0.0f);
        this.mVerticalTrackDrawable.draw(canvas);
        canvas.translate(0.0f, top);
        this.mVerticalThumbDrawable.draw(canvas);
        canvas.translate(-left, -top);
    }

    private void drawHorizontalScrollbar(Canvas canvas) {
        int viewHeight = this.mRecyclerViewHeight;
        int i = this.mHorizontalThumbHeight;
        int top = viewHeight - i;
        int i2 = this.mHorizontalThumbCenterX;
        int i3 = this.mHorizontalThumbWidth;
        int left = i2 - (i3 / 2);
        this.mHorizontalThumbDrawable.setBounds(0, 0, i3, i);
        this.mHorizontalTrackDrawable.setBounds(0, 0, this.mRecyclerViewWidth, this.mHorizontalTrackHeight);
        canvas.translate(0.0f, top);
        this.mHorizontalTrackDrawable.draw(canvas);
        canvas.translate(left, 0.0f);
        this.mHorizontalThumbDrawable.draw(canvas);
        canvas.translate(-left, -top);
    }

    void updateScrollPosition(int offsetX, int offsetY) {
        int verticalContentLength = this.mRecyclerView.computeVerticalScrollRange();
        int verticalVisibleLength = this.mRecyclerViewHeight;
        this.mNeedVerticalScrollbar = verticalContentLength - verticalVisibleLength > 0 && this.mRecyclerViewHeight >= this.mScrollbarMinimumRange;
        int horizontalContentLength = this.mRecyclerView.computeHorizontalScrollRange();
        int horizontalVisibleLength = this.mRecyclerViewWidth;
        boolean z = horizontalContentLength - horizontalVisibleLength > 0 && this.mRecyclerViewWidth >= this.mScrollbarMinimumRange;
        this.mNeedHorizontalScrollbar = z;
        boolean z2 = this.mNeedVerticalScrollbar;
        if (!z2 && !z) {
            if (this.mState != 0) {
                setState(0);
                return;
            }
            return;
        }
        if (z2) {
            float middleScreenPos = offsetY + (verticalVisibleLength / 2.0f);
            this.mVerticalThumbCenterY = (int) ((verticalVisibleLength * middleScreenPos) / verticalContentLength);
            this.mVerticalThumbHeight = Math.min(verticalVisibleLength, (verticalVisibleLength * verticalVisibleLength) / verticalContentLength);
        }
        if (this.mNeedHorizontalScrollbar) {
            float middleScreenPos2 = offsetX + (horizontalVisibleLength / 2.0f);
            this.mHorizontalThumbCenterX = (int) ((horizontalVisibleLength * middleScreenPos2) / horizontalContentLength);
            this.mHorizontalThumbWidth = Math.min(horizontalVisibleLength, (horizontalVisibleLength * horizontalVisibleLength) / horizontalContentLength);
        }
        int i = this.mState;
        if (i == 0 || i == 1) {
            setState(1);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public boolean onInterceptTouchEvent(RecyclerView recyclerView, MotionEvent ev) {
        int i = this.mState;
        if (i != 1) {
            if (i == 2) {
                return true;
            }
            return false;
        }
        boolean insideVerticalThumb = isPointInsideVerticalThumb(ev.getX(), ev.getY());
        boolean insideHorizontalThumb = isPointInsideHorizontalThumb(ev.getX(), ev.getY());
        if (ev.getAction() == 0 && (insideVerticalThumb || insideHorizontalThumb)) {
            if (insideHorizontalThumb) {
                this.mDragState = 1;
                this.mHorizontalDragX = (int) ev.getX();
            } else if (insideVerticalThumb) {
                this.mDragState = 2;
                this.mVerticalDragY = (int) ev.getY();
            }
            setState(2);
            return true;
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public void onTouchEvent(RecyclerView recyclerView, MotionEvent me) {
        if (this.mState == 0) {
            return;
        }
        if (me.getAction() == 0) {
            boolean insideVerticalThumb = isPointInsideVerticalThumb(me.getX(), me.getY());
            boolean insideHorizontalThumb = isPointInsideHorizontalThumb(me.getX(), me.getY());
            if (insideVerticalThumb || insideHorizontalThumb) {
                if (insideHorizontalThumb) {
                    this.mDragState = 1;
                    this.mHorizontalDragX = (int) me.getX();
                } else if (insideVerticalThumb) {
                    this.mDragState = 2;
                    this.mVerticalDragY = (int) me.getY();
                }
                setState(2);
            }
        } else if (me.getAction() == 1 && this.mState == 2) {
            this.mVerticalDragY = 0.0f;
            this.mHorizontalDragX = 0.0f;
            setState(1);
            this.mDragState = 0;
        } else if (me.getAction() == 2 && this.mState == 2) {
            show();
            if (this.mDragState == 1) {
                horizontalScrollTo(me.getX());
            }
            if (this.mDragState == 2) {
                verticalScrollTo(me.getY());
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.OnItemTouchListener
    public void onRequestDisallowInterceptTouchEvent(boolean disallowIntercept) {
    }

    private void verticalScrollTo(float y) {
        int[] scrollbarRange = getVerticalRange();
        float y2 = Math.max(scrollbarRange[0], Math.min(scrollbarRange[1], y));
        if (Math.abs(this.mVerticalThumbCenterY - y2) < 2.0f) {
            return;
        }
        int scrollingBy = scrollTo(this.mVerticalDragY, y2, scrollbarRange, this.mRecyclerView.computeVerticalScrollRange(), this.mRecyclerView.computeVerticalScrollOffset(), this.mRecyclerViewHeight);
        if (scrollingBy != 0) {
            this.mRecyclerView.scrollBy(0, scrollingBy);
        }
        this.mVerticalDragY = y2;
    }

    private void horizontalScrollTo(float x) {
        int[] scrollbarRange = getHorizontalRange();
        float x2 = Math.max(scrollbarRange[0], Math.min(scrollbarRange[1], x));
        if (Math.abs(this.mHorizontalThumbCenterX - x2) < 2.0f) {
            return;
        }
        int scrollingBy = scrollTo(this.mHorizontalDragX, x2, scrollbarRange, this.mRecyclerView.computeHorizontalScrollRange(), this.mRecyclerView.computeHorizontalScrollOffset(), this.mRecyclerViewWidth);
        if (scrollingBy != 0) {
            this.mRecyclerView.scrollBy(scrollingBy, 0);
        }
        this.mHorizontalDragX = x2;
    }

    private int scrollTo(float oldDragPos, float newDragPos, int[] scrollbarRange, int scrollRange, int scrollOffset, int viewLength) {
        int scrollbarLength = scrollbarRange[1] - scrollbarRange[0];
        if (scrollbarLength == 0) {
            return 0;
        }
        float percentage = (newDragPos - oldDragPos) / scrollbarLength;
        int totalPossibleOffset = scrollRange - viewLength;
        int scrollingBy = (int) (totalPossibleOffset * percentage);
        int absoluteOffset = scrollOffset + scrollingBy;
        if (absoluteOffset >= totalPossibleOffset || absoluteOffset < 0) {
            return 0;
        }
        return scrollingBy;
    }

    boolean isPointInsideVerticalThumb(float x, float y) {
        if (!isLayoutRTL() ? x >= this.mRecyclerViewWidth - this.mVerticalThumbWidth : x <= this.mVerticalThumbWidth / 2) {
            int i = this.mVerticalThumbCenterY;
            int i2 = this.mVerticalThumbHeight;
            if (y >= i - (i2 / 2) && y <= i + (i2 / 2)) {
                return true;
            }
        }
        return false;
    }

    boolean isPointInsideHorizontalThumb(float x, float y) {
        if (y >= this.mRecyclerViewHeight - this.mHorizontalThumbHeight) {
            int i = this.mHorizontalThumbCenterX;
            int i2 = this.mHorizontalThumbWidth;
            if (x >= i - (i2 / 2) && x <= i + (i2 / 2)) {
                return true;
            }
        }
        return false;
    }

    Drawable getHorizontalTrackDrawable() {
        return this.mHorizontalTrackDrawable;
    }

    Drawable getHorizontalThumbDrawable() {
        return this.mHorizontalThumbDrawable;
    }

    Drawable getVerticalTrackDrawable() {
        return this.mVerticalTrackDrawable;
    }

    Drawable getVerticalThumbDrawable() {
        return this.mVerticalThumbDrawable;
    }

    private int[] getVerticalRange() {
        int[] iArr = this.mVerticalRange;
        int i = this.mMargin;
        iArr[0] = i;
        iArr[1] = this.mRecyclerViewHeight - i;
        return iArr;
    }

    private int[] getHorizontalRange() {
        int[] iArr = this.mHorizontalRange;
        int i = this.mMargin;
        iArr[0] = i;
        iArr[1] = this.mRecyclerViewWidth - i;
        return iArr;
    }

    /* loaded from: classes.dex */
    private class AnimatorListener extends AnimatorListenerAdapter {
        private boolean mCanceled = false;

        AnimatorListener() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            if (this.mCanceled) {
                this.mCanceled = false;
            } else if (((Float) FastScroller.this.mShowHideAnimator.getAnimatedValue()).floatValue() == 0.0f) {
                FastScroller.this.mAnimationState = 0;
                FastScroller.this.setState(0);
            } else {
                FastScroller.this.mAnimationState = 2;
                FastScroller.this.requestRedraw();
            }
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            this.mCanceled = true;
        }
    }

    /* loaded from: classes.dex */
    private class AnimatorUpdater implements ValueAnimator.AnimatorUpdateListener {
        AnimatorUpdater() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            int alpha = (int) (((Float) valueAnimator.getAnimatedValue()).floatValue() * 255.0f);
            FastScroller.this.mVerticalThumbDrawable.setAlpha(alpha);
            FastScroller.this.mVerticalTrackDrawable.setAlpha(alpha);
            FastScroller.this.requestRedraw();
        }
    }
}
