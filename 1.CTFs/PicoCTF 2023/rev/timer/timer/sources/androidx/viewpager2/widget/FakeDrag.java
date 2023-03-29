package androidx.viewpager2.widget;

import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;
import androidx.recyclerview.widget.RecyclerView;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class FakeDrag {
    private int mActualDraggedDistance;
    private long mFakeDragBeginTime;
    private int mMaximumVelocity;
    private final RecyclerView mRecyclerView;
    private float mRequestedDragDistance;
    private final ScrollEventAdapter mScrollEventAdapter;
    private VelocityTracker mVelocityTracker;
    private final ViewPager2 mViewPager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FakeDrag(ViewPager2 viewPager, ScrollEventAdapter scrollEventAdapter, RecyclerView recyclerView) {
        this.mViewPager = viewPager;
        this.mScrollEventAdapter = scrollEventAdapter;
        this.mRecyclerView = recyclerView;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isFakeDragging() {
        return this.mScrollEventAdapter.isFakeDragging();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean beginFakeDrag() {
        if (this.mScrollEventAdapter.isDragging()) {
            return false;
        }
        this.mActualDraggedDistance = 0;
        this.mRequestedDragDistance = 0;
        this.mFakeDragBeginTime = SystemClock.uptimeMillis();
        beginFakeVelocityTracker();
        this.mScrollEventAdapter.notifyBeginFakeDrag();
        if (!this.mScrollEventAdapter.isIdle()) {
            this.mRecyclerView.stopScroll();
        }
        addFakeMotionEvent(this.mFakeDragBeginTime, 0, 0.0f, 0.0f);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean fakeDragBy(float offsetPxFloat) {
        if (this.mScrollEventAdapter.isFakeDragging()) {
            float f = this.mRequestedDragDistance - offsetPxFloat;
            this.mRequestedDragDistance = f;
            int offsetPx = Math.round(f - this.mActualDraggedDistance);
            this.mActualDraggedDistance += offsetPx;
            long time = SystemClock.uptimeMillis();
            boolean isHorizontal = this.mViewPager.getOrientation() == 0;
            int offsetX = isHorizontal ? offsetPx : 0;
            int offsetY = isHorizontal ? 0 : offsetPx;
            float x = isHorizontal ? this.mRequestedDragDistance : 0.0f;
            float y = isHorizontal ? 0.0f : this.mRequestedDragDistance;
            this.mRecyclerView.scrollBy(offsetX, offsetY);
            addFakeMotionEvent(time, 2, x, y);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean endFakeDrag() {
        if (!this.mScrollEventAdapter.isFakeDragging()) {
            return false;
        }
        this.mScrollEventAdapter.notifyEndFakeDrag();
        VelocityTracker velocityTracker = this.mVelocityTracker;
        velocityTracker.computeCurrentVelocity(1000, this.mMaximumVelocity);
        int xVelocity = (int) velocityTracker.getXVelocity();
        int yVelocity = (int) velocityTracker.getYVelocity();
        if (!this.mRecyclerView.fling(xVelocity, yVelocity)) {
            this.mViewPager.snapToPage();
            return true;
        }
        return true;
    }

    private void beginFakeVelocityTracker() {
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
            ViewConfiguration configuration = ViewConfiguration.get(this.mViewPager.getContext());
            this.mMaximumVelocity = configuration.getScaledMaximumFlingVelocity();
            return;
        }
        velocityTracker.clear();
    }

    private void addFakeMotionEvent(long time, int action, float x, float y) {
        MotionEvent ev = MotionEvent.obtain(this.mFakeDragBeginTime, time, action, x, y, 0);
        this.mVelocityTracker.addMovement(ev);
        ev.recycle();
    }
}
