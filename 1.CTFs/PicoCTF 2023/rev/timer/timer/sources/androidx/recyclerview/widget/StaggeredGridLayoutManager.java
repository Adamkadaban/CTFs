package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.PointF;
import android.graphics.Rect;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
/* loaded from: classes.dex */
public class StaggeredGridLayoutManager extends RecyclerView.LayoutManager implements RecyclerView.SmoothScroller.ScrollVectorProvider {
    static final boolean DEBUG = false;
    @Deprecated
    public static final int GAP_HANDLING_LAZY = 1;
    public static final int GAP_HANDLING_MOVE_ITEMS_BETWEEN_SPANS = 2;
    public static final int GAP_HANDLING_NONE = 0;
    public static final int HORIZONTAL = 0;
    static final int INVALID_OFFSET = Integer.MIN_VALUE;
    private static final float MAX_SCROLL_FACTOR = 0.33333334f;
    private static final String TAG = "StaggeredGridLManager";
    public static final int VERTICAL = 1;
    private int mFullSizeSpec;
    private boolean mLastLayoutFromEnd;
    private boolean mLastLayoutRTL;
    private final LayoutState mLayoutState;
    private int mOrientation;
    private SavedState mPendingSavedState;
    private int[] mPrefetchDistances;
    OrientationHelper mPrimaryOrientation;
    private BitSet mRemainingSpans;
    OrientationHelper mSecondaryOrientation;
    private int mSizePerSpan;
    Span[] mSpans;
    private int mSpanCount = -1;
    boolean mReverseLayout = false;
    boolean mShouldReverseLayout = false;
    int mPendingScrollPosition = -1;
    int mPendingScrollPositionOffset = Integer.MIN_VALUE;
    LazySpanLookup mLazySpanLookup = new LazySpanLookup();
    private int mGapStrategy = 2;
    private final Rect mTmpRect = new Rect();
    private final AnchorInfo mAnchorInfo = new AnchorInfo();
    private boolean mLaidOutInvalidFullSpan = false;
    private boolean mSmoothScrollbarEnabled = true;
    private final Runnable mCheckForGapsRunnable = new Runnable() { // from class: androidx.recyclerview.widget.StaggeredGridLayoutManager.1
        @Override // java.lang.Runnable
        public void run() {
            StaggeredGridLayoutManager.this.checkForGaps();
        }
    };

    public StaggeredGridLayoutManager(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        RecyclerView.LayoutManager.Properties properties = getProperties(context, attrs, defStyleAttr, defStyleRes);
        setOrientation(properties.orientation);
        setSpanCount(properties.spanCount);
        setReverseLayout(properties.reverseLayout);
        this.mLayoutState = new LayoutState();
        createOrientationHelpers();
    }

    public StaggeredGridLayoutManager(int spanCount, int orientation) {
        this.mOrientation = orientation;
        setSpanCount(spanCount);
        this.mLayoutState = new LayoutState();
        createOrientationHelpers();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean isAutoMeasureEnabled() {
        return this.mGapStrategy != 0;
    }

    private void createOrientationHelpers() {
        this.mPrimaryOrientation = OrientationHelper.createOrientationHelper(this, this.mOrientation);
        this.mSecondaryOrientation = OrientationHelper.createOrientationHelper(this, 1 - this.mOrientation);
    }

    boolean checkForGaps() {
        int minPos;
        int maxPos;
        if (getChildCount() == 0 || this.mGapStrategy == 0 || !isAttachedToWindow()) {
            return false;
        }
        if (this.mShouldReverseLayout) {
            minPos = getLastChildPosition();
            maxPos = getFirstChildPosition();
        } else {
            minPos = getFirstChildPosition();
            maxPos = getLastChildPosition();
        }
        if (minPos == 0) {
            View gapView = hasGapsToFix();
            if (gapView != null) {
                this.mLazySpanLookup.clear();
                requestSimpleAnimationsInNextLayout();
                requestLayout();
                return true;
            }
        }
        if (this.mLaidOutInvalidFullSpan) {
            int invalidGapDir = this.mShouldReverseLayout ? -1 : 1;
            LazySpanLookup.FullSpanItem invalidFsi = this.mLazySpanLookup.getFirstFullSpanItemInRange(minPos, maxPos + 1, invalidGapDir, true);
            if (invalidFsi == null) {
                this.mLaidOutInvalidFullSpan = false;
                this.mLazySpanLookup.forceInvalidateAfter(maxPos + 1);
                return false;
            }
            LazySpanLookup.FullSpanItem validFsi = this.mLazySpanLookup.getFirstFullSpanItemInRange(minPos, invalidFsi.mPosition, invalidGapDir * (-1), true);
            if (validFsi != null) {
                this.mLazySpanLookup.forceInvalidateAfter(validFsi.mPosition + 1);
            } else {
                this.mLazySpanLookup.forceInvalidateAfter(invalidFsi.mPosition);
            }
            requestSimpleAnimationsInNextLayout();
            requestLayout();
            return true;
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onScrollStateChanged(int state) {
        if (state == 0) {
            checkForGaps();
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onDetachedFromWindow(RecyclerView view, RecyclerView.Recycler recycler) {
        super.onDetachedFromWindow(view, recycler);
        removeCallbacks(this.mCheckForGapsRunnable);
        for (int i = 0; i < this.mSpanCount; i++) {
            this.mSpans[i].clear();
        }
        view.requestLayout();
    }

    View hasGapsToFix() {
        int firstChildIndex;
        int childLimit;
        int endChildIndex = getChildCount() - 1;
        BitSet mSpansToCheck = new BitSet(this.mSpanCount);
        mSpansToCheck.set(0, this.mSpanCount, true);
        int preferredSpanDir = (this.mOrientation == 1 && isLayoutRTL()) ? 1 : -1;
        if (this.mShouldReverseLayout) {
            firstChildIndex = endChildIndex;
            childLimit = 0 - 1;
        } else {
            firstChildIndex = 0;
            childLimit = endChildIndex + 1;
        }
        int nextChildDiff = firstChildIndex < childLimit ? 1 : -1;
        for (int i = firstChildIndex; i != childLimit; i += nextChildDiff) {
            View child = getChildAt(i);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            if (mSpansToCheck.get(lp.mSpan.mIndex)) {
                if (checkSpanForGap(lp.mSpan)) {
                    return child;
                }
                mSpansToCheck.clear(lp.mSpan.mIndex);
            }
            if (!lp.mFullSpan && i + nextChildDiff != childLimit) {
                View nextChild = getChildAt(i + nextChildDiff);
                boolean compareSpans = false;
                if (this.mShouldReverseLayout) {
                    int myEnd = this.mPrimaryOrientation.getDecoratedEnd(child);
                    int nextEnd = this.mPrimaryOrientation.getDecoratedEnd(nextChild);
                    if (myEnd < nextEnd) {
                        return child;
                    }
                    if (myEnd == nextEnd) {
                        compareSpans = true;
                    }
                } else {
                    int myStart = this.mPrimaryOrientation.getDecoratedStart(child);
                    int nextStart = this.mPrimaryOrientation.getDecoratedStart(nextChild);
                    if (myStart > nextStart) {
                        return child;
                    }
                    if (myStart == nextStart) {
                        compareSpans = true;
                    }
                }
                if (compareSpans) {
                    LayoutParams nextLp = (LayoutParams) nextChild.getLayoutParams();
                    if ((lp.mSpan.mIndex - nextLp.mSpan.mIndex < 0) != (preferredSpanDir < 0)) {
                        return child;
                    }
                } else {
                    continue;
                }
            }
        }
        return null;
    }

    private boolean checkSpanForGap(Span span) {
        if (this.mShouldReverseLayout) {
            if (span.getEndLine() < this.mPrimaryOrientation.getEndAfterPadding()) {
                View endView = span.mViews.get(span.mViews.size() - 1);
                LayoutParams lp = span.getLayoutParams(endView);
                return !lp.mFullSpan;
            }
        } else if (span.getStartLine() > this.mPrimaryOrientation.getStartAfterPadding()) {
            View startView = span.mViews.get(0);
            LayoutParams lp2 = span.getLayoutParams(startView);
            return !lp2.mFullSpan;
        }
        return false;
    }

    public void setSpanCount(int spanCount) {
        assertNotInLayoutOrScroll(null);
        if (spanCount != this.mSpanCount) {
            invalidateSpanAssignments();
            this.mSpanCount = spanCount;
            this.mRemainingSpans = new BitSet(this.mSpanCount);
            this.mSpans = new Span[this.mSpanCount];
            for (int i = 0; i < this.mSpanCount; i++) {
                this.mSpans[i] = new Span(i);
            }
            requestLayout();
        }
    }

    public void setOrientation(int orientation) {
        if (orientation != 0 && orientation != 1) {
            throw new IllegalArgumentException("invalid orientation.");
        }
        assertNotInLayoutOrScroll(null);
        if (orientation == this.mOrientation) {
            return;
        }
        this.mOrientation = orientation;
        OrientationHelper tmp = this.mPrimaryOrientation;
        this.mPrimaryOrientation = this.mSecondaryOrientation;
        this.mSecondaryOrientation = tmp;
        requestLayout();
    }

    public void setReverseLayout(boolean reverseLayout) {
        assertNotInLayoutOrScroll(null);
        SavedState savedState = this.mPendingSavedState;
        if (savedState != null && savedState.mReverseLayout != reverseLayout) {
            this.mPendingSavedState.mReverseLayout = reverseLayout;
        }
        this.mReverseLayout = reverseLayout;
        requestLayout();
    }

    public int getGapStrategy() {
        return this.mGapStrategy;
    }

    public void setGapStrategy(int gapStrategy) {
        assertNotInLayoutOrScroll(null);
        if (gapStrategy == this.mGapStrategy) {
            return;
        }
        if (gapStrategy != 0 && gapStrategy != 2) {
            throw new IllegalArgumentException("invalid gap strategy. Must be GAP_HANDLING_NONE or GAP_HANDLING_MOVE_ITEMS_BETWEEN_SPANS");
        }
        this.mGapStrategy = gapStrategy;
        requestLayout();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void assertNotInLayoutOrScroll(String message) {
        if (this.mPendingSavedState == null) {
            super.assertNotInLayoutOrScroll(message);
        }
    }

    public int getSpanCount() {
        return this.mSpanCount;
    }

    public void invalidateSpanAssignments() {
        this.mLazySpanLookup.clear();
        requestLayout();
    }

    private void resolveShouldLayoutReverse() {
        if (this.mOrientation == 1 || !isLayoutRTL()) {
            this.mShouldReverseLayout = this.mReverseLayout;
        } else {
            this.mShouldReverseLayout = !this.mReverseLayout;
        }
    }

    boolean isLayoutRTL() {
        return getLayoutDirection() == 1;
    }

    public boolean getReverseLayout() {
        return this.mReverseLayout;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void setMeasuredDimension(Rect childrenBounds, int wSpec, int hSpec) {
        int usedHeight;
        int width;
        int horizontalPadding = getPaddingLeft() + getPaddingRight();
        int verticalPadding = getPaddingTop() + getPaddingBottom();
        if (this.mOrientation == 1) {
            int usedHeight2 = childrenBounds.height() + verticalPadding;
            width = chooseSize(hSpec, usedHeight2, getMinimumHeight());
            usedHeight = chooseSize(wSpec, (this.mSizePerSpan * this.mSpanCount) + horizontalPadding, getMinimumWidth());
        } else {
            int width2 = childrenBounds.width();
            int usedWidth = width2 + horizontalPadding;
            int width3 = chooseSize(wSpec, usedWidth, getMinimumWidth());
            usedHeight = width3;
            width = chooseSize(hSpec, (this.mSizePerSpan * this.mSpanCount) + verticalPadding, getMinimumHeight());
        }
        setMeasuredDimension(usedHeight, width);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state) {
        onLayoutChildren(recycler, state, true);
    }

    private void onLayoutChildren(RecyclerView.Recycler recycler, RecyclerView.State state, boolean shouldCheckForGaps) {
        SavedState savedState;
        AnchorInfo anchorInfo = this.mAnchorInfo;
        if ((this.mPendingSavedState != null || this.mPendingScrollPosition != -1) && state.getItemCount() == 0) {
            removeAndRecycleAllViews(recycler);
            anchorInfo.reset();
            return;
        }
        boolean needToCheckForGaps = true;
        boolean recalculateAnchor = (anchorInfo.mValid && this.mPendingScrollPosition == -1 && this.mPendingSavedState == null) ? false : true;
        if (recalculateAnchor) {
            anchorInfo.reset();
            if (this.mPendingSavedState != null) {
                applyPendingSavedState(anchorInfo);
            } else {
                resolveShouldLayoutReverse();
                anchorInfo.mLayoutFromEnd = this.mShouldReverseLayout;
            }
            updateAnchorInfoForLayout(state, anchorInfo);
            anchorInfo.mValid = true;
        }
        if (this.mPendingSavedState == null && this.mPendingScrollPosition == -1 && (anchorInfo.mLayoutFromEnd != this.mLastLayoutFromEnd || isLayoutRTL() != this.mLastLayoutRTL)) {
            this.mLazySpanLookup.clear();
            anchorInfo.mInvalidateOffsets = true;
        }
        if (getChildCount() > 0 && ((savedState = this.mPendingSavedState) == null || savedState.mSpanOffsetsSize < 1)) {
            if (anchorInfo.mInvalidateOffsets) {
                for (int i = 0; i < this.mSpanCount; i++) {
                    this.mSpans[i].clear();
                    if (anchorInfo.mOffset != Integer.MIN_VALUE) {
                        this.mSpans[i].setLine(anchorInfo.mOffset);
                    }
                }
            } else if (recalculateAnchor || this.mAnchorInfo.mSpanReferenceLines == null) {
                for (int i2 = 0; i2 < this.mSpanCount; i2++) {
                    this.mSpans[i2].cacheReferenceLineAndClear(this.mShouldReverseLayout, anchorInfo.mOffset);
                }
                this.mAnchorInfo.saveSpanReferenceLines(this.mSpans);
            } else {
                for (int i3 = 0; i3 < this.mSpanCount; i3++) {
                    Span span = this.mSpans[i3];
                    span.clear();
                    span.setLine(this.mAnchorInfo.mSpanReferenceLines[i3]);
                }
            }
        }
        detachAndScrapAttachedViews(recycler);
        this.mLayoutState.mRecycle = false;
        this.mLaidOutInvalidFullSpan = false;
        updateMeasureSpecs(this.mSecondaryOrientation.getTotalSpace());
        updateLayoutState(anchorInfo.mPosition, state);
        if (anchorInfo.mLayoutFromEnd) {
            setLayoutStateDirection(-1);
            fill(recycler, this.mLayoutState, state);
            setLayoutStateDirection(1);
            this.mLayoutState.mCurrentPosition = anchorInfo.mPosition + this.mLayoutState.mItemDirection;
            fill(recycler, this.mLayoutState, state);
        } else {
            setLayoutStateDirection(1);
            fill(recycler, this.mLayoutState, state);
            setLayoutStateDirection(-1);
            this.mLayoutState.mCurrentPosition = anchorInfo.mPosition + this.mLayoutState.mItemDirection;
            fill(recycler, this.mLayoutState, state);
        }
        repositionToWrapContentIfNecessary();
        if (getChildCount() > 0) {
            if (this.mShouldReverseLayout) {
                fixEndGap(recycler, state, true);
                fixStartGap(recycler, state, false);
            } else {
                fixStartGap(recycler, state, true);
                fixEndGap(recycler, state, false);
            }
        }
        boolean hasGaps = false;
        if (shouldCheckForGaps && !state.isPreLayout()) {
            if (this.mGapStrategy == 0 || getChildCount() <= 0 || (!this.mLaidOutInvalidFullSpan && hasGapsToFix() == null)) {
                needToCheckForGaps = false;
            }
            if (needToCheckForGaps) {
                removeCallbacks(this.mCheckForGapsRunnable);
                if (checkForGaps()) {
                    hasGaps = true;
                }
            }
        }
        if (state.isPreLayout()) {
            this.mAnchorInfo.reset();
        }
        this.mLastLayoutFromEnd = anchorInfo.mLayoutFromEnd;
        this.mLastLayoutRTL = isLayoutRTL();
        if (hasGaps) {
            this.mAnchorInfo.reset();
            onLayoutChildren(recycler, state, false);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onLayoutCompleted(RecyclerView.State state) {
        super.onLayoutCompleted(state);
        this.mPendingScrollPosition = -1;
        this.mPendingScrollPositionOffset = Integer.MIN_VALUE;
        this.mPendingSavedState = null;
        this.mAnchorInfo.reset();
    }

    private void repositionToWrapContentIfNecessary() {
        if (this.mSecondaryOrientation.getMode() == 1073741824) {
            return;
        }
        float maxSize = 0.0f;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            float size = this.mSecondaryOrientation.getDecoratedMeasurement(child);
            if (size >= maxSize) {
                LayoutParams layoutParams = (LayoutParams) child.getLayoutParams();
                if (layoutParams.isFullSpan()) {
                    size = (1.0f * size) / this.mSpanCount;
                }
                maxSize = Math.max(maxSize, size);
            }
        }
        int i2 = this.mSizePerSpan;
        int desired = Math.round(this.mSpanCount * maxSize);
        if (this.mSecondaryOrientation.getMode() == Integer.MIN_VALUE) {
            desired = Math.min(desired, this.mSecondaryOrientation.getTotalSpace());
        }
        updateMeasureSpecs(desired);
        if (this.mSizePerSpan == i2) {
            return;
        }
        for (int i3 = 0; i3 < childCount; i3++) {
            View child2 = getChildAt(i3);
            LayoutParams lp = (LayoutParams) child2.getLayoutParams();
            if (!lp.mFullSpan) {
                if (isLayoutRTL() && this.mOrientation == 1) {
                    child2.offsetLeftAndRight(((-((this.mSpanCount - 1) - lp.mSpan.mIndex)) * this.mSizePerSpan) - ((-((this.mSpanCount - 1) - lp.mSpan.mIndex)) * i2));
                } else {
                    int newOffset = lp.mSpan.mIndex * this.mSizePerSpan;
                    int prevOffset = lp.mSpan.mIndex * i2;
                    if (this.mOrientation == 1) {
                        child2.offsetLeftAndRight(newOffset - prevOffset);
                    } else {
                        child2.offsetTopAndBottom(newOffset - prevOffset);
                    }
                }
            }
        }
    }

    private void applyPendingSavedState(AnchorInfo anchorInfo) {
        if (this.mPendingSavedState.mSpanOffsetsSize > 0) {
            if (this.mPendingSavedState.mSpanOffsetsSize == this.mSpanCount) {
                for (int i = 0; i < this.mSpanCount; i++) {
                    this.mSpans[i].clear();
                    int line = this.mPendingSavedState.mSpanOffsets[i];
                    if (line != Integer.MIN_VALUE) {
                        if (this.mPendingSavedState.mAnchorLayoutFromEnd) {
                            line += this.mPrimaryOrientation.getEndAfterPadding();
                        } else {
                            line += this.mPrimaryOrientation.getStartAfterPadding();
                        }
                    }
                    this.mSpans[i].setLine(line);
                }
            } else {
                this.mPendingSavedState.invalidateSpanInfo();
                SavedState savedState = this.mPendingSavedState;
                savedState.mAnchorPosition = savedState.mVisibleAnchorPosition;
            }
        }
        this.mLastLayoutRTL = this.mPendingSavedState.mLastLayoutRTL;
        setReverseLayout(this.mPendingSavedState.mReverseLayout);
        resolveShouldLayoutReverse();
        if (this.mPendingSavedState.mAnchorPosition != -1) {
            this.mPendingScrollPosition = this.mPendingSavedState.mAnchorPosition;
            anchorInfo.mLayoutFromEnd = this.mPendingSavedState.mAnchorLayoutFromEnd;
        } else {
            anchorInfo.mLayoutFromEnd = this.mShouldReverseLayout;
        }
        if (this.mPendingSavedState.mSpanLookupSize > 1) {
            this.mLazySpanLookup.mData = this.mPendingSavedState.mSpanLookup;
            this.mLazySpanLookup.mFullSpanItems = this.mPendingSavedState.mFullSpanItems;
        }
    }

    void updateAnchorInfoForLayout(RecyclerView.State state, AnchorInfo anchorInfo) {
        if (updateAnchorFromPendingData(state, anchorInfo) || updateAnchorFromChildren(state, anchorInfo)) {
            return;
        }
        anchorInfo.assignCoordinateFromPadding();
        anchorInfo.mPosition = 0;
    }

    private boolean updateAnchorFromChildren(RecyclerView.State state, AnchorInfo anchorInfo) {
        int findFirstReferenceChildPosition;
        if (this.mLastLayoutFromEnd) {
            findFirstReferenceChildPosition = findLastReferenceChildPosition(state.getItemCount());
        } else {
            findFirstReferenceChildPosition = findFirstReferenceChildPosition(state.getItemCount());
        }
        anchorInfo.mPosition = findFirstReferenceChildPosition;
        anchorInfo.mOffset = Integer.MIN_VALUE;
        return true;
    }

    boolean updateAnchorFromPendingData(RecyclerView.State state, AnchorInfo anchorInfo) {
        int i;
        int startAfterPadding;
        if (state.isPreLayout() || (i = this.mPendingScrollPosition) == -1) {
            return false;
        }
        if (i < 0 || i >= state.getItemCount()) {
            this.mPendingScrollPosition = -1;
            this.mPendingScrollPositionOffset = Integer.MIN_VALUE;
            return false;
        }
        SavedState savedState = this.mPendingSavedState;
        if (savedState == null || savedState.mAnchorPosition == -1 || this.mPendingSavedState.mSpanOffsetsSize < 1) {
            View child = findViewByPosition(this.mPendingScrollPosition);
            if (child != null) {
                anchorInfo.mPosition = this.mShouldReverseLayout ? getLastChildPosition() : getFirstChildPosition();
                if (this.mPendingScrollPositionOffset != Integer.MIN_VALUE) {
                    if (anchorInfo.mLayoutFromEnd) {
                        int target = this.mPrimaryOrientation.getEndAfterPadding() - this.mPendingScrollPositionOffset;
                        anchorInfo.mOffset = target - this.mPrimaryOrientation.getDecoratedEnd(child);
                    } else {
                        int target2 = this.mPrimaryOrientation.getStartAfterPadding() + this.mPendingScrollPositionOffset;
                        anchorInfo.mOffset = target2 - this.mPrimaryOrientation.getDecoratedStart(child);
                    }
                    return true;
                }
                int childSize = this.mPrimaryOrientation.getDecoratedMeasurement(child);
                if (childSize > this.mPrimaryOrientation.getTotalSpace()) {
                    if (anchorInfo.mLayoutFromEnd) {
                        startAfterPadding = this.mPrimaryOrientation.getEndAfterPadding();
                    } else {
                        startAfterPadding = this.mPrimaryOrientation.getStartAfterPadding();
                    }
                    anchorInfo.mOffset = startAfterPadding;
                    return true;
                }
                int startGap = this.mPrimaryOrientation.getDecoratedStart(child) - this.mPrimaryOrientation.getStartAfterPadding();
                if (startGap < 0) {
                    anchorInfo.mOffset = -startGap;
                    return true;
                }
                int endGap = this.mPrimaryOrientation.getEndAfterPadding() - this.mPrimaryOrientation.getDecoratedEnd(child);
                if (endGap < 0) {
                    anchorInfo.mOffset = endGap;
                    return true;
                }
                anchorInfo.mOffset = Integer.MIN_VALUE;
            } else {
                anchorInfo.mPosition = this.mPendingScrollPosition;
                int i2 = this.mPendingScrollPositionOffset;
                if (i2 == Integer.MIN_VALUE) {
                    int position = calculateScrollDirectionForPosition(anchorInfo.mPosition);
                    anchorInfo.mLayoutFromEnd = position == 1;
                    anchorInfo.assignCoordinateFromPadding();
                } else {
                    anchorInfo.assignCoordinateFromPadding(i2);
                }
                anchorInfo.mInvalidateOffsets = true;
            }
        } else {
            anchorInfo.mOffset = Integer.MIN_VALUE;
            anchorInfo.mPosition = this.mPendingScrollPosition;
        }
        return true;
    }

    void updateMeasureSpecs(int totalSpace) {
        this.mSizePerSpan = totalSpace / this.mSpanCount;
        this.mFullSizeSpec = View.MeasureSpec.makeMeasureSpec(totalSpace, this.mSecondaryOrientation.getMode());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean supportsPredictiveItemAnimations() {
        return this.mPendingSavedState == null;
    }

    public int[] findFirstVisibleItemPositions(int[] into) {
        if (into == null) {
            into = new int[this.mSpanCount];
        } else if (into.length < this.mSpanCount) {
            throw new IllegalArgumentException("Provided int[]'s size must be more than or equal to span count. Expected:" + this.mSpanCount + ", array size:" + into.length);
        }
        for (int i = 0; i < this.mSpanCount; i++) {
            into[i] = this.mSpans[i].findFirstVisibleItemPosition();
        }
        return into;
    }

    public int[] findFirstCompletelyVisibleItemPositions(int[] into) {
        if (into == null) {
            into = new int[this.mSpanCount];
        } else if (into.length < this.mSpanCount) {
            throw new IllegalArgumentException("Provided int[]'s size must be more than or equal to span count. Expected:" + this.mSpanCount + ", array size:" + into.length);
        }
        for (int i = 0; i < this.mSpanCount; i++) {
            into[i] = this.mSpans[i].findFirstCompletelyVisibleItemPosition();
        }
        return into;
    }

    public int[] findLastVisibleItemPositions(int[] into) {
        if (into == null) {
            into = new int[this.mSpanCount];
        } else if (into.length < this.mSpanCount) {
            throw new IllegalArgumentException("Provided int[]'s size must be more than or equal to span count. Expected:" + this.mSpanCount + ", array size:" + into.length);
        }
        for (int i = 0; i < this.mSpanCount; i++) {
            into[i] = this.mSpans[i].findLastVisibleItemPosition();
        }
        return into;
    }

    public int[] findLastCompletelyVisibleItemPositions(int[] into) {
        if (into == null) {
            into = new int[this.mSpanCount];
        } else if (into.length < this.mSpanCount) {
            throw new IllegalArgumentException("Provided int[]'s size must be more than or equal to span count. Expected:" + this.mSpanCount + ", array size:" + into.length);
        }
        for (int i = 0; i < this.mSpanCount; i++) {
            into[i] = this.mSpans[i].findLastCompletelyVisibleItemPosition();
        }
        return into;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    private int computeScrollOffset(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        return ScrollbarHelper.computeScrollOffset(state, this.mPrimaryOrientation, findFirstVisibleItemClosestToStart(!this.mSmoothScrollbarEnabled), findFirstVisibleItemClosestToEnd(!this.mSmoothScrollbarEnabled), this, this.mSmoothScrollbarEnabled, this.mShouldReverseLayout);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollOffset(RecyclerView.State state) {
        return computeScrollOffset(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollExtent(RecyclerView.State state) {
        return computeScrollExtent(state);
    }

    private int computeScrollExtent(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        return ScrollbarHelper.computeScrollExtent(state, this.mPrimaryOrientation, findFirstVisibleItemClosestToStart(!this.mSmoothScrollbarEnabled), findFirstVisibleItemClosestToEnd(!this.mSmoothScrollbarEnabled), this, this.mSmoothScrollbarEnabled);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollExtent(RecyclerView.State state) {
        return computeScrollExtent(state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeHorizontalScrollRange(RecyclerView.State state) {
        return computeScrollRange(state);
    }

    private int computeScrollRange(RecyclerView.State state) {
        if (getChildCount() == 0) {
            return 0;
        }
        return ScrollbarHelper.computeScrollRange(state, this.mPrimaryOrientation, findFirstVisibleItemClosestToStart(!this.mSmoothScrollbarEnabled), findFirstVisibleItemClosestToEnd(!this.mSmoothScrollbarEnabled), this, this.mSmoothScrollbarEnabled);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int computeVerticalScrollRange(RecyclerView.State state) {
        return computeScrollRange(state);
    }

    private void measureChildWithDecorationsAndMargin(View child, LayoutParams lp, boolean alreadyMeasured) {
        if (lp.mFullSpan) {
            if (this.mOrientation == 1) {
                measureChildWithDecorationsAndMargin(child, this.mFullSizeSpec, getChildMeasureSpec(getHeight(), getHeightMode(), getPaddingTop() + getPaddingBottom(), lp.height, true), alreadyMeasured);
            } else {
                measureChildWithDecorationsAndMargin(child, getChildMeasureSpec(getWidth(), getWidthMode(), getPaddingLeft() + getPaddingRight(), lp.width, true), this.mFullSizeSpec, alreadyMeasured);
            }
        } else if (this.mOrientation == 1) {
            measureChildWithDecorationsAndMargin(child, getChildMeasureSpec(this.mSizePerSpan, getWidthMode(), 0, lp.width, false), getChildMeasureSpec(getHeight(), getHeightMode(), getPaddingTop() + getPaddingBottom(), lp.height, true), alreadyMeasured);
        } else {
            measureChildWithDecorationsAndMargin(child, getChildMeasureSpec(getWidth(), getWidthMode(), getPaddingLeft() + getPaddingRight(), lp.width, true), getChildMeasureSpec(this.mSizePerSpan, getHeightMode(), 0, lp.height, false), alreadyMeasured);
        }
    }

    private void measureChildWithDecorationsAndMargin(View child, int widthSpec, int heightSpec, boolean alreadyMeasured) {
        boolean measure;
        calculateItemDecorationsForChild(child, this.mTmpRect);
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        int widthSpec2 = updateSpecWithExtra(widthSpec, lp.leftMargin + this.mTmpRect.left, lp.rightMargin + this.mTmpRect.right);
        int heightSpec2 = updateSpecWithExtra(heightSpec, lp.topMargin + this.mTmpRect.top, lp.bottomMargin + this.mTmpRect.bottom);
        if (alreadyMeasured) {
            measure = shouldReMeasureChild(child, widthSpec2, heightSpec2, lp);
        } else {
            measure = shouldMeasureChild(child, widthSpec2, heightSpec2, lp);
        }
        if (measure) {
            child.measure(widthSpec2, heightSpec2);
        }
    }

    private int updateSpecWithExtra(int spec, int startInset, int endInset) {
        if (startInset == 0 && endInset == 0) {
            return spec;
        }
        int mode = View.MeasureSpec.getMode(spec);
        if (mode == Integer.MIN_VALUE || mode == 1073741824) {
            return View.MeasureSpec.makeMeasureSpec(Math.max(0, (View.MeasureSpec.getSize(spec) - startInset) - endInset), mode);
        }
        return spec;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onRestoreInstanceState(Parcelable state) {
        if (state instanceof SavedState) {
            this.mPendingSavedState = (SavedState) state;
            requestLayout();
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public Parcelable onSaveInstanceState() {
        int line;
        if (this.mPendingSavedState != null) {
            return new SavedState(this.mPendingSavedState);
        }
        SavedState state = new SavedState();
        state.mReverseLayout = this.mReverseLayout;
        state.mAnchorLayoutFromEnd = this.mLastLayoutFromEnd;
        state.mLastLayoutRTL = this.mLastLayoutRTL;
        LazySpanLookup lazySpanLookup = this.mLazySpanLookup;
        if (lazySpanLookup != null && lazySpanLookup.mData != null) {
            state.mSpanLookup = this.mLazySpanLookup.mData;
            state.mSpanLookupSize = state.mSpanLookup.length;
            state.mFullSpanItems = this.mLazySpanLookup.mFullSpanItems;
        } else {
            state.mSpanLookupSize = 0;
        }
        if (getChildCount() > 0) {
            state.mAnchorPosition = this.mLastLayoutFromEnd ? getLastChildPosition() : getFirstChildPosition();
            state.mVisibleAnchorPosition = findFirstVisibleItemPositionInt();
            state.mSpanOffsetsSize = this.mSpanCount;
            state.mSpanOffsets = new int[this.mSpanCount];
            for (int i = 0; i < this.mSpanCount; i++) {
                if (this.mLastLayoutFromEnd) {
                    line = this.mSpans[i].getEndLine(Integer.MIN_VALUE);
                    if (line != Integer.MIN_VALUE) {
                        line -= this.mPrimaryOrientation.getEndAfterPadding();
                    }
                } else {
                    line = this.mSpans[i].getStartLine(Integer.MIN_VALUE);
                    if (line != Integer.MIN_VALUE) {
                        line -= this.mPrimaryOrientation.getStartAfterPadding();
                    }
                }
                state.mSpanOffsets[i] = line;
            }
        } else {
            state.mAnchorPosition = -1;
            state.mVisibleAnchorPosition = -1;
            state.mSpanOffsetsSize = 0;
        }
        return state;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onInitializeAccessibilityNodeInfoForItem(RecyclerView.Recycler recycler, RecyclerView.State state, View host, AccessibilityNodeInfoCompat info) {
        ViewGroup.LayoutParams lp = host.getLayoutParams();
        if (!(lp instanceof LayoutParams)) {
            super.onInitializeAccessibilityNodeInfoForItem(host, info);
            return;
        }
        LayoutParams sglp = (LayoutParams) lp;
        if (this.mOrientation == 0) {
            info.setCollectionItemInfo(AccessibilityNodeInfoCompat.CollectionItemInfoCompat.obtain(sglp.getSpanIndex(), sglp.mFullSpan ? this.mSpanCount : 1, -1, -1, false, false));
        } else {
            info.setCollectionItemInfo(AccessibilityNodeInfoCompat.CollectionItemInfoCompat.obtain(-1, -1, sglp.getSpanIndex(), sglp.mFullSpan ? this.mSpanCount : 1, false, false));
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onInitializeAccessibilityEvent(AccessibilityEvent event) {
        super.onInitializeAccessibilityEvent(event);
        if (getChildCount() > 0) {
            View start = findFirstVisibleItemClosestToStart(false);
            View end = findFirstVisibleItemClosestToEnd(false);
            if (start == null || end == null) {
                return;
            }
            int startPos = getPosition(start);
            int endPos = getPosition(end);
            if (startPos < endPos) {
                event.setFromIndex(startPos);
                event.setToIndex(endPos);
                return;
            }
            event.setFromIndex(endPos);
            event.setToIndex(startPos);
        }
    }

    int findFirstVisibleItemPositionInt() {
        View first = this.mShouldReverseLayout ? findFirstVisibleItemClosestToEnd(true) : findFirstVisibleItemClosestToStart(true);
        if (first == null) {
            return -1;
        }
        return getPosition(first);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int getRowCountForAccessibility(RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (this.mOrientation == 0) {
            return this.mSpanCount;
        }
        return super.getRowCountForAccessibility(recycler, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int getColumnCountForAccessibility(RecyclerView.Recycler recycler, RecyclerView.State state) {
        if (this.mOrientation == 1) {
            return this.mSpanCount;
        }
        return super.getColumnCountForAccessibility(recycler, state);
    }

    View findFirstVisibleItemClosestToStart(boolean fullyVisible) {
        int boundsStart = this.mPrimaryOrientation.getStartAfterPadding();
        int boundsEnd = this.mPrimaryOrientation.getEndAfterPadding();
        int limit = getChildCount();
        View partiallyVisible = null;
        for (int i = 0; i < limit; i++) {
            View child = getChildAt(i);
            int childStart = this.mPrimaryOrientation.getDecoratedStart(child);
            int childEnd = this.mPrimaryOrientation.getDecoratedEnd(child);
            if (childEnd > boundsStart && childStart < boundsEnd) {
                if (childStart >= boundsStart || !fullyVisible) {
                    return child;
                }
                if (partiallyVisible == null) {
                    partiallyVisible = child;
                }
            }
        }
        return partiallyVisible;
    }

    View findFirstVisibleItemClosestToEnd(boolean fullyVisible) {
        int boundsStart = this.mPrimaryOrientation.getStartAfterPadding();
        int boundsEnd = this.mPrimaryOrientation.getEndAfterPadding();
        View partiallyVisible = null;
        for (int i = getChildCount() - 1; i >= 0; i--) {
            View child = getChildAt(i);
            int childStart = this.mPrimaryOrientation.getDecoratedStart(child);
            int childEnd = this.mPrimaryOrientation.getDecoratedEnd(child);
            if (childEnd > boundsStart && childStart < boundsEnd) {
                if (childEnd <= boundsEnd || !fullyVisible) {
                    return child;
                }
                if (partiallyVisible == null) {
                    partiallyVisible = child;
                }
            }
        }
        return partiallyVisible;
    }

    private void fixEndGap(RecyclerView.Recycler recycler, RecyclerView.State state, boolean canOffsetChildren) {
        int gap;
        int maxEndLine = getMaxEnd(Integer.MIN_VALUE);
        if (maxEndLine != Integer.MIN_VALUE && (gap = this.mPrimaryOrientation.getEndAfterPadding() - maxEndLine) > 0) {
            int fixOffset = -scrollBy(-gap, recycler, state);
            int gap2 = gap - fixOffset;
            if (canOffsetChildren && gap2 > 0) {
                this.mPrimaryOrientation.offsetChildren(gap2);
            }
        }
    }

    private void fixStartGap(RecyclerView.Recycler recycler, RecyclerView.State state, boolean canOffsetChildren) {
        int gap;
        int minStartLine = getMinStart(Integer.MAX_VALUE);
        if (minStartLine != Integer.MAX_VALUE && (gap = minStartLine - this.mPrimaryOrientation.getStartAfterPadding()) > 0) {
            int fixOffset = scrollBy(gap, recycler, state);
            int gap2 = gap - fixOffset;
            if (canOffsetChildren && gap2 > 0) {
                this.mPrimaryOrientation.offsetChildren(-gap2);
            }
        }
    }

    private void updateLayoutState(int anchorPosition, RecyclerView.State state) {
        int targetPos;
        boolean z = false;
        this.mLayoutState.mAvailable = 0;
        this.mLayoutState.mCurrentPosition = anchorPosition;
        int startExtra = 0;
        int endExtra = 0;
        if (isSmoothScrolling() && (targetPos = state.getTargetScrollPosition()) != -1) {
            if (this.mShouldReverseLayout == (targetPos < anchorPosition)) {
                endExtra = this.mPrimaryOrientation.getTotalSpace();
            } else {
                startExtra = this.mPrimaryOrientation.getTotalSpace();
            }
        }
        boolean clipToPadding = getClipToPadding();
        if (clipToPadding) {
            this.mLayoutState.mStartLine = this.mPrimaryOrientation.getStartAfterPadding() - startExtra;
            this.mLayoutState.mEndLine = this.mPrimaryOrientation.getEndAfterPadding() + endExtra;
        } else {
            this.mLayoutState.mEndLine = this.mPrimaryOrientation.getEnd() + endExtra;
            this.mLayoutState.mStartLine = -startExtra;
        }
        this.mLayoutState.mStopInFocusable = false;
        this.mLayoutState.mRecycle = true;
        LayoutState layoutState = this.mLayoutState;
        if (this.mPrimaryOrientation.getMode() == 0 && this.mPrimaryOrientation.getEnd() == 0) {
            z = true;
        }
        layoutState.mInfinite = z;
    }

    private void setLayoutStateDirection(int direction) {
        this.mLayoutState.mLayoutDirection = direction;
        this.mLayoutState.mItemDirection = this.mShouldReverseLayout != (direction == -1) ? -1 : 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void offsetChildrenHorizontal(int dx) {
        super.offsetChildrenHorizontal(dx);
        for (int i = 0; i < this.mSpanCount; i++) {
            this.mSpans[i].onOffset(dx);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void offsetChildrenVertical(int dy) {
        super.offsetChildrenVertical(dy);
        for (int i = 0; i < this.mSpanCount; i++) {
            this.mSpans[i].onOffset(dy);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsRemoved(RecyclerView recyclerView, int positionStart, int itemCount) {
        handleUpdate(positionStart, itemCount, 2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsAdded(RecyclerView recyclerView, int positionStart, int itemCount) {
        handleUpdate(positionStart, itemCount, 1);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsChanged(RecyclerView recyclerView) {
        this.mLazySpanLookup.clear();
        requestLayout();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsMoved(RecyclerView recyclerView, int from, int to, int itemCount) {
        handleUpdate(from, to, 8);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void onItemsUpdated(RecyclerView recyclerView, int positionStart, int itemCount, Object payload) {
        handleUpdate(positionStart, itemCount, 4);
    }

    private void handleUpdate(int positionStart, int itemCountOrToPosition, int cmd) {
        int affectedRangeStart;
        int affectedRangeEnd;
        int minPosition = this.mShouldReverseLayout ? getLastChildPosition() : getFirstChildPosition();
        if (cmd == 8) {
            if (positionStart < itemCountOrToPosition) {
                affectedRangeEnd = itemCountOrToPosition + 1;
                affectedRangeStart = positionStart;
            } else {
                affectedRangeEnd = positionStart + 1;
                affectedRangeStart = itemCountOrToPosition;
            }
        } else {
            affectedRangeStart = positionStart;
            affectedRangeEnd = positionStart + itemCountOrToPosition;
        }
        this.mLazySpanLookup.invalidateAfter(affectedRangeStart);
        switch (cmd) {
            case 1:
                this.mLazySpanLookup.offsetForAddition(positionStart, itemCountOrToPosition);
                break;
            case 2:
                this.mLazySpanLookup.offsetForRemoval(positionStart, itemCountOrToPosition);
                break;
            case 8:
                this.mLazySpanLookup.offsetForRemoval(positionStart, 1);
                this.mLazySpanLookup.offsetForAddition(itemCountOrToPosition, 1);
                break;
        }
        if (affectedRangeEnd <= minPosition) {
            return;
        }
        int maxPosition = this.mShouldReverseLayout ? getFirstChildPosition() : getLastChildPosition();
        if (affectedRangeStart <= maxPosition) {
            requestLayout();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [int, boolean] */
    /* JADX WARN: Type inference failed for: r10v4 */
    /* JADX WARN: Type inference failed for: r9v0 */
    /* JADX WARN: Type inference failed for: r9v1, types: [int, boolean] */
    /* JADX WARN: Type inference failed for: r9v6 */
    private int fill(RecyclerView.Recycler recycler, LayoutState layoutState, RecyclerView.State state) {
        int targetLine;
        int startAfterPadding;
        int diff;
        Span currentSpan;
        int startLine;
        int end;
        int start;
        int startAfterPadding2;
        int otherEnd;
        int otherStart;
        Span currentSpan2;
        int i;
        ?? r9 = 0;
        ?? r10 = 1;
        this.mRemainingSpans.set(0, this.mSpanCount, true);
        if (this.mLayoutState.mInfinite) {
            if (layoutState.mLayoutDirection == 1) {
                targetLine = Integer.MAX_VALUE;
            } else {
                targetLine = Integer.MIN_VALUE;
            }
        } else {
            int targetLine2 = layoutState.mLayoutDirection;
            if (targetLine2 == 1) {
                targetLine = layoutState.mEndLine + layoutState.mAvailable;
            } else {
                int targetLine3 = layoutState.mStartLine;
                targetLine = targetLine3 - layoutState.mAvailable;
            }
        }
        updateAllRemainingSpans(layoutState.mLayoutDirection, targetLine);
        if (this.mShouldReverseLayout) {
            startAfterPadding = this.mPrimaryOrientation.getEndAfterPadding();
        } else {
            startAfterPadding = this.mPrimaryOrientation.getStartAfterPadding();
        }
        int defaultNewViewLine = startAfterPadding;
        boolean added = false;
        while (layoutState.hasMore(state) && (this.mLayoutState.mInfinite || !this.mRemainingSpans.isEmpty())) {
            View view = layoutState.next(recycler);
            LayoutParams lp = (LayoutParams) view.getLayoutParams();
            int position = lp.getViewLayoutPosition();
            int spanIndex = this.mLazySpanLookup.getSpan(position);
            boolean assignSpan = spanIndex == -1;
            if (assignSpan) {
                Span currentSpan3 = lp.mFullSpan ? this.mSpans[r9] : getNextSpan(layoutState);
                this.mLazySpanLookup.setSpan(position, currentSpan3);
                currentSpan = currentSpan3;
            } else {
                currentSpan = this.mSpans[spanIndex];
            }
            lp.mSpan = currentSpan;
            if (layoutState.mLayoutDirection == r10) {
                addView(view);
            } else {
                addView(view, r9);
            }
            measureChildWithDecorationsAndMargin(view, lp, r9);
            if (layoutState.mLayoutDirection == r10) {
                if (lp.mFullSpan) {
                    start = getMaxEnd(defaultNewViewLine);
                } else {
                    start = currentSpan.getEndLine(defaultNewViewLine);
                }
                end = this.mPrimaryOrientation.getDecoratedMeasurement(view) + start;
                if (assignSpan && lp.mFullSpan) {
                    LazySpanLookup.FullSpanItem fullSpanItem = createFullSpanItemFromEnd(start);
                    fullSpanItem.mGapDir = -1;
                    fullSpanItem.mPosition = position;
                    this.mLazySpanLookup.addFullSpanItem(fullSpanItem);
                }
            } else {
                if (lp.mFullSpan) {
                    startLine = getMinStart(defaultNewViewLine);
                } else {
                    startLine = currentSpan.getStartLine(defaultNewViewLine);
                }
                end = startLine;
                start = end - this.mPrimaryOrientation.getDecoratedMeasurement(view);
                if (assignSpan && lp.mFullSpan) {
                    LazySpanLookup.FullSpanItem fullSpanItem2 = createFullSpanItemFromStart(end);
                    fullSpanItem2.mGapDir = r10;
                    fullSpanItem2.mPosition = position;
                    this.mLazySpanLookup.addFullSpanItem(fullSpanItem2);
                }
            }
            int start2 = start;
            int end2 = end;
            if (lp.mFullSpan && layoutState.mItemDirection == -1) {
                if (assignSpan) {
                    this.mLaidOutInvalidFullSpan = r10;
                } else {
                    if (layoutState.mLayoutDirection == r10) {
                        i = (areAllEndsEqual() ? 1 : 0) ^ r10;
                    } else {
                        boolean hasInvalidGap = areAllStartsEqual();
                        i = (hasInvalidGap ? 1 : 0) ^ r10;
                    }
                    if (i != 0) {
                        LazySpanLookup.FullSpanItem fullSpanItem3 = this.mLazySpanLookup.getFullSpanItem(position);
                        if (fullSpanItem3 != null) {
                            fullSpanItem3.mHasUnwantedGapAfter = r10;
                        }
                        this.mLaidOutInvalidFullSpan = r10;
                    }
                }
            }
            attachViewToSpans(view, lp, layoutState);
            if (isLayoutRTL() && this.mOrientation == r10) {
                int otherEnd2 = lp.mFullSpan ? this.mSecondaryOrientation.getEndAfterPadding() : this.mSecondaryOrientation.getEndAfterPadding() - (((this.mSpanCount - r10) - currentSpan.mIndex) * this.mSizePerSpan);
                otherEnd = otherEnd2;
                otherStart = otherEnd2 - this.mSecondaryOrientation.getDecoratedMeasurement(view);
            } else {
                if (lp.mFullSpan) {
                    startAfterPadding2 = this.mSecondaryOrientation.getStartAfterPadding();
                } else {
                    startAfterPadding2 = (currentSpan.mIndex * this.mSizePerSpan) + this.mSecondaryOrientation.getStartAfterPadding();
                }
                int otherStart2 = startAfterPadding2;
                otherEnd = this.mSecondaryOrientation.getDecoratedMeasurement(view) + otherStart2;
                otherStart = otherStart2;
            }
            if (this.mOrientation == r10) {
                currentSpan2 = currentSpan;
                layoutDecoratedWithMargins(view, otherStart, start2, otherEnd, end2);
            } else {
                currentSpan2 = currentSpan;
                layoutDecoratedWithMargins(view, start2, otherStart, end2, otherEnd);
            }
            if (lp.mFullSpan) {
                updateAllRemainingSpans(this.mLayoutState.mLayoutDirection, targetLine);
            } else {
                updateRemainingSpans(currentSpan2, this.mLayoutState.mLayoutDirection, targetLine);
            }
            recycle(recycler, this.mLayoutState);
            if (this.mLayoutState.mStopInFocusable && view.hasFocusable()) {
                if (lp.mFullSpan) {
                    this.mRemainingSpans.clear();
                } else {
                    this.mRemainingSpans.set(currentSpan2.mIndex, false);
                }
            }
            added = true;
            r9 = 0;
            r10 = 1;
        }
        if (!added) {
            recycle(recycler, this.mLayoutState);
        }
        if (this.mLayoutState.mLayoutDirection == -1) {
            int minStart = getMinStart(this.mPrimaryOrientation.getStartAfterPadding());
            diff = this.mPrimaryOrientation.getStartAfterPadding() - minStart;
        } else {
            int maxEnd = getMaxEnd(this.mPrimaryOrientation.getEndAfterPadding());
            diff = maxEnd - this.mPrimaryOrientation.getEndAfterPadding();
        }
        if (diff > 0) {
            return Math.min(layoutState.mAvailable, diff);
        }
        return 0;
    }

    private LazySpanLookup.FullSpanItem createFullSpanItemFromEnd(int newItemTop) {
        LazySpanLookup.FullSpanItem fsi = new LazySpanLookup.FullSpanItem();
        fsi.mGapPerSpan = new int[this.mSpanCount];
        for (int i = 0; i < this.mSpanCount; i++) {
            fsi.mGapPerSpan[i] = newItemTop - this.mSpans[i].getEndLine(newItemTop);
        }
        return fsi;
    }

    private LazySpanLookup.FullSpanItem createFullSpanItemFromStart(int newItemBottom) {
        LazySpanLookup.FullSpanItem fsi = new LazySpanLookup.FullSpanItem();
        fsi.mGapPerSpan = new int[this.mSpanCount];
        for (int i = 0; i < this.mSpanCount; i++) {
            fsi.mGapPerSpan[i] = this.mSpans[i].getStartLine(newItemBottom) - newItemBottom;
        }
        return fsi;
    }

    private void attachViewToSpans(View view, LayoutParams lp, LayoutState layoutState) {
        if (layoutState.mLayoutDirection == 1) {
            if (lp.mFullSpan) {
                appendViewToAllSpans(view);
            } else {
                lp.mSpan.appendToSpan(view);
            }
        } else if (lp.mFullSpan) {
            prependViewToAllSpans(view);
        } else {
            lp.mSpan.prependToSpan(view);
        }
    }

    private void recycle(RecyclerView.Recycler recycler, LayoutState layoutState) {
        int line;
        int line2;
        if (!layoutState.mRecycle || layoutState.mInfinite) {
            return;
        }
        if (layoutState.mAvailable == 0) {
            if (layoutState.mLayoutDirection == -1) {
                recycleFromEnd(recycler, layoutState.mEndLine);
            } else {
                recycleFromStart(recycler, layoutState.mStartLine);
            }
        } else if (layoutState.mLayoutDirection == -1) {
            int scrolled = layoutState.mStartLine - getMaxStart(layoutState.mStartLine);
            if (scrolled < 0) {
                line2 = layoutState.mEndLine;
            } else {
                int line3 = layoutState.mEndLine;
                line2 = line3 - Math.min(scrolled, layoutState.mAvailable);
            }
            recycleFromEnd(recycler, line2);
        } else {
            int scrolled2 = getMinEnd(layoutState.mEndLine) - layoutState.mEndLine;
            if (scrolled2 < 0) {
                line = layoutState.mStartLine;
            } else {
                int line4 = layoutState.mStartLine;
                line = line4 + Math.min(scrolled2, layoutState.mAvailable);
            }
            recycleFromStart(recycler, line);
        }
    }

    private void appendViewToAllSpans(View view) {
        for (int i = this.mSpanCount - 1; i >= 0; i--) {
            this.mSpans[i].appendToSpan(view);
        }
    }

    private void prependViewToAllSpans(View view) {
        for (int i = this.mSpanCount - 1; i >= 0; i--) {
            this.mSpans[i].prependToSpan(view);
        }
    }

    private void updateAllRemainingSpans(int layoutDir, int targetLine) {
        for (int i = 0; i < this.mSpanCount; i++) {
            if (!this.mSpans[i].mViews.isEmpty()) {
                updateRemainingSpans(this.mSpans[i], layoutDir, targetLine);
            }
        }
    }

    private void updateRemainingSpans(Span span, int layoutDir, int targetLine) {
        int deletedSize = span.getDeletedSize();
        if (layoutDir == -1) {
            int line = span.getStartLine();
            if (line + deletedSize <= targetLine) {
                this.mRemainingSpans.set(span.mIndex, false);
                return;
            }
            return;
        }
        int line2 = span.getEndLine();
        if (line2 - deletedSize >= targetLine) {
            this.mRemainingSpans.set(span.mIndex, false);
        }
    }

    private int getMaxStart(int def) {
        int maxStart = this.mSpans[0].getStartLine(def);
        for (int i = 1; i < this.mSpanCount; i++) {
            int spanStart = this.mSpans[i].getStartLine(def);
            if (spanStart > maxStart) {
                maxStart = spanStart;
            }
        }
        return maxStart;
    }

    private int getMinStart(int def) {
        int minStart = this.mSpans[0].getStartLine(def);
        for (int i = 1; i < this.mSpanCount; i++) {
            int spanStart = this.mSpans[i].getStartLine(def);
            if (spanStart < minStart) {
                minStart = spanStart;
            }
        }
        return minStart;
    }

    boolean areAllEndsEqual() {
        int end = this.mSpans[0].getEndLine(Integer.MIN_VALUE);
        for (int i = 1; i < this.mSpanCount; i++) {
            if (this.mSpans[i].getEndLine(Integer.MIN_VALUE) != end) {
                return false;
            }
        }
        return true;
    }

    boolean areAllStartsEqual() {
        int start = this.mSpans[0].getStartLine(Integer.MIN_VALUE);
        for (int i = 1; i < this.mSpanCount; i++) {
            if (this.mSpans[i].getStartLine(Integer.MIN_VALUE) != start) {
                return false;
            }
        }
        return true;
    }

    private int getMaxEnd(int def) {
        int maxEnd = this.mSpans[0].getEndLine(def);
        for (int i = 1; i < this.mSpanCount; i++) {
            int spanEnd = this.mSpans[i].getEndLine(def);
            if (spanEnd > maxEnd) {
                maxEnd = spanEnd;
            }
        }
        return maxEnd;
    }

    private int getMinEnd(int def) {
        int minEnd = this.mSpans[0].getEndLine(def);
        for (int i = 1; i < this.mSpanCount; i++) {
            int spanEnd = this.mSpans[i].getEndLine(def);
            if (spanEnd < minEnd) {
                minEnd = spanEnd;
            }
        }
        return minEnd;
    }

    private void recycleFromStart(RecyclerView.Recycler recycler, int line) {
        while (getChildCount() > 0) {
            View child = getChildAt(0);
            if (this.mPrimaryOrientation.getDecoratedEnd(child) <= line && this.mPrimaryOrientation.getTransformedEndWithDecoration(child) <= line) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp.mFullSpan) {
                    for (int j = 0; j < this.mSpanCount; j++) {
                        if (this.mSpans[j].mViews.size() == 1) {
                            return;
                        }
                    }
                    for (int j2 = 0; j2 < this.mSpanCount; j2++) {
                        this.mSpans[j2].popStart();
                    }
                } else if (lp.mSpan.mViews.size() == 1) {
                    return;
                } else {
                    lp.mSpan.popStart();
                }
                removeAndRecycleView(child, recycler);
            } else {
                return;
            }
        }
    }

    private void recycleFromEnd(RecyclerView.Recycler recycler, int line) {
        int childCount = getChildCount();
        for (int i = childCount - 1; i >= 0; i--) {
            View child = getChildAt(i);
            if (this.mPrimaryOrientation.getDecoratedStart(child) >= line && this.mPrimaryOrientation.getTransformedStartWithDecoration(child) >= line) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp.mFullSpan) {
                    for (int j = 0; j < this.mSpanCount; j++) {
                        if (this.mSpans[j].mViews.size() == 1) {
                            return;
                        }
                    }
                    for (int j2 = 0; j2 < this.mSpanCount; j2++) {
                        this.mSpans[j2].popEnd();
                    }
                } else if (lp.mSpan.mViews.size() == 1) {
                    return;
                } else {
                    lp.mSpan.popEnd();
                }
                removeAndRecycleView(child, recycler);
            } else {
                return;
            }
        }
    }

    private boolean preferLastSpan(int layoutDir) {
        if (this.mOrientation == 0) {
            return (layoutDir == -1) != this.mShouldReverseLayout;
        }
        return ((layoutDir == -1) == this.mShouldReverseLayout) == isLayoutRTL();
    }

    private Span getNextSpan(LayoutState layoutState) {
        int startIndex;
        int endIndex;
        int diff;
        boolean preferLastSpan = preferLastSpan(layoutState.mLayoutDirection);
        if (preferLastSpan) {
            startIndex = this.mSpanCount - 1;
            endIndex = -1;
            diff = -1;
        } else {
            startIndex = 0;
            endIndex = this.mSpanCount;
            diff = 1;
        }
        if (layoutState.mLayoutDirection == 1) {
            Span min = null;
            int minLine = Integer.MAX_VALUE;
            int defaultLine = this.mPrimaryOrientation.getStartAfterPadding();
            for (int i = startIndex; i != endIndex; i += diff) {
                Span other = this.mSpans[i];
                int otherLine = other.getEndLine(defaultLine);
                if (otherLine < minLine) {
                    min = other;
                    minLine = otherLine;
                }
            }
            return min;
        }
        Span max = null;
        int maxLine = Integer.MIN_VALUE;
        int defaultLine2 = this.mPrimaryOrientation.getEndAfterPadding();
        for (int i2 = startIndex; i2 != endIndex; i2 += diff) {
            Span other2 = this.mSpans[i2];
            int otherLine2 = other2.getStartLine(defaultLine2);
            if (otherLine2 > maxLine) {
                max = other2;
                maxLine = otherLine2;
            }
        }
        return max;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollVertically() {
        return this.mOrientation == 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean canScrollHorizontally() {
        return this.mOrientation == 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollHorizontallyBy(int dx, RecyclerView.Recycler recycler, RecyclerView.State state) {
        return scrollBy(dx, recycler, state);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public int scrollVerticallyBy(int dy, RecyclerView.Recycler recycler, RecyclerView.State state) {
        return scrollBy(dy, recycler, state);
    }

    private int calculateScrollDirectionForPosition(int position) {
        if (getChildCount() == 0) {
            return this.mShouldReverseLayout ? 1 : -1;
        }
        int firstChildPos = getFirstChildPosition();
        return (position < firstChildPos) != this.mShouldReverseLayout ? -1 : 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.SmoothScroller.ScrollVectorProvider
    public PointF computeScrollVectorForPosition(int targetPosition) {
        int direction = calculateScrollDirectionForPosition(targetPosition);
        PointF outVector = new PointF();
        if (direction == 0) {
            return null;
        }
        if (this.mOrientation == 0) {
            outVector.x = direction;
            outVector.y = 0.0f;
        } else {
            outVector.x = 0.0f;
            outVector.y = direction;
        }
        return outVector;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int position) {
        LinearSmoothScroller scroller = new LinearSmoothScroller(recyclerView.getContext());
        scroller.setTargetPosition(position);
        startSmoothScroll(scroller);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void scrollToPosition(int position) {
        SavedState savedState = this.mPendingSavedState;
        if (savedState != null && savedState.mAnchorPosition != position) {
            this.mPendingSavedState.invalidateAnchorPositionInfo();
        }
        this.mPendingScrollPosition = position;
        this.mPendingScrollPositionOffset = Integer.MIN_VALUE;
        requestLayout();
    }

    public void scrollToPositionWithOffset(int position, int offset) {
        SavedState savedState = this.mPendingSavedState;
        if (savedState != null) {
            savedState.invalidateAnchorPositionInfo();
        }
        this.mPendingScrollPosition = position;
        this.mPendingScrollPositionOffset = offset;
        requestLayout();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public void collectAdjacentPrefetchPositions(int dx, int dy, RecyclerView.State state, RecyclerView.LayoutManager.LayoutPrefetchRegistry layoutPrefetchRegistry) {
        int distance;
        int delta = this.mOrientation == 0 ? dx : dy;
        if (getChildCount() == 0 || delta == 0) {
            return;
        }
        prepareLayoutStateForDelta(delta, state);
        int[] iArr = this.mPrefetchDistances;
        if (iArr == null || iArr.length < this.mSpanCount) {
            this.mPrefetchDistances = new int[this.mSpanCount];
        }
        int itemPrefetchCount = 0;
        for (int i = 0; i < this.mSpanCount; i++) {
            if (this.mLayoutState.mItemDirection == -1) {
                distance = this.mLayoutState.mStartLine - this.mSpans[i].getStartLine(this.mLayoutState.mStartLine);
            } else {
                distance = this.mSpans[i].getEndLine(this.mLayoutState.mEndLine) - this.mLayoutState.mEndLine;
            }
            if (distance >= 0) {
                this.mPrefetchDistances[itemPrefetchCount] = distance;
                itemPrefetchCount++;
            }
        }
        Arrays.sort(this.mPrefetchDistances, 0, itemPrefetchCount);
        for (int i2 = 0; i2 < itemPrefetchCount && this.mLayoutState.hasMore(state); i2++) {
            layoutPrefetchRegistry.addPosition(this.mLayoutState.mCurrentPosition, this.mPrefetchDistances[i2]);
            this.mLayoutState.mCurrentPosition += this.mLayoutState.mItemDirection;
        }
    }

    void prepareLayoutStateForDelta(int delta, RecyclerView.State state) {
        int layoutDir;
        int referenceChildPosition;
        if (delta > 0) {
            layoutDir = 1;
            referenceChildPosition = getLastChildPosition();
        } else {
            layoutDir = -1;
            referenceChildPosition = getFirstChildPosition();
        }
        this.mLayoutState.mRecycle = true;
        updateLayoutState(referenceChildPosition, state);
        setLayoutStateDirection(layoutDir);
        LayoutState layoutState = this.mLayoutState;
        layoutState.mCurrentPosition = layoutState.mItemDirection + referenceChildPosition;
        this.mLayoutState.mAvailable = Math.abs(delta);
    }

    int scrollBy(int dt, RecyclerView.Recycler recycler, RecyclerView.State state) {
        int totalScroll;
        if (getChildCount() == 0 || dt == 0) {
            return 0;
        }
        prepareLayoutStateForDelta(dt, state);
        int consumed = fill(recycler, this.mLayoutState, state);
        int available = this.mLayoutState.mAvailable;
        if (available < consumed) {
            totalScroll = dt;
        } else if (dt < 0) {
            totalScroll = -consumed;
        } else {
            totalScroll = consumed;
        }
        this.mPrimaryOrientation.offsetChildren(-totalScroll);
        this.mLastLayoutFromEnd = this.mShouldReverseLayout;
        this.mLayoutState.mAvailable = 0;
        recycle(recycler, this.mLayoutState);
        return totalScroll;
    }

    int getLastChildPosition() {
        int childCount = getChildCount();
        if (childCount == 0) {
            return 0;
        }
        return getPosition(getChildAt(childCount - 1));
    }

    int getFirstChildPosition() {
        int childCount = getChildCount();
        if (childCount == 0) {
            return 0;
        }
        return getPosition(getChildAt(0));
    }

    private int findFirstReferenceChildPosition(int itemCount) {
        int limit = getChildCount();
        for (int i = 0; i < limit; i++) {
            View view = getChildAt(i);
            int position = getPosition(view);
            if (position >= 0 && position < itemCount) {
                return position;
            }
        }
        return 0;
    }

    private int findLastReferenceChildPosition(int itemCount) {
        for (int i = getChildCount() - 1; i >= 0; i--) {
            View view = getChildAt(i);
            int position = getPosition(view);
            if (position >= 0 && position < itemCount) {
                return position;
            }
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateDefaultLayoutParams() {
        if (this.mOrientation == 0) {
            return new LayoutParams(-2, -1);
        }
        return new LayoutParams(-1, -2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateLayoutParams(Context c, AttributeSet attrs) {
        return new LayoutParams(c, attrs);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public RecyclerView.LayoutParams generateLayoutParams(ViewGroup.LayoutParams lp) {
        if (lp instanceof ViewGroup.MarginLayoutParams) {
            return new LayoutParams((ViewGroup.MarginLayoutParams) lp);
        }
        return new LayoutParams(lp);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public boolean checkLayoutParams(RecyclerView.LayoutParams lp) {
        return lp instanceof LayoutParams;
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
    public View onFocusSearchFailed(View focused, int direction, RecyclerView.Recycler recycler, RecyclerView.State state) {
        View directChild;
        int referenceChildPosition;
        int findLastPartiallyVisibleItemPosition;
        int findLastPartiallyVisibleItemPosition2;
        int findLastPartiallyVisibleItemPosition3;
        View view;
        if (getChildCount() == 0 || (directChild = findContainingItemView(focused)) == null) {
            return null;
        }
        resolveShouldLayoutReverse();
        int layoutDir = convertFocusDirectionToLayoutDirection(direction);
        if (layoutDir == Integer.MIN_VALUE) {
            return null;
        }
        LayoutParams prevFocusLayoutParams = (LayoutParams) directChild.getLayoutParams();
        boolean prevFocusFullSpan = prevFocusLayoutParams.mFullSpan;
        Span prevFocusSpan = prevFocusLayoutParams.mSpan;
        if (layoutDir == 1) {
            referenceChildPosition = getLastChildPosition();
        } else {
            referenceChildPosition = getFirstChildPosition();
        }
        updateLayoutState(referenceChildPosition, state);
        setLayoutStateDirection(layoutDir);
        LayoutState layoutState = this.mLayoutState;
        layoutState.mCurrentPosition = layoutState.mItemDirection + referenceChildPosition;
        this.mLayoutState.mAvailable = (int) (this.mPrimaryOrientation.getTotalSpace() * MAX_SCROLL_FACTOR);
        this.mLayoutState.mStopInFocusable = true;
        this.mLayoutState.mRecycle = false;
        fill(recycler, this.mLayoutState, state);
        this.mLastLayoutFromEnd = this.mShouldReverseLayout;
        if (!prevFocusFullSpan && (view = prevFocusSpan.getFocusableViewAfter(referenceChildPosition, layoutDir)) != null && view != directChild) {
            return view;
        }
        if (preferLastSpan(layoutDir)) {
            for (int i = this.mSpanCount - 1; i >= 0; i--) {
                View view2 = this.mSpans[i].getFocusableViewAfter(referenceChildPosition, layoutDir);
                if (view2 != null && view2 != directChild) {
                    return view2;
                }
            }
        } else {
            for (int i2 = 0; i2 < this.mSpanCount; i2++) {
                View view3 = this.mSpans[i2].getFocusableViewAfter(referenceChildPosition, layoutDir);
                if (view3 != null && view3 != directChild) {
                    return view3;
                }
            }
        }
        boolean shouldSearchFromStart = (this.mReverseLayout ^ true) == (layoutDir == -1);
        if (!prevFocusFullSpan) {
            if (shouldSearchFromStart) {
                findLastPartiallyVisibleItemPosition3 = prevFocusSpan.findFirstPartiallyVisibleItemPosition();
            } else {
                findLastPartiallyVisibleItemPosition3 = prevFocusSpan.findLastPartiallyVisibleItemPosition();
            }
            View unfocusableCandidate = findViewByPosition(findLastPartiallyVisibleItemPosition3);
            if (unfocusableCandidate != null && unfocusableCandidate != directChild) {
                return unfocusableCandidate;
            }
        }
        if (preferLastSpan(layoutDir)) {
            for (int i3 = this.mSpanCount - 1; i3 >= 0; i3--) {
                if (i3 != prevFocusSpan.mIndex) {
                    if (shouldSearchFromStart) {
                        findLastPartiallyVisibleItemPosition2 = this.mSpans[i3].findFirstPartiallyVisibleItemPosition();
                    } else {
                        findLastPartiallyVisibleItemPosition2 = this.mSpans[i3].findLastPartiallyVisibleItemPosition();
                    }
                    View unfocusableCandidate2 = findViewByPosition(findLastPartiallyVisibleItemPosition2);
                    if (unfocusableCandidate2 != null && unfocusableCandidate2 != directChild) {
                        return unfocusableCandidate2;
                    }
                }
            }
        } else {
            for (int i4 = 0; i4 < this.mSpanCount; i4++) {
                if (shouldSearchFromStart) {
                    findLastPartiallyVisibleItemPosition = this.mSpans[i4].findFirstPartiallyVisibleItemPosition();
                } else {
                    findLastPartiallyVisibleItemPosition = this.mSpans[i4].findLastPartiallyVisibleItemPosition();
                }
                View unfocusableCandidate3 = findViewByPosition(findLastPartiallyVisibleItemPosition);
                if (unfocusableCandidate3 != null && unfocusableCandidate3 != directChild) {
                    return unfocusableCandidate3;
                }
            }
        }
        return null;
    }

    private int convertFocusDirectionToLayoutDirection(int focusDirection) {
        switch (focusDirection) {
            case 1:
                return (this.mOrientation != 1 && isLayoutRTL()) ? 1 : -1;
            case 2:
                return (this.mOrientation != 1 && isLayoutRTL()) ? -1 : 1;
            case 17:
                return this.mOrientation == 0 ? -1 : Integer.MIN_VALUE;
            case 33:
                return this.mOrientation == 1 ? -1 : Integer.MIN_VALUE;
            case 66:
                return this.mOrientation == 0 ? 1 : Integer.MIN_VALUE;
            case 130:
                return this.mOrientation == 1 ? 1 : Integer.MIN_VALUE;
            default:
                return Integer.MIN_VALUE;
        }
    }

    /* loaded from: classes.dex */
    public static class LayoutParams extends RecyclerView.LayoutParams {
        public static final int INVALID_SPAN_ID = -1;
        boolean mFullSpan;
        Span mSpan;

        public LayoutParams(Context c, AttributeSet attrs) {
            super(c, attrs);
        }

        public LayoutParams(int width, int height) {
            super(width, height);
        }

        public LayoutParams(ViewGroup.MarginLayoutParams source) {
            super(source);
        }

        public LayoutParams(ViewGroup.LayoutParams source) {
            super(source);
        }

        public LayoutParams(RecyclerView.LayoutParams source) {
            super(source);
        }

        public void setFullSpan(boolean fullSpan) {
            this.mFullSpan = fullSpan;
        }

        public boolean isFullSpan() {
            return this.mFullSpan;
        }

        public final int getSpanIndex() {
            Span span = this.mSpan;
            if (span == null) {
                return -1;
            }
            return span.mIndex;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class Span {
        static final int INVALID_LINE = Integer.MIN_VALUE;
        final int mIndex;
        ArrayList<View> mViews = new ArrayList<>();
        int mCachedStart = Integer.MIN_VALUE;
        int mCachedEnd = Integer.MIN_VALUE;
        int mDeletedSize = 0;

        Span(int index) {
            this.mIndex = index;
        }

        int getStartLine(int def) {
            int i = this.mCachedStart;
            if (i != Integer.MIN_VALUE) {
                return i;
            }
            if (this.mViews.size() == 0) {
                return def;
            }
            calculateCachedStart();
            return this.mCachedStart;
        }

        void calculateCachedStart() {
            LazySpanLookup.FullSpanItem fsi;
            View startView = this.mViews.get(0);
            LayoutParams lp = getLayoutParams(startView);
            this.mCachedStart = StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedStart(startView);
            if (lp.mFullSpan && (fsi = StaggeredGridLayoutManager.this.mLazySpanLookup.getFullSpanItem(lp.getViewLayoutPosition())) != null && fsi.mGapDir == -1) {
                this.mCachedStart -= fsi.getGapForSpan(this.mIndex);
            }
        }

        int getStartLine() {
            int i = this.mCachedStart;
            if (i != Integer.MIN_VALUE) {
                return i;
            }
            calculateCachedStart();
            return this.mCachedStart;
        }

        int getEndLine(int def) {
            int i = this.mCachedEnd;
            if (i != Integer.MIN_VALUE) {
                return i;
            }
            int size = this.mViews.size();
            if (size == 0) {
                return def;
            }
            calculateCachedEnd();
            return this.mCachedEnd;
        }

        void calculateCachedEnd() {
            LazySpanLookup.FullSpanItem fsi;
            ArrayList<View> arrayList = this.mViews;
            View endView = arrayList.get(arrayList.size() - 1);
            LayoutParams lp = getLayoutParams(endView);
            this.mCachedEnd = StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedEnd(endView);
            if (lp.mFullSpan && (fsi = StaggeredGridLayoutManager.this.mLazySpanLookup.getFullSpanItem(lp.getViewLayoutPosition())) != null && fsi.mGapDir == 1) {
                this.mCachedEnd += fsi.getGapForSpan(this.mIndex);
            }
        }

        int getEndLine() {
            int i = this.mCachedEnd;
            if (i != Integer.MIN_VALUE) {
                return i;
            }
            calculateCachedEnd();
            return this.mCachedEnd;
        }

        void prependToSpan(View view) {
            LayoutParams lp = getLayoutParams(view);
            lp.mSpan = this;
            this.mViews.add(0, view);
            this.mCachedStart = Integer.MIN_VALUE;
            if (this.mViews.size() == 1) {
                this.mCachedEnd = Integer.MIN_VALUE;
            }
            if (lp.isItemRemoved() || lp.isItemChanged()) {
                this.mDeletedSize += StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedMeasurement(view);
            }
        }

        void appendToSpan(View view) {
            LayoutParams lp = getLayoutParams(view);
            lp.mSpan = this;
            this.mViews.add(view);
            this.mCachedEnd = Integer.MIN_VALUE;
            if (this.mViews.size() == 1) {
                this.mCachedStart = Integer.MIN_VALUE;
            }
            if (lp.isItemRemoved() || lp.isItemChanged()) {
                this.mDeletedSize += StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedMeasurement(view);
            }
        }

        void cacheReferenceLineAndClear(boolean reverseLayout, int offset) {
            int reference;
            if (reverseLayout) {
                reference = getEndLine(Integer.MIN_VALUE);
            } else {
                reference = getStartLine(Integer.MIN_VALUE);
            }
            clear();
            if (reference == Integer.MIN_VALUE) {
                return;
            }
            if (!reverseLayout || reference >= StaggeredGridLayoutManager.this.mPrimaryOrientation.getEndAfterPadding()) {
                if (!reverseLayout && reference > StaggeredGridLayoutManager.this.mPrimaryOrientation.getStartAfterPadding()) {
                    return;
                }
                if (offset != Integer.MIN_VALUE) {
                    reference += offset;
                }
                this.mCachedEnd = reference;
                this.mCachedStart = reference;
            }
        }

        void clear() {
            this.mViews.clear();
            invalidateCache();
            this.mDeletedSize = 0;
        }

        void invalidateCache() {
            this.mCachedStart = Integer.MIN_VALUE;
            this.mCachedEnd = Integer.MIN_VALUE;
        }

        void setLine(int line) {
            this.mCachedStart = line;
            this.mCachedEnd = line;
        }

        void popEnd() {
            int size = this.mViews.size();
            View end = this.mViews.remove(size - 1);
            LayoutParams lp = getLayoutParams(end);
            lp.mSpan = null;
            if (lp.isItemRemoved() || lp.isItemChanged()) {
                this.mDeletedSize -= StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedMeasurement(end);
            }
            if (size == 1) {
                this.mCachedStart = Integer.MIN_VALUE;
            }
            this.mCachedEnd = Integer.MIN_VALUE;
        }

        void popStart() {
            View start = this.mViews.remove(0);
            LayoutParams lp = getLayoutParams(start);
            lp.mSpan = null;
            if (this.mViews.size() == 0) {
                this.mCachedEnd = Integer.MIN_VALUE;
            }
            if (lp.isItemRemoved() || lp.isItemChanged()) {
                this.mDeletedSize -= StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedMeasurement(start);
            }
            this.mCachedStart = Integer.MIN_VALUE;
        }

        public int getDeletedSize() {
            return this.mDeletedSize;
        }

        LayoutParams getLayoutParams(View view) {
            return (LayoutParams) view.getLayoutParams();
        }

        void onOffset(int dt) {
            int i = this.mCachedStart;
            if (i != Integer.MIN_VALUE) {
                this.mCachedStart = i + dt;
            }
            int i2 = this.mCachedEnd;
            if (i2 != Integer.MIN_VALUE) {
                this.mCachedEnd = i2 + dt;
            }
        }

        public int findFirstVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOneVisibleChild(this.mViews.size() - 1, -1, false);
            }
            return findOneVisibleChild(0, this.mViews.size(), false);
        }

        public int findFirstPartiallyVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOnePartiallyVisibleChild(this.mViews.size() - 1, -1, true);
            }
            return findOnePartiallyVisibleChild(0, this.mViews.size(), true);
        }

        public int findFirstCompletelyVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOneVisibleChild(this.mViews.size() - 1, -1, true);
            }
            return findOneVisibleChild(0, this.mViews.size(), true);
        }

        public int findLastVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOneVisibleChild(0, this.mViews.size(), false);
            }
            return findOneVisibleChild(this.mViews.size() - 1, -1, false);
        }

        public int findLastPartiallyVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOnePartiallyVisibleChild(0, this.mViews.size(), true);
            }
            return findOnePartiallyVisibleChild(this.mViews.size() - 1, -1, true);
        }

        public int findLastCompletelyVisibleItemPosition() {
            if (StaggeredGridLayoutManager.this.mReverseLayout) {
                return findOneVisibleChild(0, this.mViews.size(), true);
            }
            return findOneVisibleChild(this.mViews.size() - 1, -1, true);
        }

        int findOnePartiallyOrCompletelyVisibleChild(int fromIndex, int toIndex, boolean completelyVisible, boolean acceptCompletelyVisible, boolean acceptEndPointInclusion) {
            int start = StaggeredGridLayoutManager.this.mPrimaryOrientation.getStartAfterPadding();
            int end = StaggeredGridLayoutManager.this.mPrimaryOrientation.getEndAfterPadding();
            int next = toIndex > fromIndex ? 1 : -1;
            for (int i = fromIndex; i != toIndex; i += next) {
                View child = this.mViews.get(i);
                int childStart = StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedStart(child);
                int childEnd = StaggeredGridLayoutManager.this.mPrimaryOrientation.getDecoratedEnd(child);
                boolean childEndInclusion = false;
                boolean childStartInclusion = !acceptEndPointInclusion ? childStart >= end : childStart > end;
                if (!acceptEndPointInclusion ? childEnd > start : childEnd >= start) {
                    childEndInclusion = true;
                }
                if (childStartInclusion && childEndInclusion) {
                    if (completelyVisible && acceptCompletelyVisible) {
                        if (childStart >= start && childEnd <= end) {
                            return StaggeredGridLayoutManager.this.getPosition(child);
                        }
                    } else if (acceptCompletelyVisible) {
                        return StaggeredGridLayoutManager.this.getPosition(child);
                    } else {
                        if (childStart < start || childEnd > end) {
                            return StaggeredGridLayoutManager.this.getPosition(child);
                        }
                    }
                }
            }
            return -1;
        }

        int findOneVisibleChild(int fromIndex, int toIndex, boolean completelyVisible) {
            return findOnePartiallyOrCompletelyVisibleChild(fromIndex, toIndex, completelyVisible, true, false);
        }

        int findOnePartiallyVisibleChild(int fromIndex, int toIndex, boolean acceptEndPointInclusion) {
            return findOnePartiallyOrCompletelyVisibleChild(fromIndex, toIndex, false, false, acceptEndPointInclusion);
        }

        public View getFocusableViewAfter(int referenceChildPosition, int layoutDir) {
            View candidate = null;
            if (layoutDir == -1) {
                int limit = this.mViews.size();
                for (int i = 0; i < limit; i++) {
                    View view = this.mViews.get(i);
                    if ((StaggeredGridLayoutManager.this.mReverseLayout && StaggeredGridLayoutManager.this.getPosition(view) <= referenceChildPosition) || ((!StaggeredGridLayoutManager.this.mReverseLayout && StaggeredGridLayoutManager.this.getPosition(view) >= referenceChildPosition) || !view.hasFocusable())) {
                        break;
                    }
                    candidate = view;
                }
            } else {
                for (int i2 = this.mViews.size() - 1; i2 >= 0; i2--) {
                    View view2 = this.mViews.get(i2);
                    if ((StaggeredGridLayoutManager.this.mReverseLayout && StaggeredGridLayoutManager.this.getPosition(view2) >= referenceChildPosition) || ((!StaggeredGridLayoutManager.this.mReverseLayout && StaggeredGridLayoutManager.this.getPosition(view2) <= referenceChildPosition) || !view2.hasFocusable())) {
                        break;
                    }
                    candidate = view2;
                }
            }
            return candidate;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class LazySpanLookup {
        private static final int MIN_SIZE = 10;
        int[] mData;
        List<FullSpanItem> mFullSpanItems;

        LazySpanLookup() {
        }

        int forceInvalidateAfter(int position) {
            List<FullSpanItem> list = this.mFullSpanItems;
            if (list != null) {
                for (int i = list.size() - 1; i >= 0; i--) {
                    FullSpanItem fsi = this.mFullSpanItems.get(i);
                    if (fsi.mPosition >= position) {
                        this.mFullSpanItems.remove(i);
                    }
                }
            }
            int i2 = invalidateAfter(position);
            return i2;
        }

        int invalidateAfter(int position) {
            int[] iArr = this.mData;
            if (iArr != null && position < iArr.length) {
                int endPosition = invalidateFullSpansAfter(position);
                if (endPosition == -1) {
                    int[] iArr2 = this.mData;
                    Arrays.fill(iArr2, position, iArr2.length, -1);
                    return this.mData.length;
                }
                Arrays.fill(this.mData, position, endPosition + 1, -1);
                return endPosition + 1;
            }
            return -1;
        }

        int getSpan(int position) {
            int[] iArr = this.mData;
            if (iArr == null || position >= iArr.length) {
                return -1;
            }
            return iArr[position];
        }

        void setSpan(int position, Span span) {
            ensureSize(position);
            this.mData[position] = span.mIndex;
        }

        int sizeForPosition(int position) {
            int len = this.mData.length;
            while (len <= position) {
                len *= 2;
            }
            return len;
        }

        void ensureSize(int position) {
            int[] iArr = this.mData;
            if (iArr == null) {
                int[] iArr2 = new int[Math.max(position, 10) + 1];
                this.mData = iArr2;
                Arrays.fill(iArr2, -1);
            } else if (position >= iArr.length) {
                int[] old = this.mData;
                int[] iArr3 = new int[sizeForPosition(position)];
                this.mData = iArr3;
                System.arraycopy(old, 0, iArr3, 0, old.length);
                int[] iArr4 = this.mData;
                Arrays.fill(iArr4, old.length, iArr4.length, -1);
            }
        }

        void clear() {
            int[] iArr = this.mData;
            if (iArr != null) {
                Arrays.fill(iArr, -1);
            }
            this.mFullSpanItems = null;
        }

        void offsetForRemoval(int positionStart, int itemCount) {
            int[] iArr = this.mData;
            if (iArr == null || positionStart >= iArr.length) {
                return;
            }
            ensureSize(positionStart + itemCount);
            int[] iArr2 = this.mData;
            System.arraycopy(iArr2, positionStart + itemCount, iArr2, positionStart, (iArr2.length - positionStart) - itemCount);
            int[] iArr3 = this.mData;
            Arrays.fill(iArr3, iArr3.length - itemCount, iArr3.length, -1);
            offsetFullSpansForRemoval(positionStart, itemCount);
        }

        private void offsetFullSpansForRemoval(int positionStart, int itemCount) {
            List<FullSpanItem> list = this.mFullSpanItems;
            if (list == null) {
                return;
            }
            int end = positionStart + itemCount;
            for (int i = list.size() - 1; i >= 0; i--) {
                FullSpanItem fsi = this.mFullSpanItems.get(i);
                if (fsi.mPosition >= positionStart) {
                    if (fsi.mPosition < end) {
                        this.mFullSpanItems.remove(i);
                    } else {
                        fsi.mPosition -= itemCount;
                    }
                }
            }
        }

        void offsetForAddition(int positionStart, int itemCount) {
            int[] iArr = this.mData;
            if (iArr == null || positionStart >= iArr.length) {
                return;
            }
            ensureSize(positionStart + itemCount);
            int[] iArr2 = this.mData;
            System.arraycopy(iArr2, positionStart, iArr2, positionStart + itemCount, (iArr2.length - positionStart) - itemCount);
            Arrays.fill(this.mData, positionStart, positionStart + itemCount, -1);
            offsetFullSpansForAddition(positionStart, itemCount);
        }

        private void offsetFullSpansForAddition(int positionStart, int itemCount) {
            List<FullSpanItem> list = this.mFullSpanItems;
            if (list == null) {
                return;
            }
            for (int i = list.size() - 1; i >= 0; i--) {
                FullSpanItem fsi = this.mFullSpanItems.get(i);
                if (fsi.mPosition >= positionStart) {
                    fsi.mPosition += itemCount;
                }
            }
        }

        private int invalidateFullSpansAfter(int position) {
            if (this.mFullSpanItems == null) {
                return -1;
            }
            FullSpanItem item = getFullSpanItem(position);
            if (item != null) {
                this.mFullSpanItems.remove(item);
            }
            int nextFsiIndex = -1;
            int count = this.mFullSpanItems.size();
            int i = 0;
            while (true) {
                if (i >= count) {
                    break;
                }
                FullSpanItem fsi = this.mFullSpanItems.get(i);
                if (fsi.mPosition < position) {
                    i++;
                } else {
                    nextFsiIndex = i;
                    break;
                }
            }
            if (nextFsiIndex != -1) {
                FullSpanItem fsi2 = this.mFullSpanItems.get(nextFsiIndex);
                this.mFullSpanItems.remove(nextFsiIndex);
                return fsi2.mPosition;
            }
            return -1;
        }

        public void addFullSpanItem(FullSpanItem fullSpanItem) {
            if (this.mFullSpanItems == null) {
                this.mFullSpanItems = new ArrayList();
            }
            int size = this.mFullSpanItems.size();
            for (int i = 0; i < size; i++) {
                FullSpanItem other = this.mFullSpanItems.get(i);
                if (other.mPosition == fullSpanItem.mPosition) {
                    this.mFullSpanItems.remove(i);
                }
                if (other.mPosition >= fullSpanItem.mPosition) {
                    this.mFullSpanItems.add(i, fullSpanItem);
                    return;
                }
            }
            this.mFullSpanItems.add(fullSpanItem);
        }

        public FullSpanItem getFullSpanItem(int position) {
            List<FullSpanItem> list = this.mFullSpanItems;
            if (list == null) {
                return null;
            }
            for (int i = list.size() - 1; i >= 0; i--) {
                FullSpanItem fsi = this.mFullSpanItems.get(i);
                if (fsi.mPosition == position) {
                    return fsi;
                }
            }
            return null;
        }

        public FullSpanItem getFirstFullSpanItemInRange(int minPos, int maxPos, int gapDir, boolean hasUnwantedGapAfter) {
            List<FullSpanItem> list = this.mFullSpanItems;
            if (list == null) {
                return null;
            }
            int limit = list.size();
            for (int i = 0; i < limit; i++) {
                FullSpanItem fsi = this.mFullSpanItems.get(i);
                if (fsi.mPosition >= maxPos) {
                    return null;
                }
                if (fsi.mPosition >= minPos && (gapDir == 0 || fsi.mGapDir == gapDir || (hasUnwantedGapAfter && fsi.mHasUnwantedGapAfter))) {
                    return fsi;
                }
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* loaded from: classes.dex */
        public static class FullSpanItem implements Parcelable {
            public static final Parcelable.Creator<FullSpanItem> CREATOR = new Parcelable.Creator<FullSpanItem>() { // from class: androidx.recyclerview.widget.StaggeredGridLayoutManager.LazySpanLookup.FullSpanItem.1
                /* JADX WARN: Can't rename method to resolve collision */
                @Override // android.os.Parcelable.Creator
                public FullSpanItem createFromParcel(Parcel in) {
                    return new FullSpanItem(in);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // android.os.Parcelable.Creator
                public FullSpanItem[] newArray(int size) {
                    return new FullSpanItem[size];
                }
            };
            int mGapDir;
            int[] mGapPerSpan;
            boolean mHasUnwantedGapAfter;
            int mPosition;

            FullSpanItem(Parcel in) {
                this.mPosition = in.readInt();
                this.mGapDir = in.readInt();
                this.mHasUnwantedGapAfter = in.readInt() == 1;
                int spanCount = in.readInt();
                if (spanCount > 0) {
                    int[] iArr = new int[spanCount];
                    this.mGapPerSpan = iArr;
                    in.readIntArray(iArr);
                }
            }

            FullSpanItem() {
            }

            int getGapForSpan(int spanIndex) {
                int[] iArr = this.mGapPerSpan;
                if (iArr == null) {
                    return 0;
                }
                return iArr[spanIndex];
            }

            @Override // android.os.Parcelable
            public int describeContents() {
                return 0;
            }

            @Override // android.os.Parcelable
            public void writeToParcel(Parcel dest, int flags) {
                dest.writeInt(this.mPosition);
                dest.writeInt(this.mGapDir);
                dest.writeInt(this.mHasUnwantedGapAfter ? 1 : 0);
                int[] iArr = this.mGapPerSpan;
                if (iArr != null && iArr.length > 0) {
                    dest.writeInt(iArr.length);
                    dest.writeIntArray(this.mGapPerSpan);
                    return;
                }
                dest.writeInt(0);
            }

            public String toString() {
                return "FullSpanItem{mPosition=" + this.mPosition + ", mGapDir=" + this.mGapDir + ", mHasUnwantedGapAfter=" + this.mHasUnwantedGapAfter + ", mGapPerSpan=" + Arrays.toString(this.mGapPerSpan) + '}';
            }
        }
    }

    /* loaded from: classes.dex */
    public static class SavedState implements Parcelable {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.Creator<SavedState>() { // from class: androidx.recyclerview.widget.StaggeredGridLayoutManager.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        boolean mAnchorLayoutFromEnd;
        int mAnchorPosition;
        List<LazySpanLookup.FullSpanItem> mFullSpanItems;
        boolean mLastLayoutRTL;
        boolean mReverseLayout;
        int[] mSpanLookup;
        int mSpanLookupSize;
        int[] mSpanOffsets;
        int mSpanOffsetsSize;
        int mVisibleAnchorPosition;

        public SavedState() {
        }

        SavedState(Parcel in) {
            this.mAnchorPosition = in.readInt();
            this.mVisibleAnchorPosition = in.readInt();
            int readInt = in.readInt();
            this.mSpanOffsetsSize = readInt;
            if (readInt > 0) {
                int[] iArr = new int[readInt];
                this.mSpanOffsets = iArr;
                in.readIntArray(iArr);
            }
            int readInt2 = in.readInt();
            this.mSpanLookupSize = readInt2;
            if (readInt2 > 0) {
                int[] iArr2 = new int[readInt2];
                this.mSpanLookup = iArr2;
                in.readIntArray(iArr2);
            }
            this.mReverseLayout = in.readInt() == 1;
            this.mAnchorLayoutFromEnd = in.readInt() == 1;
            this.mLastLayoutRTL = in.readInt() == 1;
            List<LazySpanLookup.FullSpanItem> fullSpanItems = in.readArrayList(LazySpanLookup.FullSpanItem.class.getClassLoader());
            this.mFullSpanItems = fullSpanItems;
        }

        public SavedState(SavedState other) {
            this.mSpanOffsetsSize = other.mSpanOffsetsSize;
            this.mAnchorPosition = other.mAnchorPosition;
            this.mVisibleAnchorPosition = other.mVisibleAnchorPosition;
            this.mSpanOffsets = other.mSpanOffsets;
            this.mSpanLookupSize = other.mSpanLookupSize;
            this.mSpanLookup = other.mSpanLookup;
            this.mReverseLayout = other.mReverseLayout;
            this.mAnchorLayoutFromEnd = other.mAnchorLayoutFromEnd;
            this.mLastLayoutRTL = other.mLastLayoutRTL;
            this.mFullSpanItems = other.mFullSpanItems;
        }

        void invalidateSpanInfo() {
            this.mSpanOffsets = null;
            this.mSpanOffsetsSize = 0;
            this.mSpanLookupSize = 0;
            this.mSpanLookup = null;
            this.mFullSpanItems = null;
        }

        void invalidateAnchorPositionInfo() {
            this.mSpanOffsets = null;
            this.mSpanOffsetsSize = 0;
            this.mAnchorPosition = -1;
            this.mVisibleAnchorPosition = -1;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeInt(this.mAnchorPosition);
            dest.writeInt(this.mVisibleAnchorPosition);
            dest.writeInt(this.mSpanOffsetsSize);
            if (this.mSpanOffsetsSize > 0) {
                dest.writeIntArray(this.mSpanOffsets);
            }
            dest.writeInt(this.mSpanLookupSize);
            if (this.mSpanLookupSize > 0) {
                dest.writeIntArray(this.mSpanLookup);
            }
            dest.writeInt(this.mReverseLayout ? 1 : 0);
            dest.writeInt(this.mAnchorLayoutFromEnd ? 1 : 0);
            dest.writeInt(this.mLastLayoutRTL ? 1 : 0);
            dest.writeList(this.mFullSpanItems);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class AnchorInfo {
        boolean mInvalidateOffsets;
        boolean mLayoutFromEnd;
        int mOffset;
        int mPosition;
        int[] mSpanReferenceLines;
        boolean mValid;

        AnchorInfo() {
            reset();
        }

        void reset() {
            this.mPosition = -1;
            this.mOffset = Integer.MIN_VALUE;
            this.mLayoutFromEnd = false;
            this.mInvalidateOffsets = false;
            this.mValid = false;
            int[] iArr = this.mSpanReferenceLines;
            if (iArr != null) {
                Arrays.fill(iArr, -1);
            }
        }

        void saveSpanReferenceLines(Span[] spans) {
            int spanCount = spans.length;
            int[] iArr = this.mSpanReferenceLines;
            if (iArr == null || iArr.length < spanCount) {
                this.mSpanReferenceLines = new int[StaggeredGridLayoutManager.this.mSpans.length];
            }
            for (int i = 0; i < spanCount; i++) {
                this.mSpanReferenceLines[i] = spans[i].getStartLine(Integer.MIN_VALUE);
            }
        }

        void assignCoordinateFromPadding() {
            this.mOffset = this.mLayoutFromEnd ? StaggeredGridLayoutManager.this.mPrimaryOrientation.getEndAfterPadding() : StaggeredGridLayoutManager.this.mPrimaryOrientation.getStartAfterPadding();
        }

        void assignCoordinateFromPadding(int addedDistance) {
            if (this.mLayoutFromEnd) {
                this.mOffset = StaggeredGridLayoutManager.this.mPrimaryOrientation.getEndAfterPadding() - addedDistance;
            } else {
                this.mOffset = StaggeredGridLayoutManager.this.mPrimaryOrientation.getStartAfterPadding() + addedDistance;
            }
        }
    }
}
