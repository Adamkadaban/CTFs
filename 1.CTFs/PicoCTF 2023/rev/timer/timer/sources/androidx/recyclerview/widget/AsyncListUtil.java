package androidx.recyclerview.widget;

import android.util.Log;
import android.util.SparseBooleanArray;
import android.util.SparseIntArray;
import androidx.recyclerview.widget.ThreadUtil;
import androidx.recyclerview.widget.TileList;
/* loaded from: classes.dex */
public class AsyncListUtil<T> {
    static final boolean DEBUG = false;
    static final String TAG = "AsyncListUtil";
    boolean mAllowScrollHints;
    private final ThreadUtil.BackgroundCallback<T> mBackgroundCallback;
    final ThreadUtil.BackgroundCallback<T> mBackgroundProxy;
    final DataCallback<T> mDataCallback;
    private final ThreadUtil.MainThreadCallback<T> mMainThreadCallback;
    final ThreadUtil.MainThreadCallback<T> mMainThreadProxy;
    final Class<T> mTClass;
    final TileList<T> mTileList;
    final int mTileSize;
    final ViewCallback mViewCallback;
    final int[] mTmpRange = new int[2];
    final int[] mPrevRange = new int[2];
    final int[] mTmpRangeExtended = new int[2];
    private int mScrollHint = 0;
    int mItemCount = 0;
    int mDisplayedGeneration = 0;
    int mRequestedGeneration = 0;
    final SparseIntArray mMissingPositions = new SparseIntArray();

    void log(String s, Object... args) {
        Log.d(TAG, "[MAIN] " + String.format(s, args));
    }

    public AsyncListUtil(Class<T> klass, int tileSize, DataCallback<T> dataCallback, ViewCallback viewCallback) {
        ThreadUtil.MainThreadCallback<T> mainThreadCallback = new ThreadUtil.MainThreadCallback<T>() { // from class: androidx.recyclerview.widget.AsyncListUtil.1
            @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
            public void updateItemCount(int generation, int itemCount) {
                if (!isRequestedGeneration(generation)) {
                    return;
                }
                AsyncListUtil.this.mItemCount = itemCount;
                AsyncListUtil.this.mViewCallback.onDataRefresh();
                AsyncListUtil asyncListUtil = AsyncListUtil.this;
                asyncListUtil.mDisplayedGeneration = asyncListUtil.mRequestedGeneration;
                recycleAllTiles();
                AsyncListUtil.this.mAllowScrollHints = false;
                AsyncListUtil.this.updateRange();
            }

            @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
            public void addTile(int generation, TileList.Tile<T> tile) {
                if (!isRequestedGeneration(generation)) {
                    AsyncListUtil.this.mBackgroundProxy.recycleTile(tile);
                    return;
                }
                TileList.Tile<T> duplicate = AsyncListUtil.this.mTileList.addOrReplace(tile);
                if (duplicate != null) {
                    Log.e(AsyncListUtil.TAG, "duplicate tile @" + duplicate.mStartPosition);
                    AsyncListUtil.this.mBackgroundProxy.recycleTile(duplicate);
                }
                int endPosition = tile.mStartPosition + tile.mItemCount;
                int index = 0;
                while (index < AsyncListUtil.this.mMissingPositions.size()) {
                    int position = AsyncListUtil.this.mMissingPositions.keyAt(index);
                    if (tile.mStartPosition <= position && position < endPosition) {
                        AsyncListUtil.this.mMissingPositions.removeAt(index);
                        AsyncListUtil.this.mViewCallback.onItemLoaded(position);
                    } else {
                        index++;
                    }
                }
            }

            @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
            public void removeTile(int generation, int position) {
                if (!isRequestedGeneration(generation)) {
                    return;
                }
                TileList.Tile<T> tile = AsyncListUtil.this.mTileList.removeAtPos(position);
                if (tile == null) {
                    Log.e(AsyncListUtil.TAG, "tile not found @" + position);
                    return;
                }
                AsyncListUtil.this.mBackgroundProxy.recycleTile(tile);
            }

            private void recycleAllTiles() {
                for (int i = 0; i < AsyncListUtil.this.mTileList.size(); i++) {
                    AsyncListUtil.this.mBackgroundProxy.recycleTile(AsyncListUtil.this.mTileList.getAtIndex(i));
                }
                AsyncListUtil.this.mTileList.clear();
            }

            private boolean isRequestedGeneration(int generation) {
                return generation == AsyncListUtil.this.mRequestedGeneration;
            }
        };
        this.mMainThreadCallback = mainThreadCallback;
        ThreadUtil.BackgroundCallback<T> backgroundCallback = new ThreadUtil.BackgroundCallback<T>() { // from class: androidx.recyclerview.widget.AsyncListUtil.2
            private int mFirstRequiredTileStart;
            private int mGeneration;
            private int mItemCount;
            private int mLastRequiredTileStart;
            final SparseBooleanArray mLoadedTiles = new SparseBooleanArray();
            private TileList.Tile<T> mRecycledRoot;

            @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
            public void refresh(int generation) {
                this.mGeneration = generation;
                this.mLoadedTiles.clear();
                this.mItemCount = AsyncListUtil.this.mDataCallback.refreshData();
                AsyncListUtil.this.mMainThreadProxy.updateItemCount(this.mGeneration, this.mItemCount);
            }

            @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
            public void updateRange(int rangeStart, int rangeEnd, int extRangeStart, int extRangeEnd, int scrollHint) {
                if (rangeStart > rangeEnd) {
                    return;
                }
                int firstVisibleTileStart = getTileStart(rangeStart);
                int lastVisibleTileStart = getTileStart(rangeEnd);
                this.mFirstRequiredTileStart = getTileStart(extRangeStart);
                int tileStart = getTileStart(extRangeEnd);
                this.mLastRequiredTileStart = tileStart;
                if (scrollHint == 1) {
                    requestTiles(this.mFirstRequiredTileStart, lastVisibleTileStart, scrollHint, true);
                    requestTiles(AsyncListUtil.this.mTileSize + lastVisibleTileStart, this.mLastRequiredTileStart, scrollHint, false);
                    return;
                }
                requestTiles(firstVisibleTileStart, tileStart, scrollHint, false);
                requestTiles(this.mFirstRequiredTileStart, firstVisibleTileStart - AsyncListUtil.this.mTileSize, scrollHint, true);
            }

            private int getTileStart(int position) {
                return position - (position % AsyncListUtil.this.mTileSize);
            }

            private void requestTiles(int firstTileStart, int lastTileStart, int scrollHint, boolean backwards) {
                int i = firstTileStart;
                while (i <= lastTileStart) {
                    int tileStart = backwards ? (lastTileStart + firstTileStart) - i : i;
                    AsyncListUtil.this.mBackgroundProxy.loadTile(tileStart, scrollHint);
                    i += AsyncListUtil.this.mTileSize;
                }
            }

            @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
            public void loadTile(int position, int scrollHint) {
                if (isTileLoaded(position)) {
                    return;
                }
                TileList.Tile<T> tile = acquireTile();
                tile.mStartPosition = position;
                tile.mItemCount = Math.min(AsyncListUtil.this.mTileSize, this.mItemCount - tile.mStartPosition);
                AsyncListUtil.this.mDataCallback.fillData(tile.mItems, tile.mStartPosition, tile.mItemCount);
                flushTileCache(scrollHint);
                addTile(tile);
            }

            @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
            public void recycleTile(TileList.Tile<T> tile) {
                AsyncListUtil.this.mDataCallback.recycleData(tile.mItems, tile.mItemCount);
                tile.mNext = this.mRecycledRoot;
                this.mRecycledRoot = tile;
            }

            private TileList.Tile<T> acquireTile() {
                TileList.Tile<T> tile = this.mRecycledRoot;
                if (tile != null) {
                    TileList.Tile<T> result = this.mRecycledRoot;
                    this.mRecycledRoot = tile.mNext;
                    return result;
                }
                return new TileList.Tile<>(AsyncListUtil.this.mTClass, AsyncListUtil.this.mTileSize);
            }

            private boolean isTileLoaded(int position) {
                return this.mLoadedTiles.get(position);
            }

            private void addTile(TileList.Tile<T> tile) {
                this.mLoadedTiles.put(tile.mStartPosition, true);
                AsyncListUtil.this.mMainThreadProxy.addTile(this.mGeneration, tile);
            }

            private void removeTile(int position) {
                this.mLoadedTiles.delete(position);
                AsyncListUtil.this.mMainThreadProxy.removeTile(this.mGeneration, position);
            }

            private void flushTileCache(int scrollHint) {
                int cacheSizeLimit = AsyncListUtil.this.mDataCallback.getMaxCachedTiles();
                while (this.mLoadedTiles.size() >= cacheSizeLimit) {
                    int firstLoadedTileStart = this.mLoadedTiles.keyAt(0);
                    SparseBooleanArray sparseBooleanArray = this.mLoadedTiles;
                    int lastLoadedTileStart = sparseBooleanArray.keyAt(sparseBooleanArray.size() - 1);
                    int startMargin = this.mFirstRequiredTileStart - firstLoadedTileStart;
                    int endMargin = lastLoadedTileStart - this.mLastRequiredTileStart;
                    if (startMargin > 0 && (startMargin >= endMargin || scrollHint == 2)) {
                        removeTile(firstLoadedTileStart);
                    } else if (endMargin <= 0) {
                        return;
                    } else {
                        if (startMargin < endMargin || scrollHint == 1) {
                            removeTile(lastLoadedTileStart);
                        } else {
                            return;
                        }
                    }
                }
            }

            private void log(String s, Object... args) {
                Log.d(AsyncListUtil.TAG, "[BKGR] " + String.format(s, args));
            }
        };
        this.mBackgroundCallback = backgroundCallback;
        this.mTClass = klass;
        this.mTileSize = tileSize;
        this.mDataCallback = dataCallback;
        this.mViewCallback = viewCallback;
        this.mTileList = new TileList<>(tileSize);
        ThreadUtil<T> threadUtil = new MessageThreadUtil<>();
        this.mMainThreadProxy = threadUtil.getMainThreadProxy(mainThreadCallback);
        this.mBackgroundProxy = threadUtil.getBackgroundProxy(backgroundCallback);
        refresh();
    }

    private boolean isRefreshPending() {
        return this.mRequestedGeneration != this.mDisplayedGeneration;
    }

    public void onRangeChanged() {
        if (isRefreshPending()) {
            return;
        }
        updateRange();
        this.mAllowScrollHints = true;
    }

    public void refresh() {
        this.mMissingPositions.clear();
        ThreadUtil.BackgroundCallback<T> backgroundCallback = this.mBackgroundProxy;
        int i = this.mRequestedGeneration + 1;
        this.mRequestedGeneration = i;
        backgroundCallback.refresh(i);
    }

    public T getItem(int position) {
        if (position < 0 || position >= this.mItemCount) {
            throw new IndexOutOfBoundsException(position + " is not within 0 and " + this.mItemCount);
        }
        T item = this.mTileList.getItemAt(position);
        if (item == null && !isRefreshPending()) {
            this.mMissingPositions.put(position, 0);
        }
        return item;
    }

    public int getItemCount() {
        return this.mItemCount;
    }

    void updateRange() {
        this.mViewCallback.getItemRangeInto(this.mTmpRange);
        int[] iArr = this.mTmpRange;
        if (iArr[0] > iArr[1] || iArr[0] < 0 || iArr[1] >= this.mItemCount) {
            return;
        }
        if (!this.mAllowScrollHints) {
            this.mScrollHint = 0;
        } else {
            int i = iArr[0];
            int[] iArr2 = this.mPrevRange;
            if (i > iArr2[1] || iArr2[0] > iArr[1]) {
                this.mScrollHint = 0;
            } else if (iArr[0] < iArr2[0]) {
                this.mScrollHint = 1;
            } else if (iArr[0] > iArr2[0]) {
                this.mScrollHint = 2;
            }
        }
        int[] iArr3 = this.mPrevRange;
        iArr3[0] = iArr[0];
        iArr3[1] = iArr[1];
        this.mViewCallback.extendRangeInto(iArr, this.mTmpRangeExtended, this.mScrollHint);
        int[] iArr4 = this.mTmpRangeExtended;
        iArr4[0] = Math.min(this.mTmpRange[0], Math.max(iArr4[0], 0));
        int[] iArr5 = this.mTmpRangeExtended;
        iArr5[1] = Math.max(this.mTmpRange[1], Math.min(iArr5[1], this.mItemCount - 1));
        ThreadUtil.BackgroundCallback<T> backgroundCallback = this.mBackgroundProxy;
        int[] iArr6 = this.mTmpRange;
        int i2 = iArr6[0];
        int i3 = iArr6[1];
        int[] iArr7 = this.mTmpRangeExtended;
        backgroundCallback.updateRange(i2, i3, iArr7[0], iArr7[1], this.mScrollHint);
    }

    /* loaded from: classes.dex */
    public static abstract class DataCallback<T> {
        public abstract void fillData(T[] tArr, int i, int i2);

        public abstract int refreshData();

        public void recycleData(T[] data, int itemCount) {
        }

        public int getMaxCachedTiles() {
            return 10;
        }
    }

    /* loaded from: classes.dex */
    public static abstract class ViewCallback {
        public static final int HINT_SCROLL_ASC = 2;
        public static final int HINT_SCROLL_DESC = 1;
        public static final int HINT_SCROLL_NONE = 0;

        public abstract void getItemRangeInto(int[] iArr);

        public abstract void onDataRefresh();

        public abstract void onItemLoaded(int i);

        public void extendRangeInto(int[] range, int[] outRange, int scrollHint) {
            int fullRange = (range[1] - range[0]) + 1;
            int halfRange = fullRange / 2;
            outRange[0] = range[0] - (scrollHint == 1 ? fullRange : halfRange);
            outRange[1] = range[1] + (scrollHint == 2 ? fullRange : halfRange);
        }
    }
}
