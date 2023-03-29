package androidx.viewpager2.adapter;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcelable;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.collection.ArraySet;
import androidx.collection.LongSparseArray;
import androidx.core.util.Preconditions;
import androidx.core.view.ViewCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;
import java.util.Set;
/* loaded from: classes.dex */
public abstract class FragmentStateAdapter extends RecyclerView.Adapter<FragmentViewHolder> implements StatefulAdapter {
    private static final long GRACE_WINDOW_TIME_MS = 10000;
    private static final String KEY_PREFIX_FRAGMENT = "f#";
    private static final String KEY_PREFIX_STATE = "s#";
    final FragmentManager mFragmentManager;
    private FragmentMaxLifecycleEnforcer mFragmentMaxLifecycleEnforcer;
    final LongSparseArray<Fragment> mFragments;
    private boolean mHasStaleFragments;
    boolean mIsInGracePeriod;
    private final LongSparseArray<Integer> mItemIdToViewHolder;
    final Lifecycle mLifecycle;
    private final LongSparseArray<Fragment.SavedState> mSavedStates;

    public abstract Fragment createFragment(int i);

    public FragmentStateAdapter(FragmentActivity fragmentActivity) {
        this(fragmentActivity.getSupportFragmentManager(), fragmentActivity.getLifecycle());
    }

    public FragmentStateAdapter(Fragment fragment) {
        this(fragment.getChildFragmentManager(), fragment.getLifecycle());
    }

    public FragmentStateAdapter(FragmentManager fragmentManager, Lifecycle lifecycle) {
        this.mFragments = new LongSparseArray<>();
        this.mSavedStates = new LongSparseArray<>();
        this.mItemIdToViewHolder = new LongSparseArray<>();
        this.mIsInGracePeriod = false;
        this.mHasStaleFragments = false;
        this.mFragmentManager = fragmentManager;
        this.mLifecycle = lifecycle;
        super.setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        Preconditions.checkArgument(this.mFragmentMaxLifecycleEnforcer == null);
        FragmentMaxLifecycleEnforcer fragmentMaxLifecycleEnforcer = new FragmentMaxLifecycleEnforcer();
        this.mFragmentMaxLifecycleEnforcer = fragmentMaxLifecycleEnforcer;
        fragmentMaxLifecycleEnforcer.register(recyclerView);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        this.mFragmentMaxLifecycleEnforcer.unregister(recyclerView);
        this.mFragmentMaxLifecycleEnforcer = null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final FragmentViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return FragmentViewHolder.create(parent);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onBindViewHolder(final FragmentViewHolder holder, int position) {
        long itemId = holder.getItemId();
        int viewHolderId = holder.getContainer().getId();
        Long boundItemId = itemForViewHolder(viewHolderId);
        if (boundItemId != null && boundItemId.longValue() != itemId) {
            removeFragment(boundItemId.longValue());
            this.mItemIdToViewHolder.remove(boundItemId.longValue());
        }
        this.mItemIdToViewHolder.put(itemId, Integer.valueOf(viewHolderId));
        ensureFragment(position);
        final FrameLayout container = holder.getContainer();
        if (ViewCompat.isAttachedToWindow(container)) {
            if (container.getParent() != null) {
                throw new IllegalStateException("Design assumption violated.");
            }
            container.addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.1
                @Override // android.view.View.OnLayoutChangeListener
                public void onLayoutChange(View v, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                    if (container.getParent() != null) {
                        container.removeOnLayoutChangeListener(this);
                        FragmentStateAdapter.this.placeFragmentInViewHolder(holder);
                    }
                }
            });
        }
        gcFragments();
    }

    void gcFragments() {
        if (!this.mHasStaleFragments || shouldDelayFragmentTransactions()) {
            return;
        }
        Set<Long> toRemove = new ArraySet<>();
        for (int ix = 0; ix < this.mFragments.size(); ix++) {
            long itemId = this.mFragments.keyAt(ix);
            if (!containsItem(itemId)) {
                toRemove.add(Long.valueOf(itemId));
                this.mItemIdToViewHolder.remove(itemId);
            }
        }
        if (!this.mIsInGracePeriod) {
            this.mHasStaleFragments = false;
            for (int ix2 = 0; ix2 < this.mFragments.size(); ix2++) {
                long itemId2 = this.mFragments.keyAt(ix2);
                if (!isFragmentViewBound(itemId2)) {
                    toRemove.add(Long.valueOf(itemId2));
                }
            }
        }
        for (Long itemId3 : toRemove) {
            removeFragment(itemId3.longValue());
        }
    }

    private boolean isFragmentViewBound(long itemId) {
        View view;
        if (this.mItemIdToViewHolder.containsKey(itemId)) {
            return true;
        }
        Fragment fragment = this.mFragments.get(itemId);
        return (fragment == null || (view = fragment.getView()) == null || view.getParent() == null) ? false : true;
    }

    private Long itemForViewHolder(int viewHolderId) {
        Long boundItemId = null;
        for (int ix = 0; ix < this.mItemIdToViewHolder.size(); ix++) {
            if (this.mItemIdToViewHolder.valueAt(ix).intValue() == viewHolderId) {
                if (boundItemId != null) {
                    throw new IllegalStateException("Design assumption violated: a ViewHolder can only be bound to one item at a time.");
                }
                boundItemId = Long.valueOf(this.mItemIdToViewHolder.keyAt(ix));
            }
        }
        return boundItemId;
    }

    private void ensureFragment(int position) {
        long itemId = getItemId(position);
        if (!this.mFragments.containsKey(itemId)) {
            Fragment newFragment = createFragment(position);
            newFragment.setInitialSavedState(this.mSavedStates.get(itemId));
            this.mFragments.put(itemId, newFragment);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onViewAttachedToWindow(FragmentViewHolder holder) {
        placeFragmentInViewHolder(holder);
        gcFragments();
    }

    void placeFragmentInViewHolder(final FragmentViewHolder holder) {
        Fragment fragment = this.mFragments.get(holder.getItemId());
        if (fragment == null) {
            throw new IllegalStateException("Design assumption violated.");
        }
        FrameLayout container = holder.getContainer();
        View view = fragment.getView();
        if (!fragment.isAdded() && view != null) {
            throw new IllegalStateException("Design assumption violated.");
        }
        if (fragment.isAdded() && view == null) {
            scheduleViewAttach(fragment, container);
        } else if (fragment.isAdded() && view.getParent() != null) {
            if (view.getParent() != container) {
                addViewToContainer(view, container);
            }
        } else if (fragment.isAdded()) {
            addViewToContainer(view, container);
        } else if (!shouldDelayFragmentTransactions()) {
            scheduleViewAttach(fragment, container);
            FragmentTransaction beginTransaction = this.mFragmentManager.beginTransaction();
            beginTransaction.add(fragment, "f" + holder.getItemId()).setMaxLifecycle(fragment, Lifecycle.State.STARTED).commitNow();
            this.mFragmentMaxLifecycleEnforcer.updateFragmentMaxLifecycle(false);
        } else if (this.mFragmentManager.isDestroyed()) {
        } else {
            this.mLifecycle.addObserver(new LifecycleEventObserver() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.2
                @Override // androidx.lifecycle.LifecycleEventObserver
                public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                    if (FragmentStateAdapter.this.shouldDelayFragmentTransactions()) {
                        return;
                    }
                    source.getLifecycle().removeObserver(this);
                    if (ViewCompat.isAttachedToWindow(holder.getContainer())) {
                        FragmentStateAdapter.this.placeFragmentInViewHolder(holder);
                    }
                }
            });
        }
    }

    private void scheduleViewAttach(final Fragment fragment, final FrameLayout container) {
        this.mFragmentManager.registerFragmentLifecycleCallbacks(new FragmentManager.FragmentLifecycleCallbacks() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.3
            @Override // androidx.fragment.app.FragmentManager.FragmentLifecycleCallbacks
            public void onFragmentViewCreated(FragmentManager fm, Fragment f, View v, Bundle savedInstanceState) {
                if (f == fragment) {
                    fm.unregisterFragmentLifecycleCallbacks(this);
                    FragmentStateAdapter.this.addViewToContainer(v, container);
                }
            }
        }, false);
    }

    void addViewToContainer(View v, FrameLayout container) {
        if (container.getChildCount() > 1) {
            throw new IllegalStateException("Design assumption violated.");
        }
        if (v.getParent() == container) {
            return;
        }
        if (container.getChildCount() > 0) {
            container.removeAllViews();
        }
        if (v.getParent() != null) {
            ((ViewGroup) v.getParent()).removeView(v);
        }
        container.addView(v);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onViewRecycled(FragmentViewHolder holder) {
        int viewHolderId = holder.getContainer().getId();
        Long boundItemId = itemForViewHolder(viewHolderId);
        if (boundItemId != null) {
            removeFragment(boundItemId.longValue());
            this.mItemIdToViewHolder.remove(boundItemId.longValue());
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final boolean onFailedToRecycleView(FragmentViewHolder holder) {
        return true;
    }

    private void removeFragment(long itemId) {
        ViewParent viewParent;
        Fragment fragment = this.mFragments.get(itemId);
        if (fragment == null) {
            return;
        }
        if (fragment.getView() != null && (viewParent = fragment.getView().getParent()) != null) {
            ((FrameLayout) viewParent).removeAllViews();
        }
        if (!containsItem(itemId)) {
            this.mSavedStates.remove(itemId);
        }
        if (!fragment.isAdded()) {
            this.mFragments.remove(itemId);
        } else if (shouldDelayFragmentTransactions()) {
            this.mHasStaleFragments = true;
        } else {
            if (fragment.isAdded() && containsItem(itemId)) {
                this.mSavedStates.put(itemId, this.mFragmentManager.saveFragmentInstanceState(fragment));
            }
            this.mFragmentManager.beginTransaction().remove(fragment).commitNow();
            this.mFragments.remove(itemId);
        }
    }

    boolean shouldDelayFragmentTransactions() {
        return this.mFragmentManager.isStateSaved();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        return position;
    }

    public boolean containsItem(long itemId) {
        return itemId >= 0 && itemId < ((long) getItemCount());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void setHasStableIds(boolean hasStableIds) {
        throw new UnsupportedOperationException("Stable Ids are required for the adapter to function properly, and the adapter takes care of setting the flag.");
    }

    @Override // androidx.viewpager2.adapter.StatefulAdapter
    public final Parcelable saveState() {
        Bundle savedState = new Bundle(this.mFragments.size() + this.mSavedStates.size());
        for (int ix = 0; ix < this.mFragments.size(); ix++) {
            long itemId = this.mFragments.keyAt(ix);
            Fragment fragment = this.mFragments.get(itemId);
            if (fragment != null && fragment.isAdded()) {
                String key = createKey(KEY_PREFIX_FRAGMENT, itemId);
                this.mFragmentManager.putFragment(savedState, key, fragment);
            }
        }
        for (int ix2 = 0; ix2 < this.mSavedStates.size(); ix2++) {
            long itemId2 = this.mSavedStates.keyAt(ix2);
            if (containsItem(itemId2)) {
                String key2 = createKey(KEY_PREFIX_STATE, itemId2);
                savedState.putParcelable(key2, this.mSavedStates.get(itemId2));
            }
        }
        return savedState;
    }

    @Override // androidx.viewpager2.adapter.StatefulAdapter
    public final void restoreState(Parcelable savedState) {
        if (!this.mSavedStates.isEmpty() || !this.mFragments.isEmpty()) {
            throw new IllegalStateException("Expected the adapter to be 'fresh' while restoring state.");
        }
        Bundle bundle = (Bundle) savedState;
        if (bundle.getClassLoader() == null) {
            bundle.setClassLoader(getClass().getClassLoader());
        }
        for (String key : bundle.keySet()) {
            if (isValidKey(key, KEY_PREFIX_FRAGMENT)) {
                long itemId = parseIdFromKey(key, KEY_PREFIX_FRAGMENT);
                Fragment fragment = this.mFragmentManager.getFragment(bundle, key);
                this.mFragments.put(itemId, fragment);
            } else if (isValidKey(key, KEY_PREFIX_STATE)) {
                long itemId2 = parseIdFromKey(key, KEY_PREFIX_STATE);
                Fragment.SavedState state = (Fragment.SavedState) bundle.getParcelable(key);
                if (containsItem(itemId2)) {
                    this.mSavedStates.put(itemId2, state);
                }
            } else {
                throw new IllegalArgumentException("Unexpected key in savedState: " + key);
            }
        }
        if (!this.mFragments.isEmpty()) {
            this.mHasStaleFragments = true;
            this.mIsInGracePeriod = true;
            gcFragments();
            scheduleGracePeriodEnd();
        }
    }

    private void scheduleGracePeriodEnd() {
        final Handler handler = new Handler(Looper.getMainLooper());
        final Runnable runnable = new Runnable() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.4
            @Override // java.lang.Runnable
            public void run() {
                FragmentStateAdapter.this.mIsInGracePeriod = false;
                FragmentStateAdapter.this.gcFragments();
            }
        };
        this.mLifecycle.addObserver(new LifecycleEventObserver() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.5
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                if (event == Lifecycle.Event.ON_DESTROY) {
                    handler.removeCallbacks(runnable);
                    source.getLifecycle().removeObserver(this);
                }
            }
        });
        handler.postDelayed(runnable, GRACE_WINDOW_TIME_MS);
    }

    private static String createKey(String prefix, long id) {
        return prefix + id;
    }

    private static boolean isValidKey(String key, String prefix) {
        return key.startsWith(prefix) && key.length() > prefix.length();
    }

    private static long parseIdFromKey(String key, String prefix) {
        return Long.parseLong(key.substring(prefix.length()));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class FragmentMaxLifecycleEnforcer {
        private RecyclerView.AdapterDataObserver mDataObserver;
        private LifecycleEventObserver mLifecycleObserver;
        private ViewPager2.OnPageChangeCallback mPageChangeCallback;
        private long mPrimaryItemId = -1;
        private ViewPager2 mViewPager;

        FragmentMaxLifecycleEnforcer() {
        }

        void register(RecyclerView recyclerView) {
            this.mViewPager = inferViewPager(recyclerView);
            ViewPager2.OnPageChangeCallback onPageChangeCallback = new ViewPager2.OnPageChangeCallback() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.FragmentMaxLifecycleEnforcer.1
                @Override // androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback
                public void onPageScrollStateChanged(int state) {
                    FragmentMaxLifecycleEnforcer.this.updateFragmentMaxLifecycle(false);
                }

                @Override // androidx.viewpager2.widget.ViewPager2.OnPageChangeCallback
                public void onPageSelected(int position) {
                    FragmentMaxLifecycleEnforcer.this.updateFragmentMaxLifecycle(false);
                }
            };
            this.mPageChangeCallback = onPageChangeCallback;
            this.mViewPager.registerOnPageChangeCallback(onPageChangeCallback);
            DataSetChangeObserver dataSetChangeObserver = new DataSetChangeObserver() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.FragmentMaxLifecycleEnforcer.2
                @Override // androidx.viewpager2.adapter.FragmentStateAdapter.DataSetChangeObserver, androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
                public void onChanged() {
                    FragmentMaxLifecycleEnforcer.this.updateFragmentMaxLifecycle(true);
                }
            };
            this.mDataObserver = dataSetChangeObserver;
            FragmentStateAdapter.this.registerAdapterDataObserver(dataSetChangeObserver);
            this.mLifecycleObserver = new LifecycleEventObserver() { // from class: androidx.viewpager2.adapter.FragmentStateAdapter.FragmentMaxLifecycleEnforcer.3
                @Override // androidx.lifecycle.LifecycleEventObserver
                public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                    FragmentMaxLifecycleEnforcer.this.updateFragmentMaxLifecycle(false);
                }
            };
            FragmentStateAdapter.this.mLifecycle.addObserver(this.mLifecycleObserver);
        }

        void unregister(RecyclerView recyclerView) {
            ViewPager2 viewPager = inferViewPager(recyclerView);
            viewPager.unregisterOnPageChangeCallback(this.mPageChangeCallback);
            FragmentStateAdapter.this.unregisterAdapterDataObserver(this.mDataObserver);
            FragmentStateAdapter.this.mLifecycle.removeObserver(this.mLifecycleObserver);
            this.mViewPager = null;
        }

        void updateFragmentMaxLifecycle(boolean dataSetChanged) {
            int currentItem;
            Fragment currentItemFragment;
            if (FragmentStateAdapter.this.shouldDelayFragmentTransactions() || this.mViewPager.getScrollState() != 0 || FragmentStateAdapter.this.mFragments.isEmpty() || FragmentStateAdapter.this.getItemCount() == 0 || (currentItem = this.mViewPager.getCurrentItem()) >= FragmentStateAdapter.this.getItemCount()) {
                return;
            }
            long currentItemId = FragmentStateAdapter.this.getItemId(currentItem);
            if ((currentItemId == this.mPrimaryItemId && !dataSetChanged) || (currentItemFragment = FragmentStateAdapter.this.mFragments.get(currentItemId)) == null || !currentItemFragment.isAdded()) {
                return;
            }
            this.mPrimaryItemId = currentItemId;
            FragmentTransaction transaction = FragmentStateAdapter.this.mFragmentManager.beginTransaction();
            Fragment toResume = null;
            for (int ix = 0; ix < FragmentStateAdapter.this.mFragments.size(); ix++) {
                long itemId = FragmentStateAdapter.this.mFragments.keyAt(ix);
                Fragment fragment = FragmentStateAdapter.this.mFragments.valueAt(ix);
                if (fragment.isAdded()) {
                    if (itemId != this.mPrimaryItemId) {
                        transaction.setMaxLifecycle(fragment, Lifecycle.State.STARTED);
                    } else {
                        toResume = fragment;
                    }
                    fragment.setMenuVisibility(itemId == this.mPrimaryItemId);
                }
            }
            if (toResume != null) {
                transaction.setMaxLifecycle(toResume, Lifecycle.State.RESUMED);
            }
            if (!transaction.isEmpty()) {
                transaction.commitNow();
            }
        }

        private ViewPager2 inferViewPager(RecyclerView recyclerView) {
            ViewParent parent = recyclerView.getParent();
            if (parent instanceof ViewPager2) {
                return (ViewPager2) parent;
            }
            throw new IllegalStateException("Expected ViewPager2 instance. Got: " + parent);
        }
    }

    /* loaded from: classes.dex */
    private static abstract class DataSetChangeObserver extends RecyclerView.AdapterDataObserver {
        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public abstract void onChanged();

        private DataSetChangeObserver() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public final void onItemRangeChanged(int positionStart, int itemCount) {
            onChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public final void onItemRangeChanged(int positionStart, int itemCount, Object payload) {
            onChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public final void onItemRangeInserted(int positionStart, int itemCount) {
            onChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public final void onItemRangeRemoved(int positionStart, int itemCount) {
            onChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.AdapterDataObserver
        public final void onItemRangeMoved(int fromPosition, int toPosition, int itemCount) {
            onChanged();
        }
    }
}
