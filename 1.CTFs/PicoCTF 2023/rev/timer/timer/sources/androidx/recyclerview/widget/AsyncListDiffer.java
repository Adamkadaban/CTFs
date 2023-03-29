package androidx.recyclerview.widget;

import android.os.Handler;
import android.os.Looper;
import androidx.recyclerview.widget.AsyncDifferConfig;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.RecyclerView;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
/* loaded from: classes.dex */
public class AsyncListDiffer<T> {
    private static final Executor sMainThreadExecutor = new MainThreadExecutor();
    final AsyncDifferConfig<T> mConfig;
    private List<T> mList;
    private final List<ListListener<T>> mListeners;
    Executor mMainThreadExecutor;
    int mMaxScheduledGeneration;
    private List<T> mReadOnlyList;
    private final ListUpdateCallback mUpdateCallback;

    /* loaded from: classes.dex */
    public interface ListListener<T> {
        void onCurrentListChanged(List<T> list, List<T> list2);
    }

    /* loaded from: classes.dex */
    private static class MainThreadExecutor implements Executor {
        final Handler mHandler = new Handler(Looper.getMainLooper());

        MainThreadExecutor() {
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable command) {
            this.mHandler.post(command);
        }
    }

    public AsyncListDiffer(RecyclerView.Adapter adapter, DiffUtil.ItemCallback<T> diffCallback) {
        this(new AdapterListUpdateCallback(adapter), new AsyncDifferConfig.Builder(diffCallback).build());
    }

    public AsyncListDiffer(ListUpdateCallback listUpdateCallback, AsyncDifferConfig<T> config) {
        this.mListeners = new CopyOnWriteArrayList();
        this.mReadOnlyList = Collections.emptyList();
        this.mUpdateCallback = listUpdateCallback;
        this.mConfig = config;
        if (config.getMainThreadExecutor() != null) {
            this.mMainThreadExecutor = config.getMainThreadExecutor();
        } else {
            this.mMainThreadExecutor = sMainThreadExecutor;
        }
    }

    public List<T> getCurrentList() {
        return this.mReadOnlyList;
    }

    public void submitList(List<T> newList) {
        submitList(newList, null);
    }

    public void submitList(final List<T> newList, final Runnable commitCallback) {
        final int runGeneration = this.mMaxScheduledGeneration + 1;
        this.mMaxScheduledGeneration = runGeneration;
        List<T> list = this.mList;
        if (newList == list) {
            if (commitCallback != null) {
                commitCallback.run();
                return;
            }
            return;
        }
        List<T> previousList = this.mReadOnlyList;
        if (newList == null) {
            int countRemoved = list.size();
            this.mList = null;
            this.mReadOnlyList = Collections.emptyList();
            this.mUpdateCallback.onRemoved(0, countRemoved);
            onCurrentListChanged(previousList, commitCallback);
        } else if (list == null) {
            this.mList = newList;
            this.mReadOnlyList = Collections.unmodifiableList(newList);
            this.mUpdateCallback.onInserted(0, newList.size());
            onCurrentListChanged(previousList, commitCallback);
        } else {
            final List<T> oldList = this.mList;
            this.mConfig.getBackgroundThreadExecutor().execute(new Runnable() { // from class: androidx.recyclerview.widget.AsyncListDiffer.1
                @Override // java.lang.Runnable
                public void run() {
                    final DiffUtil.DiffResult result = DiffUtil.calculateDiff(new DiffUtil.Callback() { // from class: androidx.recyclerview.widget.AsyncListDiffer.1.1
                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public int getOldListSize() {
                            return oldList.size();
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public int getNewListSize() {
                            return newList.size();
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public boolean areItemsTheSame(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = newList.get(newItemPosition);
                            if (obj == null || obj2 == null) {
                                return obj == null && obj2 == null;
                            }
                            return AsyncListDiffer.this.mConfig.getDiffCallback().areItemsTheSame(obj, obj2);
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = newList.get(newItemPosition);
                            if (obj != null && obj2 != null) {
                                return AsyncListDiffer.this.mConfig.getDiffCallback().areContentsTheSame(obj, obj2);
                            }
                            if (obj == null && obj2 == null) {
                                return true;
                            }
                            throw new AssertionError();
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public Object getChangePayload(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = newList.get(newItemPosition);
                            if (obj != null && obj2 != null) {
                                return AsyncListDiffer.this.mConfig.getDiffCallback().getChangePayload(obj, obj2);
                            }
                            throw new AssertionError();
                        }
                    });
                    AsyncListDiffer.this.mMainThreadExecutor.execute(new Runnable() { // from class: androidx.recyclerview.widget.AsyncListDiffer.1.2
                        @Override // java.lang.Runnable
                        public void run() {
                            if (AsyncListDiffer.this.mMaxScheduledGeneration == runGeneration) {
                                AsyncListDiffer.this.latchList(newList, result, commitCallback);
                            }
                        }
                    });
                }
            });
        }
    }

    void latchList(List<T> newList, DiffUtil.DiffResult diffResult, Runnable commitCallback) {
        List<T> previousList = this.mReadOnlyList;
        this.mList = newList;
        this.mReadOnlyList = Collections.unmodifiableList(newList);
        diffResult.dispatchUpdatesTo(this.mUpdateCallback);
        onCurrentListChanged(previousList, commitCallback);
    }

    private void onCurrentListChanged(List<T> previousList, Runnable commitCallback) {
        for (ListListener<T> listener : this.mListeners) {
            listener.onCurrentListChanged(previousList, this.mReadOnlyList);
        }
        if (commitCallback != null) {
            commitCallback.run();
        }
    }

    public void addListListener(ListListener<T> listener) {
        this.mListeners.add(listener);
    }

    public void removeListListener(ListListener<T> listener) {
        this.mListeners.remove(listener);
    }
}
