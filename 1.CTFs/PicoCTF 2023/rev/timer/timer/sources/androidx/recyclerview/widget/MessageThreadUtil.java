package androidx.recyclerview.widget;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.recyclerview.widget.ThreadUtil;
import androidx.recyclerview.widget.TileList;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
/* loaded from: classes.dex */
class MessageThreadUtil<T> implements ThreadUtil<T> {

    /* renamed from: androidx.recyclerview.widget.MessageThreadUtil$1  reason: invalid class name */
    /* loaded from: classes.dex */
    class AnonymousClass1 implements ThreadUtil.MainThreadCallback<T> {
        static final int ADD_TILE = 2;
        static final int REMOVE_TILE = 3;
        static final int UPDATE_ITEM_COUNT = 1;
        final /* synthetic */ ThreadUtil.MainThreadCallback val$callback;
        final MessageQueue mQueue = new MessageQueue();
        private final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
        private Runnable mMainThreadRunnable = new Runnable() { // from class: androidx.recyclerview.widget.MessageThreadUtil.1.1
            @Override // java.lang.Runnable
            public void run() {
                SyncQueueItem msg = AnonymousClass1.this.mQueue.next();
                while (msg != null) {
                    switch (msg.what) {
                        case 1:
                            AnonymousClass1.this.val$callback.updateItemCount(msg.arg1, msg.arg2);
                            break;
                        case 2:
                            TileList.Tile<T> tile = (TileList.Tile) msg.data;
                            AnonymousClass1.this.val$callback.addTile(msg.arg1, tile);
                            break;
                        case 3:
                            AnonymousClass1.this.val$callback.removeTile(msg.arg1, msg.arg2);
                            break;
                        default:
                            Log.e("ThreadUtil", "Unsupported message, what=" + msg.what);
                            break;
                    }
                    msg = AnonymousClass1.this.mQueue.next();
                }
            }
        };

        AnonymousClass1(ThreadUtil.MainThreadCallback mainThreadCallback) {
            this.val$callback = mainThreadCallback;
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
        public void updateItemCount(int generation, int itemCount) {
            sendMessage(SyncQueueItem.obtainMessage(1, generation, itemCount));
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
        public void addTile(int generation, TileList.Tile<T> tile) {
            sendMessage(SyncQueueItem.obtainMessage(2, generation, tile));
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.MainThreadCallback
        public void removeTile(int generation, int position) {
            sendMessage(SyncQueueItem.obtainMessage(3, generation, position));
        }

        private void sendMessage(SyncQueueItem msg) {
            this.mQueue.sendMessage(msg);
            this.mMainThreadHandler.post(this.mMainThreadRunnable);
        }
    }

    @Override // androidx.recyclerview.widget.ThreadUtil
    public ThreadUtil.MainThreadCallback<T> getMainThreadProxy(ThreadUtil.MainThreadCallback<T> callback) {
        return new AnonymousClass1(callback);
    }

    /* renamed from: androidx.recyclerview.widget.MessageThreadUtil$2  reason: invalid class name */
    /* loaded from: classes.dex */
    class AnonymousClass2 implements ThreadUtil.BackgroundCallback<T> {
        static final int LOAD_TILE = 3;
        static final int RECYCLE_TILE = 4;
        static final int REFRESH = 1;
        static final int UPDATE_RANGE = 2;
        final /* synthetic */ ThreadUtil.BackgroundCallback val$callback;
        final MessageQueue mQueue = new MessageQueue();
        private final Executor mExecutor = AsyncTask.THREAD_POOL_EXECUTOR;
        AtomicBoolean mBackgroundRunning = new AtomicBoolean(false);
        private Runnable mBackgroundRunnable = new Runnable() { // from class: androidx.recyclerview.widget.MessageThreadUtil.2.1
            @Override // java.lang.Runnable
            public void run() {
                while (true) {
                    SyncQueueItem msg = AnonymousClass2.this.mQueue.next();
                    if (msg != null) {
                        switch (msg.what) {
                            case 1:
                                AnonymousClass2.this.mQueue.removeMessages(1);
                                AnonymousClass2.this.val$callback.refresh(msg.arg1);
                                break;
                            case 2:
                                AnonymousClass2.this.mQueue.removeMessages(2);
                                AnonymousClass2.this.mQueue.removeMessages(3);
                                AnonymousClass2.this.val$callback.updateRange(msg.arg1, msg.arg2, msg.arg3, msg.arg4, msg.arg5);
                                break;
                            case 3:
                                AnonymousClass2.this.val$callback.loadTile(msg.arg1, msg.arg2);
                                break;
                            case 4:
                                TileList.Tile<T> tile = (TileList.Tile) msg.data;
                                AnonymousClass2.this.val$callback.recycleTile(tile);
                                break;
                            default:
                                Log.e("ThreadUtil", "Unsupported message, what=" + msg.what);
                                break;
                        }
                    } else {
                        AnonymousClass2.this.mBackgroundRunning.set(false);
                        return;
                    }
                }
            }
        };

        AnonymousClass2(ThreadUtil.BackgroundCallback backgroundCallback) {
            this.val$callback = backgroundCallback;
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
        public void refresh(int generation) {
            sendMessageAtFrontOfQueue(SyncQueueItem.obtainMessage(1, generation, (Object) null));
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
        public void updateRange(int rangeStart, int rangeEnd, int extRangeStart, int extRangeEnd, int scrollHint) {
            sendMessageAtFrontOfQueue(SyncQueueItem.obtainMessage(2, rangeStart, rangeEnd, extRangeStart, extRangeEnd, scrollHint, null));
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
        public void loadTile(int position, int scrollHint) {
            sendMessage(SyncQueueItem.obtainMessage(3, position, scrollHint));
        }

        @Override // androidx.recyclerview.widget.ThreadUtil.BackgroundCallback
        public void recycleTile(TileList.Tile<T> tile) {
            sendMessage(SyncQueueItem.obtainMessage(4, 0, tile));
        }

        private void sendMessage(SyncQueueItem msg) {
            this.mQueue.sendMessage(msg);
            maybeExecuteBackgroundRunnable();
        }

        private void sendMessageAtFrontOfQueue(SyncQueueItem msg) {
            this.mQueue.sendMessageAtFrontOfQueue(msg);
            maybeExecuteBackgroundRunnable();
        }

        private void maybeExecuteBackgroundRunnable() {
            if (this.mBackgroundRunning.compareAndSet(false, true)) {
                this.mExecutor.execute(this.mBackgroundRunnable);
            }
        }
    }

    @Override // androidx.recyclerview.widget.ThreadUtil
    public ThreadUtil.BackgroundCallback<T> getBackgroundProxy(ThreadUtil.BackgroundCallback<T> callback) {
        return new AnonymousClass2(callback);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class SyncQueueItem {
        private static SyncQueueItem sPool;
        private static final Object sPoolLock = new Object();
        public int arg1;
        public int arg2;
        public int arg3;
        public int arg4;
        public int arg5;
        public Object data;
        SyncQueueItem next;
        public int what;

        SyncQueueItem() {
        }

        void recycle() {
            this.next = null;
            this.arg5 = 0;
            this.arg4 = 0;
            this.arg3 = 0;
            this.arg2 = 0;
            this.arg1 = 0;
            this.what = 0;
            this.data = null;
            synchronized (sPoolLock) {
                SyncQueueItem syncQueueItem = sPool;
                if (syncQueueItem != null) {
                    this.next = syncQueueItem;
                }
                sPool = this;
            }
        }

        static SyncQueueItem obtainMessage(int what, int arg1, int arg2, int arg3, int arg4, int arg5, Object data) {
            SyncQueueItem item;
            synchronized (sPoolLock) {
                SyncQueueItem item2 = sPool;
                if (item2 == null) {
                    item = new SyncQueueItem();
                } else {
                    sPool = item2.next;
                    item2.next = null;
                    item = item2;
                }
                item.what = what;
                item.arg1 = arg1;
                item.arg2 = arg2;
                item.arg3 = arg3;
                item.arg4 = arg4;
                item.arg5 = arg5;
                item.data = data;
            }
            return item;
        }

        static SyncQueueItem obtainMessage(int what, int arg1, int arg2) {
            return obtainMessage(what, arg1, arg2, 0, 0, 0, null);
        }

        static SyncQueueItem obtainMessage(int what, int arg1, Object data) {
            return obtainMessage(what, arg1, 0, 0, 0, 0, data);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class MessageQueue {
        private SyncQueueItem mRoot;

        MessageQueue() {
        }

        synchronized SyncQueueItem next() {
            SyncQueueItem next = this.mRoot;
            if (next == null) {
                return null;
            }
            this.mRoot = next.next;
            return next;
        }

        synchronized void sendMessageAtFrontOfQueue(SyncQueueItem item) {
            item.next = this.mRoot;
            this.mRoot = item;
        }

        synchronized void sendMessage(SyncQueueItem item) {
            SyncQueueItem last = this.mRoot;
            if (last == null) {
                this.mRoot = item;
                return;
            }
            while (last.next != null) {
                last = last.next;
            }
            last.next = item;
        }

        synchronized void removeMessages(int what) {
            while (true) {
                SyncQueueItem syncQueueItem = this.mRoot;
                if (syncQueueItem == null || syncQueueItem.what != what) {
                    break;
                }
                SyncQueueItem item = this.mRoot;
                this.mRoot = item.next;
                item.recycle();
            }
            SyncQueueItem prev = this.mRoot;
            if (prev != null) {
                SyncQueueItem item2 = prev.next;
                while (item2 != null) {
                    SyncQueueItem next = item2.next;
                    if (item2.what == what) {
                        prev.next = next;
                        item2.recycle();
                    } else {
                        prev = item2;
                    }
                    item2 = next;
                }
            }
        }
    }
}
