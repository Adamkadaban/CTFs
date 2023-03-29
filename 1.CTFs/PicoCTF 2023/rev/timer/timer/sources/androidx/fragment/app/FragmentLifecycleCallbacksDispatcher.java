package androidx.fragment.app;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.FragmentManager;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class FragmentLifecycleCallbacksDispatcher {
    private final FragmentManager mFragmentManager;
    private final CopyOnWriteArrayList<FragmentLifecycleCallbacksHolder> mLifecycleCallbacks = new CopyOnWriteArrayList<>();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class FragmentLifecycleCallbacksHolder {
        final FragmentManager.FragmentLifecycleCallbacks mCallback;
        final boolean mRecursive;

        FragmentLifecycleCallbacksHolder(FragmentManager.FragmentLifecycleCallbacks callback, boolean recursive) {
            this.mCallback = callback;
            this.mRecursive = recursive;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public FragmentLifecycleCallbacksDispatcher(FragmentManager fragmentManager) {
        this.mFragmentManager = fragmentManager;
    }

    public void registerFragmentLifecycleCallbacks(FragmentManager.FragmentLifecycleCallbacks cb, boolean recursive) {
        this.mLifecycleCallbacks.add(new FragmentLifecycleCallbacksHolder(cb, recursive));
    }

    public void unregisterFragmentLifecycleCallbacks(FragmentManager.FragmentLifecycleCallbacks cb) {
        synchronized (this.mLifecycleCallbacks) {
            int i = 0;
            int count = this.mLifecycleCallbacks.size();
            while (true) {
                if (i >= count) {
                    break;
                } else if (this.mLifecycleCallbacks.get(i).mCallback != cb) {
                    i++;
                } else {
                    this.mLifecycleCallbacks.remove(i);
                    break;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentPreAttached(Fragment f, boolean onlyRecursive) {
        Context context = this.mFragmentManager.getHost().getContext();
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentPreAttached(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentPreAttached(this.mFragmentManager, f, context);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentAttached(Fragment f, boolean onlyRecursive) {
        Context context = this.mFragmentManager.getHost().getContext();
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentAttached(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentAttached(this.mFragmentManager, f, context);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentPreCreated(Fragment f, Bundle savedInstanceState, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentPreCreated(f, savedInstanceState, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentPreCreated(this.mFragmentManager, f, savedInstanceState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentCreated(Fragment f, Bundle savedInstanceState, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentCreated(f, savedInstanceState, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentCreated(this.mFragmentManager, f, savedInstanceState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentActivityCreated(Fragment f, Bundle savedInstanceState, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentActivityCreated(f, savedInstanceState, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentActivityCreated(this.mFragmentManager, f, savedInstanceState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentViewCreated(Fragment f, View v, Bundle savedInstanceState, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentViewCreated(f, v, savedInstanceState, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentViewCreated(this.mFragmentManager, f, v, savedInstanceState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentStarted(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentStarted(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentStarted(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentResumed(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentResumed(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentResumed(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentPaused(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentPaused(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentPaused(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentStopped(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentStopped(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentStopped(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentSaveInstanceState(Fragment f, Bundle outState, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentSaveInstanceState(f, outState, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentSaveInstanceState(this.mFragmentManager, f, outState);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentViewDestroyed(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentViewDestroyed(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentViewDestroyed(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentDestroyed(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentDestroyed(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentDestroyed(this.mFragmentManager, f);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void dispatchOnFragmentDetached(Fragment f, boolean onlyRecursive) {
        Fragment parent = this.mFragmentManager.getParent();
        if (parent != null) {
            FragmentManager parentManager = parent.getParentFragmentManager();
            parentManager.getLifecycleCallbacksDispatcher().dispatchOnFragmentDetached(f, true);
        }
        Iterator<FragmentLifecycleCallbacksHolder> it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder holder = it.next();
            if (!onlyRecursive || holder.mRecursive) {
                holder.mCallback.onFragmentDetached(this.mFragmentManager, f);
            }
        }
    }
}
