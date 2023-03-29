package androidx.loader.app;

import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import androidx.collection.SparseArrayCompat;
import androidx.core.util.DebugUtils;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.loader.app.LoaderManager;
import androidx.loader.content.Loader;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class LoaderManagerImpl extends LoaderManager {
    static boolean DEBUG = false;
    static final String TAG = "LoaderManager";
    private final LifecycleOwner mLifecycleOwner;
    private final LoaderViewModel mLoaderViewModel;

    /* loaded from: classes.dex */
    public static class LoaderInfo<D> extends MutableLiveData<D> implements Loader.OnLoadCompleteListener<D> {
        private final Bundle mArgs;
        private final int mId;
        private LifecycleOwner mLifecycleOwner;
        private final Loader<D> mLoader;
        private LoaderObserver<D> mObserver;
        private Loader<D> mPriorLoader;

        LoaderInfo(int id, Bundle args, Loader<D> loader, Loader<D> priorLoader) {
            this.mId = id;
            this.mArgs = args;
            this.mLoader = loader;
            this.mPriorLoader = priorLoader;
            loader.registerListener(id, this);
        }

        Loader<D> getLoader() {
            return this.mLoader;
        }

        @Override // androidx.lifecycle.LiveData
        protected void onActive() {
            if (LoaderManagerImpl.DEBUG) {
                Log.v(LoaderManagerImpl.TAG, "  Starting: " + this);
            }
            this.mLoader.startLoading();
        }

        @Override // androidx.lifecycle.LiveData
        protected void onInactive() {
            if (LoaderManagerImpl.DEBUG) {
                Log.v(LoaderManagerImpl.TAG, "  Stopping: " + this);
            }
            this.mLoader.stopLoading();
        }

        Loader<D> setCallback(LifecycleOwner owner, LoaderManager.LoaderCallbacks<D> callback) {
            LoaderObserver<D> observer = new LoaderObserver<>(this.mLoader, callback);
            observe(owner, observer);
            LoaderObserver<D> loaderObserver = this.mObserver;
            if (loaderObserver != null) {
                removeObserver(loaderObserver);
            }
            this.mLifecycleOwner = owner;
            this.mObserver = observer;
            return this.mLoader;
        }

        void markForRedelivery() {
            LifecycleOwner lifecycleOwner = this.mLifecycleOwner;
            LoaderObserver<D> observer = this.mObserver;
            if (lifecycleOwner != null && observer != null) {
                super.removeObserver(observer);
                observe(lifecycleOwner, observer);
            }
        }

        boolean isCallbackWaitingForData() {
            LoaderObserver<D> loaderObserver;
            return (!hasActiveObservers() || (loaderObserver = this.mObserver) == null || loaderObserver.hasDeliveredData()) ? false : true;
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // androidx.lifecycle.LiveData
        public void removeObserver(Observer<? super D> observer) {
            super.removeObserver(observer);
            this.mLifecycleOwner = null;
            this.mObserver = null;
        }

        Loader<D> destroy(boolean reset) {
            if (LoaderManagerImpl.DEBUG) {
                Log.v(LoaderManagerImpl.TAG, "  Destroying: " + this);
            }
            this.mLoader.cancelLoad();
            this.mLoader.abandon();
            LoaderObserver<D> observer = this.mObserver;
            if (observer != null) {
                removeObserver(observer);
                if (reset) {
                    observer.reset();
                }
            }
            this.mLoader.unregisterListener(this);
            if ((observer != null && !observer.hasDeliveredData()) || reset) {
                this.mLoader.reset();
                return this.mPriorLoader;
            }
            return this.mLoader;
        }

        @Override // androidx.loader.content.Loader.OnLoadCompleteListener
        public void onLoadComplete(Loader<D> loader, D data) {
            if (LoaderManagerImpl.DEBUG) {
                Log.v(LoaderManagerImpl.TAG, "onLoadComplete: " + this);
            }
            if (Looper.myLooper() == Looper.getMainLooper()) {
                setValue(data);
                return;
            }
            if (LoaderManagerImpl.DEBUG) {
                Log.w(LoaderManagerImpl.TAG, "onLoadComplete was incorrectly called on a background thread");
            }
            postValue(data);
        }

        @Override // androidx.lifecycle.MutableLiveData, androidx.lifecycle.LiveData
        public void setValue(D value) {
            super.setValue(value);
            Loader<D> loader = this.mPriorLoader;
            if (loader != null) {
                loader.reset();
                this.mPriorLoader = null;
            }
        }

        public String toString() {
            StringBuilder sb = new StringBuilder(64);
            sb.append("LoaderInfo{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" #");
            sb.append(this.mId);
            sb.append(" : ");
            DebugUtils.buildShortClassTag(this.mLoader, sb);
            sb.append("}}");
            return sb.toString();
        }

        public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
            writer.print(prefix);
            writer.print("mId=");
            writer.print(this.mId);
            writer.print(" mArgs=");
            writer.println(this.mArgs);
            writer.print(prefix);
            writer.print("mLoader=");
            writer.println(this.mLoader);
            Loader<D> loader = this.mLoader;
            loader.dump(prefix + "  ", fd, writer, args);
            if (this.mObserver != null) {
                writer.print(prefix);
                writer.print("mCallbacks=");
                writer.println(this.mObserver);
                LoaderObserver<D> loaderObserver = this.mObserver;
                loaderObserver.dump(prefix + "  ", writer);
            }
            writer.print(prefix);
            writer.print("mData=");
            writer.println(getLoader().dataToString(getValue()));
            writer.print(prefix);
            writer.print("mStarted=");
            writer.println(hasActiveObservers());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class LoaderObserver<D> implements Observer<D> {
        private final LoaderManager.LoaderCallbacks<D> mCallback;
        private boolean mDeliveredData = false;
        private final Loader<D> mLoader;

        LoaderObserver(Loader<D> loader, LoaderManager.LoaderCallbacks<D> callback) {
            this.mLoader = loader;
            this.mCallback = callback;
        }

        @Override // androidx.lifecycle.Observer
        public void onChanged(D data) {
            if (LoaderManagerImpl.DEBUG) {
                Log.v(LoaderManagerImpl.TAG, "  onLoadFinished in " + this.mLoader + ": " + this.mLoader.dataToString(data));
            }
            this.mCallback.onLoadFinished(this.mLoader, data);
            this.mDeliveredData = true;
        }

        boolean hasDeliveredData() {
            return this.mDeliveredData;
        }

        void reset() {
            if (this.mDeliveredData) {
                if (LoaderManagerImpl.DEBUG) {
                    Log.v(LoaderManagerImpl.TAG, "  Resetting: " + this.mLoader);
                }
                this.mCallback.onLoaderReset(this.mLoader);
            }
        }

        public String toString() {
            return this.mCallback.toString();
        }

        public void dump(String prefix, PrintWriter writer) {
            writer.print(prefix);
            writer.print("mDeliveredData=");
            writer.println(this.mDeliveredData);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class LoaderViewModel extends ViewModel {
        private static final ViewModelProvider.Factory FACTORY = new ViewModelProvider.Factory() { // from class: androidx.loader.app.LoaderManagerImpl.LoaderViewModel.1
            @Override // androidx.lifecycle.ViewModelProvider.Factory
            public <T extends ViewModel> T create(Class<T> modelClass) {
                return new LoaderViewModel();
            }
        };
        private SparseArrayCompat<LoaderInfo> mLoaders = new SparseArrayCompat<>();
        private boolean mCreatingLoader = false;

        LoaderViewModel() {
        }

        static LoaderViewModel getInstance(ViewModelStore viewModelStore) {
            return (LoaderViewModel) new ViewModelProvider(viewModelStore, FACTORY).get(LoaderViewModel.class);
        }

        void startCreatingLoader() {
            this.mCreatingLoader = true;
        }

        boolean isCreatingLoader() {
            return this.mCreatingLoader;
        }

        void finishCreatingLoader() {
            this.mCreatingLoader = false;
        }

        void putLoader(int id, LoaderInfo info) {
            this.mLoaders.put(id, info);
        }

        <D> LoaderInfo<D> getLoader(int id) {
            return this.mLoaders.get(id);
        }

        void removeLoader(int id) {
            this.mLoaders.remove(id);
        }

        boolean hasRunningLoaders() {
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                LoaderInfo info = this.mLoaders.valueAt(index);
                if (info.isCallbackWaitingForData()) {
                    return true;
                }
            }
            return false;
        }

        void markForRedelivery() {
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                LoaderInfo info = this.mLoaders.valueAt(index);
                info.markForRedelivery();
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // androidx.lifecycle.ViewModel
        public void onCleared() {
            super.onCleared();
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                LoaderInfo info = this.mLoaders.valueAt(index);
                info.destroy(true);
            }
            this.mLoaders.clear();
        }

        public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
            if (this.mLoaders.size() > 0) {
                writer.print(prefix);
                writer.println("Loaders:");
                String innerPrefix = prefix + "    ";
                for (int i = 0; i < this.mLoaders.size(); i++) {
                    LoaderInfo info = this.mLoaders.valueAt(i);
                    writer.print(prefix);
                    writer.print("  #");
                    writer.print(this.mLoaders.keyAt(i));
                    writer.print(": ");
                    writer.println(info.toString());
                    info.dump(innerPrefix, fd, writer, args);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LoaderManagerImpl(LifecycleOwner lifecycleOwner, ViewModelStore viewModelStore) {
        this.mLifecycleOwner = lifecycleOwner;
        this.mLoaderViewModel = LoaderViewModel.getInstance(viewModelStore);
    }

    private <D> Loader<D> createAndInstallLoader(int id, Bundle args, LoaderManager.LoaderCallbacks<D> callback, Loader<D> priorLoader) {
        try {
            this.mLoaderViewModel.startCreatingLoader();
            Loader<D> loader = callback.onCreateLoader(id, args);
            if (loader == null) {
                throw new IllegalArgumentException("Object returned from onCreateLoader must not be null");
            }
            if (loader.getClass().isMemberClass() && !Modifier.isStatic(loader.getClass().getModifiers())) {
                throw new IllegalArgumentException("Object returned from onCreateLoader must not be a non-static inner member class: " + loader);
            }
            LoaderInfo<D> info = new LoaderInfo<>(id, args, loader, priorLoader);
            try {
                if (DEBUG) {
                    Log.v(TAG, "  Created new loader " + info);
                }
                this.mLoaderViewModel.putLoader(id, info);
                this.mLoaderViewModel.finishCreatingLoader();
                return info.setCallback(this.mLifecycleOwner, callback);
            } catch (Throwable th) {
                th = th;
                this.mLoaderViewModel.finishCreatingLoader();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    @Override // androidx.loader.app.LoaderManager
    public <D> Loader<D> initLoader(int id, Bundle args, LoaderManager.LoaderCallbacks<D> callback) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        }
        if (Looper.getMainLooper() != Looper.myLooper()) {
            throw new IllegalStateException("initLoader must be called on the main thread");
        }
        LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
        if (DEBUG) {
            Log.v(TAG, "initLoader in " + this + ": args=" + args);
        }
        if (info == null) {
            return createAndInstallLoader(id, args, callback, null);
        }
        if (DEBUG) {
            Log.v(TAG, "  Re-using existing loader " + info);
        }
        return info.setCallback(this.mLifecycleOwner, callback);
    }

    @Override // androidx.loader.app.LoaderManager
    public <D> Loader<D> restartLoader(int id, Bundle args, LoaderManager.LoaderCallbacks<D> callback) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        }
        if (Looper.getMainLooper() != Looper.myLooper()) {
            throw new IllegalStateException("restartLoader must be called on the main thread");
        }
        if (DEBUG) {
            Log.v(TAG, "restartLoader in " + this + ": args=" + args);
        }
        LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
        Loader<D> priorLoader = null;
        if (info != null) {
            priorLoader = info.destroy(false);
        }
        return createAndInstallLoader(id, args, callback, priorLoader);
    }

    @Override // androidx.loader.app.LoaderManager
    public void destroyLoader(int id) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        }
        if (Looper.getMainLooper() != Looper.myLooper()) {
            throw new IllegalStateException("destroyLoader must be called on the main thread");
        }
        if (DEBUG) {
            Log.v(TAG, "destroyLoader in " + this + " of " + id);
        }
        LoaderInfo info = this.mLoaderViewModel.getLoader(id);
        if (info != null) {
            info.destroy(true);
            this.mLoaderViewModel.removeLoader(id);
        }
    }

    @Override // androidx.loader.app.LoaderManager
    public <D> Loader<D> getLoader(int id) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        }
        LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
        if (info != null) {
            return info.getLoader();
        }
        return null;
    }

    @Override // androidx.loader.app.LoaderManager
    public void markForRedelivery() {
        this.mLoaderViewModel.markForRedelivery();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("LoaderManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        DebugUtils.buildShortClassTag(this.mLifecycleOwner, sb);
        sb.append("}}");
        return sb.toString();
    }

    @Override // androidx.loader.app.LoaderManager
    @Deprecated
    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        this.mLoaderViewModel.dump(prefix, fd, writer, args);
    }

    @Override // androidx.loader.app.LoaderManager
    public boolean hasRunningLoaders() {
        return this.mLoaderViewModel.hasRunningLoaders();
    }
}
