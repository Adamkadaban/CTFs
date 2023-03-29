package androidx.concurrent.futures;

import com.google.common.util.concurrent.ListenableFuture;
import java.lang.ref.WeakReference;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
/* loaded from: classes.dex */
public final class CallbackToFutureAdapter {

    /* loaded from: classes.dex */
    public interface Resolver<T> {
        Object attachCompleter(Completer<T> completer) throws Exception;
    }

    private CallbackToFutureAdapter() {
    }

    public static <T> ListenableFuture<T> getFuture(Resolver<T> callback) {
        Completer<T> completer = new Completer<>();
        SafeFuture<T> safeFuture = new SafeFuture<>(completer);
        completer.future = safeFuture;
        completer.tag = callback.getClass();
        try {
            Object tag = callback.attachCompleter(completer);
            if (tag != null) {
                completer.tag = tag;
            }
        } catch (Exception e) {
            safeFuture.setException(e);
        }
        return safeFuture;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class SafeFuture<T> implements ListenableFuture<T> {
        final WeakReference<Completer<T>> completerWeakReference;
        private final AbstractResolvableFuture<T> delegate = new AbstractResolvableFuture<T>() { // from class: androidx.concurrent.futures.CallbackToFutureAdapter.SafeFuture.1
            @Override // androidx.concurrent.futures.AbstractResolvableFuture
            protected String pendingToString() {
                Completer<T> completer = SafeFuture.this.completerWeakReference.get();
                if (completer == null) {
                    return "Completer object has been garbage collected, future will fail soon";
                }
                return "tag=[" + completer.tag + "]";
            }
        };

        SafeFuture(Completer<T> completer) {
            this.completerWeakReference = new WeakReference<>(completer);
        }

        @Override // java.util.concurrent.Future
        public boolean cancel(boolean mayInterruptIfRunning) {
            Completer<T> completer = this.completerWeakReference.get();
            boolean cancelled = this.delegate.cancel(mayInterruptIfRunning);
            if (cancelled && completer != null) {
                completer.fireCancellationListeners();
            }
            return cancelled;
        }

        boolean cancelWithoutNotifyingCompleter(boolean shouldInterrupt) {
            return this.delegate.cancel(shouldInterrupt);
        }

        boolean set(T value) {
            return this.delegate.set(value);
        }

        boolean setException(Throwable t) {
            return this.delegate.setException(t);
        }

        @Override // java.util.concurrent.Future
        public boolean isCancelled() {
            return this.delegate.isCancelled();
        }

        @Override // java.util.concurrent.Future
        public boolean isDone() {
            return this.delegate.isDone();
        }

        @Override // java.util.concurrent.Future
        public T get() throws InterruptedException, ExecutionException {
            return this.delegate.get();
        }

        @Override // java.util.concurrent.Future
        public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return this.delegate.get(timeout, unit);
        }

        @Override // com.google.common.util.concurrent.ListenableFuture
        public void addListener(Runnable listener, Executor executor) {
            this.delegate.addListener(listener, executor);
        }

        public String toString() {
            return this.delegate.toString();
        }
    }

    /* loaded from: classes.dex */
    public static final class Completer<T> {
        private boolean attemptedSetting;
        private ResolvableFuture<Void> cancellationFuture = ResolvableFuture.create();
        SafeFuture<T> future;
        Object tag;

        Completer() {
        }

        public boolean set(T value) {
            boolean wasSet = true;
            this.attemptedSetting = true;
            SafeFuture<T> localFuture = this.future;
            wasSet = (localFuture == null || !localFuture.set(value)) ? false : false;
            if (wasSet) {
                setCompletedNormally();
            }
            return wasSet;
        }

        public boolean setException(Throwable t) {
            boolean wasSet = true;
            this.attemptedSetting = true;
            SafeFuture<T> localFuture = this.future;
            wasSet = (localFuture == null || !localFuture.setException(t)) ? false : false;
            if (wasSet) {
                setCompletedNormally();
            }
            return wasSet;
        }

        public boolean setCancelled() {
            boolean wasSet = true;
            this.attemptedSetting = true;
            SafeFuture<T> localFuture = this.future;
            wasSet = (localFuture == null || !localFuture.cancelWithoutNotifyingCompleter(true)) ? false : false;
            if (wasSet) {
                setCompletedNormally();
            }
            return wasSet;
        }

        public void addCancellationListener(Runnable runnable, Executor executor) {
            ListenableFuture<?> localCancellationFuture = this.cancellationFuture;
            if (localCancellationFuture != null) {
                localCancellationFuture.addListener(runnable, executor);
            }
        }

        void fireCancellationListeners() {
            this.tag = null;
            this.future = null;
            this.cancellationFuture.set(null);
        }

        private void setCompletedNormally() {
            this.tag = null;
            this.future = null;
            this.cancellationFuture = null;
        }

        protected void finalize() {
            ResolvableFuture<Void> localCancellationFuture;
            SafeFuture<T> localFuture = this.future;
            if (localFuture != null && !localFuture.isDone()) {
                localFuture.setException(new FutureGarbageCollectedException("The completer object was garbage collected - this future would otherwise never complete. The tag was: " + this.tag));
            }
            if (!this.attemptedSetting && (localCancellationFuture = this.cancellationFuture) != null) {
                localCancellationFuture.set(null);
            }
        }
    }

    /* loaded from: classes.dex */
    static final class FutureGarbageCollectedException extends Throwable {
        FutureGarbageCollectedException(String message) {
            super(message);
        }

        @Override // java.lang.Throwable
        public synchronized Throwable fillInStackTrace() {
            return this;
        }
    }
}
