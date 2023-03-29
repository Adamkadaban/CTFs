package androidx.core.location;

import android.content.Context;
import android.location.GnssStatus;
import android.location.GpsStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.location.LocationRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.TextUtils;
import androidx.collection.SimpleArrayMap;
import androidx.core.location.GnssStatusCompat;
import androidx.core.location.LocationManagerCompat;
import androidx.core.os.CancellationSignal;
import androidx.core.os.ExecutorCompat;
import androidx.core.util.Consumer;
import androidx.core.util.ObjectsCompat;
import androidx.core.util.Preconditions;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
/* loaded from: classes.dex */
public final class LocationManagerCompat {
    private static final long GET_CURRENT_LOCATION_TIMEOUT_MS = 30000;
    private static final long MAX_CURRENT_LOCATION_AGE_MS = 10000;
    private static final long PRE_N_LOOPER_TIMEOUT_S = 5;
    private static Field sContextField;
    static final WeakHashMap<LocationListener, List<WeakReference<LocationListenerTransport>>> sLocationListeners = new WeakHashMap<>();
    private static Method sRequestLocationUpdatesExecutorMethod;
    private static Method sRequestLocationUpdatesLooperMethod;

    public static boolean isLocationEnabled(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.isLocationEnabled(locationManager);
        }
        if (Build.VERSION.SDK_INT <= 19) {
            try {
                if (sContextField == null) {
                    Field declaredField = LocationManager.class.getDeclaredField("mContext");
                    sContextField = declaredField;
                    declaredField.setAccessible(true);
                }
                Context context = (Context) sContextField.get(locationManager);
                if (context != null) {
                    if (Build.VERSION.SDK_INT == 19) {
                        return Settings.Secure.getInt(context.getContentResolver(), "location_mode", 0) != 0;
                    }
                    return !TextUtils.isEmpty(Settings.Secure.getString(context.getContentResolver(), "location_providers_allowed"));
                }
            } catch (ClassCastException e) {
            } catch (IllegalAccessException e2) {
            } catch (NoSuchFieldException e3) {
            } catch (SecurityException e4) {
            }
        }
        return locationManager.isProviderEnabled("network") || locationManager.isProviderEnabled("gps");
    }

    public static boolean hasProvider(LocationManager locationManager, String provider) {
        if (Build.VERSION.SDK_INT >= 31) {
            return Api31Impl.hasProvider(locationManager, provider);
        }
        if (locationManager.getAllProviders().contains(provider)) {
            return true;
        }
        try {
            return locationManager.getProvider(provider) != null;
        } catch (SecurityException e) {
            return false;
        }
    }

    public static void getCurrentLocation(LocationManager locationManager, String provider, CancellationSignal cancellationSignal, Executor executor, final Consumer<Location> consumer) {
        if (Build.VERSION.SDK_INT >= 30) {
            Api30Impl.getCurrentLocation(locationManager, provider, cancellationSignal, executor, consumer);
            return;
        }
        if (cancellationSignal != null) {
            cancellationSignal.throwIfCanceled();
        }
        final Location location = locationManager.getLastKnownLocation(provider);
        if (location != null) {
            long locationAgeMs = SystemClock.elapsedRealtime() - LocationCompat.getElapsedRealtimeMillis(location);
            if (locationAgeMs < MAX_CURRENT_LOCATION_AGE_MS) {
                executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda0
                    @Override // java.lang.Runnable
                    public final void run() {
                        Consumer.this.accept(location);
                    }
                });
                return;
            }
        }
        final CancellableLocationListener listener = new CancellableLocationListener(locationManager, executor, consumer);
        locationManager.requestLocationUpdates(provider, 0L, 0.0f, listener, Looper.getMainLooper());
        if (cancellationSignal != null) {
            cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() { // from class: androidx.core.location.LocationManagerCompat.1
                @Override // androidx.core.os.CancellationSignal.OnCancelListener
                public void onCancel() {
                    CancellableLocationListener.this.cancel();
                }
            });
        }
        listener.startTimeout(GET_CURRENT_LOCATION_TIMEOUT_MS);
    }

    public static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequestCompat locationRequest, Executor executor, LocationListenerCompat listener) {
        if (Build.VERSION.SDK_INT >= 31) {
            Api31Impl.requestLocationUpdates(locationManager, provider, locationRequest.toLocationRequest(), executor, listener);
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                if (sRequestLocationUpdatesExecutorMethod == null) {
                    Method declaredMethod = LocationManager.class.getDeclaredMethod("requestLocationUpdates", LocationRequest.class, Executor.class, LocationListener.class);
                    sRequestLocationUpdatesExecutorMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                LocationRequest request = locationRequest.toLocationRequest(provider);
                if (request != null) {
                    sRequestLocationUpdatesExecutorMethod.invoke(locationManager, request, executor, listener);
                    return;
                }
            } catch (IllegalAccessException e) {
            } catch (NoSuchMethodException e2) {
            } catch (UnsupportedOperationException e3) {
            } catch (InvocationTargetException e4) {
            }
        }
        LocationListenerTransport transport = new LocationListenerTransport(listener, executor);
        if (Build.VERSION.SDK_INT >= 19) {
            try {
                if (sRequestLocationUpdatesLooperMethod == null) {
                    Method declaredMethod2 = LocationManager.class.getDeclaredMethod("requestLocationUpdates", LocationRequest.class, LocationListener.class, Looper.class);
                    sRequestLocationUpdatesLooperMethod = declaredMethod2;
                    declaredMethod2.setAccessible(true);
                }
                LocationRequest request2 = locationRequest.toLocationRequest(provider);
                if (request2 != null) {
                    synchronized (sLocationListeners) {
                        sRequestLocationUpdatesLooperMethod.invoke(locationManager, request2, transport, Looper.getMainLooper());
                        transport.register();
                    }
                    return;
                }
            } catch (IllegalAccessException e5) {
            } catch (NoSuchMethodException e6) {
            } catch (UnsupportedOperationException e7) {
            } catch (InvocationTargetException e8) {
            }
        }
        synchronized (sLocationListeners) {
            locationManager.requestLocationUpdates(provider, locationRequest.getIntervalMillis(), locationRequest.getMinUpdateDistanceMeters(), transport, Looper.getMainLooper());
            transport.register();
        }
    }

    public static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequestCompat locationRequest, LocationListenerCompat listener, Looper looper) {
        if (Build.VERSION.SDK_INT >= 31) {
            Api31Impl.requestLocationUpdates(locationManager, provider, locationRequest.toLocationRequest(), ExecutorCompat.create(new Handler(looper)), listener);
            return;
        }
        if (Build.VERSION.SDK_INT >= 19) {
            try {
                if (sRequestLocationUpdatesLooperMethod == null) {
                    Method declaredMethod = LocationManager.class.getDeclaredMethod("requestLocationUpdates", LocationRequest.class, LocationListener.class, Looper.class);
                    sRequestLocationUpdatesLooperMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                LocationRequest request = locationRequest.toLocationRequest(provider);
                if (request != null) {
                    sRequestLocationUpdatesLooperMethod.invoke(locationManager, request, listener, looper);
                    return;
                }
            } catch (IllegalAccessException e) {
            } catch (NoSuchMethodException e2) {
            } catch (UnsupportedOperationException e3) {
            } catch (InvocationTargetException e4) {
            }
        }
        locationManager.requestLocationUpdates(provider, locationRequest.getIntervalMillis(), locationRequest.getMinUpdateDistanceMeters(), listener, looper);
    }

    public static void removeUpdates(LocationManager locationManager, LocationListenerCompat listener) {
        WeakHashMap<LocationListener, List<WeakReference<LocationListenerTransport>>> weakHashMap = sLocationListeners;
        synchronized (weakHashMap) {
            List<WeakReference<LocationListenerTransport>> transports = weakHashMap.remove(listener);
            if (transports != null) {
                for (WeakReference<LocationListenerTransport> reference : transports) {
                    LocationListenerTransport transport = reference.get();
                    if (transport != null && transport.unregister()) {
                        locationManager.removeUpdates(transport);
                    }
                }
            }
        }
        locationManager.removeUpdates(listener);
    }

    public static String getGnssHardwareModelName(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getGnssHardwareModelName(locationManager);
        }
        return null;
    }

    public static int getGnssYearOfHardware(LocationManager locationManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.getGnssYearOfHardware(locationManager);
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class GnssLazyLoader {
        static final SimpleArrayMap<Object, Object> sGnssStatusListeners = new SimpleArrayMap<>();

        private GnssLazyLoader() {
        }
    }

    public static boolean registerGnssStatusCallback(LocationManager locationManager, GnssStatusCompat.Callback callback, Handler handler) {
        if (Build.VERSION.SDK_INT >= 30) {
            return registerGnssStatusCallback(locationManager, ExecutorCompat.create(handler), callback);
        }
        return registerGnssStatusCallback(locationManager, new InlineHandlerExecutor(handler), callback);
    }

    public static boolean registerGnssStatusCallback(LocationManager locationManager, Executor executor, GnssStatusCompat.Callback callback) {
        if (Build.VERSION.SDK_INT >= 30) {
            return registerGnssStatusCallback(locationManager, null, executor, callback);
        }
        Looper looper = Looper.myLooper();
        if (looper == null) {
            looper = Looper.getMainLooper();
        }
        return registerGnssStatusCallback(locationManager, new Handler(looper), executor, callback);
    }

    private static boolean registerGnssStatusCallback(final LocationManager locationManager, Handler baseHandler, Executor executor, GnssStatusCompat.Callback callback) {
        GpsStatusTransport transport;
        if (Build.VERSION.SDK_INT >= 30) {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GnssStatusTransport transport2 = (GnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.get(callback);
                if (transport2 == null) {
                    transport2 = new GnssStatusTransport(callback);
                }
                if (locationManager.registerGnssStatusCallback(executor, transport2)) {
                    GnssLazyLoader.sGnssStatusListeners.put(callback, transport2);
                    return true;
                }
                return false;
            }
        } else if (Build.VERSION.SDK_INT >= 24) {
            Preconditions.checkArgument(baseHandler != null);
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                PreRGnssStatusTransport transport3 = (PreRGnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.get(callback);
                if (transport3 == null) {
                    transport3 = new PreRGnssStatusTransport(callback);
                } else {
                    transport3.unregister();
                }
                transport3.register(executor);
                if (locationManager.registerGnssStatusCallback(transport3, baseHandler)) {
                    GnssLazyLoader.sGnssStatusListeners.put(callback, transport3);
                    return true;
                }
                return false;
            }
        } else {
            Preconditions.checkArgument(baseHandler != null);
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GpsStatusTransport transport4 = (GpsStatusTransport) GnssLazyLoader.sGnssStatusListeners.get(callback);
                if (transport4 == null) {
                    transport = new GpsStatusTransport(locationManager, callback);
                } else {
                    transport4.unregister();
                    transport = transport4;
                }
                transport.register(executor);
                final GpsStatusTransport myTransport = transport;
                FutureTask<Boolean> task = new FutureTask<>(new Callable() { // from class: androidx.core.location.LocationManagerCompat$$ExternalSyntheticLambda1
                    @Override // java.util.concurrent.Callable
                    public final Object call() {
                        Boolean valueOf;
                        valueOf = Boolean.valueOf(locationManager.addGpsStatusListener(myTransport));
                        return valueOf;
                    }
                });
                if (Looper.myLooper() == baseHandler.getLooper()) {
                    task.run();
                } else if (!baseHandler.post(task)) {
                    throw new IllegalStateException(baseHandler + " is shutting down");
                }
                boolean interrupted = false;
                try {
                    long remainingNanos = TimeUnit.SECONDS.toNanos(PRE_N_LOOPER_TIMEOUT_S);
                    long end = System.nanoTime() + remainingNanos;
                    while (task.get(remainingNanos, TimeUnit.NANOSECONDS).booleanValue()) {
                        try {
                            GnssLazyLoader.sGnssStatusListeners.put(callback, myTransport);
                            if (interrupted) {
                                Thread.currentThread().interrupt();
                            }
                            return true;
                        } catch (InterruptedException e) {
                            interrupted = true;
                            remainingNanos = end - System.nanoTime();
                        }
                    }
                    if (interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    return false;
                } catch (ExecutionException e2) {
                    if (e2.getCause() instanceof RuntimeException) {
                        throw ((RuntimeException) e2.getCause());
                    }
                    if (e2.getCause() instanceof Error) {
                        throw ((Error) e2.getCause());
                    }
                    throw new IllegalStateException(e2);
                } catch (TimeoutException e3) {
                    throw new IllegalStateException(baseHandler + " appears to be blocked, please run registerGnssStatusCallback() directly on a Looper thread or ensure the main Looper is not blocked by this thread", e3);
                }
            }
        }
    }

    public static void unregisterGnssStatusCallback(LocationManager locationManager, GnssStatusCompat.Callback callback) {
        if (Build.VERSION.SDK_INT >= 30) {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GnssStatusTransport transport = (GnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport != null) {
                    locationManager.unregisterGnssStatusCallback(transport);
                }
            }
        } else if (Build.VERSION.SDK_INT >= 24) {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                PreRGnssStatusTransport transport2 = (PreRGnssStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport2 != null) {
                    transport2.unregister();
                    locationManager.unregisterGnssStatusCallback(transport2);
                }
            }
        } else {
            synchronized (GnssLazyLoader.sGnssStatusListeners) {
                GpsStatusTransport transport3 = (GpsStatusTransport) GnssLazyLoader.sGnssStatusListeners.remove(callback);
                if (transport3 != null) {
                    transport3.unregister();
                    locationManager.removeGpsStatusListener(transport3);
                }
            }
        }
    }

    private LocationManagerCompat() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class LocationListenerTransport implements LocationListener {
        final Executor mExecutor;
        volatile LocationListenerCompat mListener;

        LocationListenerTransport(LocationListenerCompat listener, Executor executor) {
            this.mListener = (LocationListenerCompat) ObjectsCompat.requireNonNull(listener, "invalid null listener");
            this.mExecutor = executor;
        }

        public void register() {
            List<WeakReference<LocationListenerTransport>> transports = LocationManagerCompat.sLocationListeners.get(this.mListener);
            if (transports == null) {
                transports = new ArrayList(1);
                LocationManagerCompat.sLocationListeners.put(this.mListener, transports);
            } else if (Build.VERSION.SDK_INT >= 24) {
                transports.removeIf(LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda6.INSTANCE);
            } else {
                Iterator<WeakReference<LocationListenerTransport>> it = transports.iterator();
                while (it.hasNext()) {
                    if (it.next().get() == null) {
                        it.remove();
                    }
                }
            }
            transports.add(new WeakReference<>(this));
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static /* synthetic */ boolean lambda$register$0(WeakReference reference) {
            return reference.get() == null;
        }

        public boolean unregister() {
            LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return false;
            }
            this.mListener = null;
            List<WeakReference<LocationListenerTransport>> transports = LocationManagerCompat.sLocationListeners.get(listener);
            if (transports != null) {
                if (Build.VERSION.SDK_INT >= 24) {
                    transports.removeIf(LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda7.INSTANCE);
                } else {
                    Iterator<WeakReference<LocationListenerTransport>> it = transports.iterator();
                    while (it.hasNext()) {
                        if (it.next().get() == null) {
                            it.remove();
                        }
                    }
                }
                if (transports.isEmpty()) {
                    LocationManagerCompat.sLocationListeners.remove(listener);
                    return true;
                }
                return true;
            }
            return true;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static /* synthetic */ boolean lambda$unregister$1(WeakReference reference) {
            return reference.get() == null;
        }

        @Override // android.location.LocationListener
        public void onLocationChanged(final Location location) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m14xad6a74fb(listener, location);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onLocationChanged$2$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m14xad6a74fb(LocationListenerCompat listener, Location location) {
            if (this.mListener != listener) {
                return;
            }
            listener.onLocationChanged(location);
        }

        @Override // android.location.LocationListener
        public void onLocationChanged(final List<Location> locations) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda5
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m15x2fb529da(listener, locations);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onLocationChanged$3$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m15x2fb529da(LocationListenerCompat listener, List locations) {
            if (this.mListener != listener) {
                return;
            }
            listener.onLocationChanged(locations);
        }

        @Override // android.location.LocationListener
        public void onFlushComplete(final int requestCode) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m13xf4e2685b(listener, requestCode);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onFlushComplete$4$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m13xf4e2685b(LocationListenerCompat listener, int requestCode) {
            if (this.mListener != listener) {
                return;
            }
            listener.onFlushComplete(requestCode);
        }

        @Override // android.location.LocationListener
        public void onStatusChanged(final String provider, final int status, final Bundle extras) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda4
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m18xe07c10d5(listener, provider, status, extras);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onStatusChanged$5$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m18xe07c10d5(LocationListenerCompat listener, String provider, int status, Bundle extras) {
            if (this.mListener != listener) {
                return;
            }
            listener.onStatusChanged(provider, status, extras);
        }

        @Override // android.location.LocationListener
        public void onProviderEnabled(final String provider) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda3
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m17x5ebfe4c6(listener, provider);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onProviderEnabled$6$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m17x5ebfe4c6(LocationListenerCompat listener, String provider) {
            if (this.mListener != listener) {
                return;
            }
            listener.onProviderEnabled(provider);
        }

        @Override // android.location.LocationListener
        public void onProviderDisabled(final String provider) {
            final LocationListenerCompat listener = this.mListener;
            if (listener == null) {
                return;
            }
            this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$LocationListenerTransport$$ExternalSyntheticLambda2
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.LocationListenerTransport.this.m16x48c02650(listener, provider);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onProviderDisabled$7$androidx-core-location-LocationManagerCompat$LocationListenerTransport  reason: not valid java name */
        public /* synthetic */ void m16x48c02650(LocationListenerCompat listener, String provider) {
            if (this.mListener != listener) {
                return;
            }
            listener.onProviderDisabled(provider);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class GnssStatusTransport extends GnssStatus.Callback {
        final GnssStatusCompat.Callback mCallback;

        GnssStatusTransport(GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mCallback = callback;
        }

        @Override // android.location.GnssStatus.Callback
        public void onStarted() {
            this.mCallback.onStarted();
        }

        @Override // android.location.GnssStatus.Callback
        public void onStopped() {
            this.mCallback.onStopped();
        }

        @Override // android.location.GnssStatus.Callback
        public void onFirstFix(int ttffMillis) {
            this.mCallback.onFirstFix(ttffMillis);
        }

        @Override // android.location.GnssStatus.Callback
        public void onSatelliteStatusChanged(GnssStatus status) {
            this.mCallback.onSatelliteStatusChanged(GnssStatusCompat.wrap(status));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class PreRGnssStatusTransport extends GnssStatus.Callback {
        final GnssStatusCompat.Callback mCallback;
        volatile Executor mExecutor;

        PreRGnssStatusTransport(GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mCallback = callback;
        }

        public void register(Executor executor) {
            Preconditions.checkArgument(executor != null, "invalid null executor");
            Preconditions.checkState(this.mExecutor == null);
            this.mExecutor = executor;
        }

        public void unregister() {
            this.mExecutor = null;
        }

        @Override // android.location.GnssStatus.Callback
        public void onStarted() {
            final Executor executor = this.mExecutor;
            if (executor == null) {
                return;
            }
            executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.PreRGnssStatusTransport.this.m21x7ba12b9c(executor);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onStarted$0$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport  reason: not valid java name */
        public /* synthetic */ void m21x7ba12b9c(Executor executor) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onStarted();
        }

        @Override // android.location.GnssStatus.Callback
        public void onStopped() {
            final Executor executor = this.mExecutor;
            if (executor == null) {
                return;
            }
            executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.PreRGnssStatusTransport.this.m22x80a5cd6f(executor);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onStopped$1$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport  reason: not valid java name */
        public /* synthetic */ void m22x80a5cd6f(Executor executor) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onStopped();
        }

        @Override // android.location.GnssStatus.Callback
        public void onFirstFix(final int ttffMillis) {
            final Executor executor = this.mExecutor;
            if (executor == null) {
                return;
            }
            executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda2
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.PreRGnssStatusTransport.this.m19x4191f1e(executor, ttffMillis);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onFirstFix$2$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport  reason: not valid java name */
        public /* synthetic */ void m19x4191f1e(Executor executor, int ttffMillis) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onFirstFix(ttffMillis);
        }

        @Override // android.location.GnssStatus.Callback
        public void onSatelliteStatusChanged(final GnssStatus status) {
            final Executor executor = this.mExecutor;
            if (executor == null) {
                return;
            }
            executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$PreRGnssStatusTransport$$ExternalSyntheticLambda3
                @Override // java.lang.Runnable
                public final void run() {
                    LocationManagerCompat.PreRGnssStatusTransport.this.m20xdecf6cdb(executor, status);
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onSatelliteStatusChanged$3$androidx-core-location-LocationManagerCompat$PreRGnssStatusTransport  reason: not valid java name */
        public /* synthetic */ void m20xdecf6cdb(Executor executor, GnssStatus status) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onSatelliteStatusChanged(GnssStatusCompat.wrap(status));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class GpsStatusTransport implements GpsStatus.Listener {
        final GnssStatusCompat.Callback mCallback;
        volatile Executor mExecutor;
        private final LocationManager mLocationManager;

        GpsStatusTransport(LocationManager locationManager, GnssStatusCompat.Callback callback) {
            Preconditions.checkArgument(callback != null, "invalid null callback");
            this.mLocationManager = locationManager;
            this.mCallback = callback;
        }

        public void register(Executor executor) {
            Preconditions.checkState(this.mExecutor == null);
            this.mExecutor = executor;
        }

        public void unregister() {
            this.mExecutor = null;
        }

        @Override // android.location.GpsStatus.Listener
        public void onGpsStatusChanged(int event) {
            final Executor executor = this.mExecutor;
            if (executor == null) {
                return;
            }
            switch (event) {
                case 1:
                    executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda0
                        @Override // java.lang.Runnable
                        public final void run() {
                            LocationManagerCompat.GpsStatusTransport.this.m9x75e92221(executor);
                        }
                    });
                    return;
                case 2:
                    executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda1
                        @Override // java.lang.Runnable
                        public final void run() {
                            LocationManagerCompat.GpsStatusTransport.this.m10xc3a89a22(executor);
                        }
                    });
                    return;
                case 3:
                    GpsStatus gpsStatus = this.mLocationManager.getGpsStatus(null);
                    if (gpsStatus != null) {
                        final int ttff = gpsStatus.getTimeToFirstFix();
                        executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda2
                            @Override // java.lang.Runnable
                            public final void run() {
                                LocationManagerCompat.GpsStatusTransport.this.m11x11681223(executor, ttff);
                            }
                        });
                        return;
                    }
                    return;
                case 4:
                    GpsStatus gpsStatus2 = this.mLocationManager.getGpsStatus(null);
                    if (gpsStatus2 != null) {
                        final GnssStatusCompat gnssStatus = GnssStatusCompat.wrap(gpsStatus2);
                        executor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$GpsStatusTransport$$ExternalSyntheticLambda3
                            @Override // java.lang.Runnable
                            public final void run() {
                                LocationManagerCompat.GpsStatusTransport.this.m12x5f278a24(executor, gnssStatus);
                            }
                        });
                        return;
                    }
                    return;
                default:
                    return;
            }
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$0$androidx-core-location-LocationManagerCompat$GpsStatusTransport  reason: not valid java name */
        public /* synthetic */ void m9x75e92221(Executor executor) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onStarted();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$1$androidx-core-location-LocationManagerCompat$GpsStatusTransport  reason: not valid java name */
        public /* synthetic */ void m10xc3a89a22(Executor executor) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onStopped();
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$2$androidx-core-location-LocationManagerCompat$GpsStatusTransport  reason: not valid java name */
        public /* synthetic */ void m11x11681223(Executor executor, int ttff) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onFirstFix(ttff);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$onGpsStatusChanged$3$androidx-core-location-LocationManagerCompat$GpsStatusTransport  reason: not valid java name */
        public /* synthetic */ void m12x5f278a24(Executor executor, GnssStatusCompat gnssStatus) {
            if (this.mExecutor != executor) {
                return;
            }
            this.mCallback.onSatelliteStatusChanged(gnssStatus);
        }
    }

    /* loaded from: classes.dex */
    private static class Api31Impl {
        private Api31Impl() {
        }

        static boolean hasProvider(LocationManager locationManager, String provider) {
            return locationManager.hasProvider(provider);
        }

        static void requestLocationUpdates(LocationManager locationManager, String provider, LocationRequest locationRequest, Executor executor, LocationListener listener) {
            locationManager.requestLocationUpdates(provider, locationRequest, executor, listener);
        }
    }

    /* loaded from: classes.dex */
    private static class Api30Impl {
        private Api30Impl() {
        }

        static void getCurrentLocation(LocationManager locationManager, String provider, CancellationSignal cancellationSignal, Executor executor, final Consumer<Location> consumer) {
            android.os.CancellationSignal cancellationSignal2;
            if (cancellationSignal != null) {
                cancellationSignal2 = (android.os.CancellationSignal) cancellationSignal.getCancellationSignalObject();
            } else {
                cancellationSignal2 = null;
            }
            Objects.requireNonNull(consumer);
            locationManager.getCurrentLocation(provider, cancellationSignal2, executor, new java.util.function.Consumer() { // from class: androidx.core.location.LocationManagerCompat$Api30Impl$$ExternalSyntheticLambda0
                @Override // java.util.function.Consumer
                public final void accept(Object obj) {
                    Consumer.this.accept((Location) obj);
                }
            });
        }
    }

    /* loaded from: classes.dex */
    private static class Api28Impl {
        private Api28Impl() {
        }

        static boolean isLocationEnabled(LocationManager locationManager) {
            return locationManager.isLocationEnabled();
        }

        static String getGnssHardwareModelName(LocationManager locationManager) {
            return locationManager.getGnssHardwareModelName();
        }

        static int getGnssYearOfHardware(LocationManager locationManager) {
            return locationManager.getGnssYearOfHardware();
        }
    }

    /* loaded from: classes.dex */
    private static final class CancellableLocationListener implements LocationListener {
        private Consumer<Location> mConsumer;
        private final Executor mExecutor;
        private final LocationManager mLocationManager;
        private final Handler mTimeoutHandler = new Handler(Looper.getMainLooper());
        Runnable mTimeoutRunnable;
        private boolean mTriggered;

        CancellableLocationListener(LocationManager locationManager, Executor executor, Consumer<Location> consumer) {
            this.mLocationManager = locationManager;
            this.mExecutor = executor;
            this.mConsumer = consumer;
        }

        public void cancel() {
            synchronized (this) {
                if (this.mTriggered) {
                    return;
                }
                this.mTriggered = true;
                cleanup();
            }
        }

        public void startTimeout(long timeoutMs) {
            synchronized (this) {
                if (this.mTriggered) {
                    return;
                }
                Runnable runnable = new Runnable() { // from class: androidx.core.location.LocationManagerCompat.CancellableLocationListener.1
                    @Override // java.lang.Runnable
                    public void run() {
                        CancellableLocationListener.this.mTimeoutRunnable = null;
                        CancellableLocationListener.this.onLocationChanged((Location) null);
                    }
                };
                this.mTimeoutRunnable = runnable;
                this.mTimeoutHandler.postDelayed(runnable, timeoutMs);
            }
        }

        @Override // android.location.LocationListener
        public void onStatusChanged(String provider, int status, Bundle extras) {
        }

        @Override // android.location.LocationListener
        public void onProviderEnabled(String provider) {
        }

        @Override // android.location.LocationListener
        public void onProviderDisabled(String p) {
            onLocationChanged((Location) null);
        }

        @Override // android.location.LocationListener
        public void onLocationChanged(final Location location) {
            synchronized (this) {
                if (this.mTriggered) {
                    return;
                }
                this.mTriggered = true;
                final Consumer<Location> consumer = this.mConsumer;
                this.mExecutor.execute(new Runnable() { // from class: androidx.core.location.LocationManagerCompat$CancellableLocationListener$$ExternalSyntheticLambda0
                    @Override // java.lang.Runnable
                    public final void run() {
                        Consumer.this.accept(location);
                    }
                });
                cleanup();
            }
        }

        private void cleanup() {
            this.mConsumer = null;
            this.mLocationManager.removeUpdates(this);
            Runnable runnable = this.mTimeoutRunnable;
            if (runnable != null) {
                this.mTimeoutHandler.removeCallbacks(runnable);
                this.mTimeoutRunnable = null;
            }
        }
    }

    /* loaded from: classes.dex */
    private static final class InlineHandlerExecutor implements Executor {
        private final Handler mHandler;

        InlineHandlerExecutor(Handler handler) {
            this.mHandler = (Handler) Preconditions.checkNotNull(handler);
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable command) {
            if (Looper.myLooper() == this.mHandler.getLooper()) {
                command.run();
            } else if (!this.mHandler.post((Runnable) Preconditions.checkNotNull(command))) {
                throw new RejectedExecutionException(this.mHandler + " is shutting down");
            }
        }
    }
}
