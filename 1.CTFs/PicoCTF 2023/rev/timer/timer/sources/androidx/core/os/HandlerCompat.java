package androidx.core.os;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public final class HandlerCompat {
    private static final String TAG = "HandlerCompat";

    public static Handler createAsync(Looper looper) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.createAsync(looper);
        }
        if (Build.VERSION.SDK_INT >= 17) {
            try {
                return (Handler) Handler.class.getDeclaredConstructor(Looper.class, Handler.Callback.class, Boolean.TYPE).newInstance(looper, null, true);
            } catch (IllegalAccessException e) {
                wrappedException = e;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper);
            } catch (InstantiationException e2) {
                wrappedException = e2;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper);
            } catch (NoSuchMethodException e3) {
                wrappedException = e3;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper);
            } catch (InvocationTargetException e4) {
                Throwable cause = e4.getCause();
                if (cause instanceof RuntimeException) {
                    throw ((RuntimeException) cause);
                }
                if (cause instanceof Error) {
                    throw ((Error) cause);
                }
                throw new RuntimeException(cause);
            }
        }
        return new Handler(looper);
    }

    public static Handler createAsync(Looper looper, Handler.Callback callback) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.createAsync(looper, callback);
        }
        if (Build.VERSION.SDK_INT >= 17) {
            try {
                return (Handler) Handler.class.getDeclaredConstructor(Looper.class, Handler.Callback.class, Boolean.TYPE).newInstance(looper, callback, true);
            } catch (IllegalAccessException e) {
                wrappedException = e;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper, callback);
            } catch (InstantiationException e2) {
                wrappedException = e2;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper, callback);
            } catch (NoSuchMethodException e3) {
                wrappedException = e3;
                Log.w(TAG, "Unable to invoke Handler(Looper, Callback, boolean) constructor", wrappedException);
                return new Handler(looper, callback);
            } catch (InvocationTargetException e4) {
                Throwable cause = e4.getCause();
                if (cause instanceof RuntimeException) {
                    throw ((RuntimeException) cause);
                }
                if (cause instanceof Error) {
                    throw ((Error) cause);
                }
                throw new RuntimeException(cause);
            }
        }
        return new Handler(looper, callback);
    }

    public static boolean postDelayed(Handler handler, Runnable r, Object token, long delayMillis) {
        if (Build.VERSION.SDK_INT >= 28) {
            return Api28Impl.postDelayed(handler, r, token, delayMillis);
        }
        Message message = Message.obtain(handler, r);
        message.obj = token;
        return handler.sendMessageDelayed(message, delayMillis);
    }

    public static boolean hasCallbacks(Handler handler, Runnable r) {
        Exception wrappedException = null;
        if (Build.VERSION.SDK_INT >= 29) {
            return Api29Impl.hasCallbacks(handler, r);
        }
        if (Build.VERSION.SDK_INT >= 16) {
            try {
                Method hasCallbacksMethod = Handler.class.getMethod("hasCallbacks", Runnable.class);
                return ((Boolean) hasCallbacksMethod.invoke(handler, r)).booleanValue();
            } catch (IllegalAccessException e) {
                wrappedException = e;
            } catch (NoSuchMethodException e2) {
                wrappedException = e2;
            } catch (NullPointerException e3) {
                wrappedException = e3;
            } catch (InvocationTargetException e4) {
                Throwable cause = e4.getCause();
                if (cause instanceof RuntimeException) {
                    throw ((RuntimeException) cause);
                }
                if (cause instanceof Error) {
                    throw ((Error) cause);
                }
                throw new RuntimeException(cause);
            }
        }
        throw new UnsupportedOperationException("Failed to call Handler.hasCallbacks(), but there is no safe failure mode for this method. Raising exception.", wrappedException);
    }

    private HandlerCompat() {
    }

    /* loaded from: classes.dex */
    private static class Api29Impl {
        private Api29Impl() {
        }

        public static boolean hasCallbacks(Handler handler, Runnable r) {
            return handler.hasCallbacks(r);
        }
    }

    /* loaded from: classes.dex */
    private static class Api28Impl {
        private Api28Impl() {
        }

        public static Handler createAsync(Looper looper) {
            return Handler.createAsync(looper);
        }

        public static Handler createAsync(Looper looper, Handler.Callback callback) {
            return Handler.createAsync(looper, callback);
        }

        public static boolean postDelayed(Handler handler, Runnable r, Object token, long delayMillis) {
            return handler.postDelayed(r, token, delayMillis);
        }
    }
}
