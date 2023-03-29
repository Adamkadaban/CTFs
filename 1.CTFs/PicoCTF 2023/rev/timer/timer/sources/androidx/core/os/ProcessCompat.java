package androidx.core.os;

import android.os.Build;
import android.os.Process;
import android.os.UserHandle;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public final class ProcessCompat {
    private ProcessCompat() {
    }

    public static boolean isApplicationUid(int uid) {
        if (Build.VERSION.SDK_INT >= 24) {
            return Api24Impl.isApplicationUid(uid);
        }
        if (Build.VERSION.SDK_INT >= 17) {
            return Api17Impl.isApplicationUid(uid);
        }
        if (Build.VERSION.SDK_INT == 16) {
            return Api16Impl.isApplicationUid(uid);
        }
        return true;
    }

    /* loaded from: classes.dex */
    static class Api24Impl {
        private Api24Impl() {
        }

        static boolean isApplicationUid(int uid) {
            return Process.isApplicationUid(uid);
        }
    }

    /* loaded from: classes.dex */
    static class Api17Impl {
        private static Method sMethodUserHandleIsAppMethod;
        private static boolean sResolved;
        private static final Object sResolvedLock = new Object();

        private Api17Impl() {
        }

        static boolean isApplicationUid(int uid) {
            try {
                synchronized (sResolvedLock) {
                    if (!sResolved) {
                        sResolved = true;
                        sMethodUserHandleIsAppMethod = UserHandle.class.getDeclaredMethod("isApp", Integer.TYPE);
                    }
                }
                Method method = sMethodUserHandleIsAppMethod;
                if (method != null) {
                    Boolean result = (Boolean) method.invoke(null, Integer.valueOf(uid));
                    if (result == null) {
                        throw new NullPointerException();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return true;
        }
    }

    /* loaded from: classes.dex */
    static class Api16Impl {
        private static Method sMethodUserIdIsAppMethod;
        private static boolean sResolved;
        private static final Object sResolvedLock = new Object();

        private Api16Impl() {
        }

        static boolean isApplicationUid(int uid) {
            try {
                synchronized (sResolvedLock) {
                    if (!sResolved) {
                        sResolved = true;
                        sMethodUserIdIsAppMethod = Class.forName("android.os.UserId").getDeclaredMethod("isApp", Integer.TYPE);
                    }
                }
                Method method = sMethodUserIdIsAppMethod;
                if (method != null) {
                    Boolean result = (Boolean) method.invoke(null, Integer.valueOf(uid));
                    if (result == null) {
                        throw new NullPointerException();
                    }
                    return result.booleanValue();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return true;
        }
    }
}
