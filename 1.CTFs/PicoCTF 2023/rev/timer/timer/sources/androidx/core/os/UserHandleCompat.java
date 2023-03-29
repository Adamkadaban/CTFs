package androidx.core.os;

import android.os.Build;
import android.os.UserHandle;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public class UserHandleCompat {
    private static Method sGetUserIdMethod;
    private static Constructor<UserHandle> sUserHandleConstructor;

    private UserHandleCompat() {
    }

    public static UserHandle getUserHandleForUid(int uid) {
        if (Build.VERSION.SDK_INT >= 24) {
            return Api24Impl.getUserHandleForUid(uid);
        }
        try {
            Integer userId = (Integer) getGetUserIdMethod().invoke(null, Integer.valueOf(uid));
            return getUserHandleConstructor().newInstance(userId);
        } catch (IllegalAccessException e) {
            Error error = new IllegalAccessError();
            error.initCause(e);
            throw error;
        } catch (InstantiationException e2) {
            Error error2 = new InstantiationError();
            error2.initCause(e2);
            throw error2;
        } catch (NoSuchMethodException e3) {
            Error error3 = new NoSuchMethodError();
            error3.initCause(e3);
            throw error3;
        } catch (InvocationTargetException e4) {
            throw new RuntimeException(e4);
        }
    }

    /* loaded from: classes.dex */
    private static class Api24Impl {
        private Api24Impl() {
        }

        static UserHandle getUserHandleForUid(int uid) {
            return UserHandle.getUserHandleForUid(uid);
        }
    }

    private static Method getGetUserIdMethod() throws NoSuchMethodException {
        if (sGetUserIdMethod == null) {
            Method declaredMethod = UserHandle.class.getDeclaredMethod("getUserId", Integer.TYPE);
            sGetUserIdMethod = declaredMethod;
            declaredMethod.setAccessible(true);
        }
        return sGetUserIdMethod;
    }

    private static Constructor<UserHandle> getUserHandleConstructor() throws NoSuchMethodException {
        if (sUserHandleConstructor == null) {
            Constructor<UserHandle> declaredConstructor = UserHandle.class.getDeclaredConstructor(Integer.TYPE);
            sUserHandleConstructor = declaredConstructor;
            declaredConstructor.setAccessible(true);
        }
        return sUserHandleConstructor;
    }
}
