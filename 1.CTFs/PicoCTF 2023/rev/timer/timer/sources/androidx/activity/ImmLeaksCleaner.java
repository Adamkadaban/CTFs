package androidx.activity;

import android.app.Activity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import java.lang.reflect.Field;
/* loaded from: classes.dex */
final class ImmLeaksCleaner implements LifecycleEventObserver {
    private static final int INIT_FAILED = 2;
    private static final int INIT_SUCCESS = 1;
    private static final int NOT_INITIALIAZED = 0;
    private static Field sHField;
    private static Field sNextServedViewField;
    private static int sReflectedFieldsInitialized = 0;
    private static Field sServedViewField;
    private Activity mActivity;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ImmLeaksCleaner(Activity activity) {
        this.mActivity = activity;
    }

    @Override // androidx.lifecycle.LifecycleEventObserver
    public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
        if (event != Lifecycle.Event.ON_DESTROY) {
            return;
        }
        if (sReflectedFieldsInitialized == 0) {
            initializeReflectiveFields();
        }
        if (sReflectedFieldsInitialized == 1) {
            InputMethodManager inputMethodManager = (InputMethodManager) this.mActivity.getSystemService("input_method");
            try {
                Object lock = sHField.get(inputMethodManager);
                if (lock == null) {
                    return;
                }
                synchronized (lock) {
                    try {
                        try {
                            View servedView = (View) sServedViewField.get(inputMethodManager);
                            if (servedView == null) {
                                return;
                            }
                            if (servedView.isAttachedToWindow()) {
                                return;
                            }
                            try {
                                sNextServedViewField.set(inputMethodManager, null);
                                inputMethodManager.isActive();
                            } catch (IllegalAccessException e) {
                            }
                        } catch (ClassCastException e2) {
                        } catch (IllegalAccessException e3) {
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            } catch (IllegalAccessException e4) {
            }
        }
    }

    private static void initializeReflectiveFields() {
        try {
            sReflectedFieldsInitialized = 2;
            Field declaredField = InputMethodManager.class.getDeclaredField("mServedView");
            sServedViewField = declaredField;
            declaredField.setAccessible(true);
            Field declaredField2 = InputMethodManager.class.getDeclaredField("mNextServedView");
            sNextServedViewField = declaredField2;
            declaredField2.setAccessible(true);
            Field declaredField3 = InputMethodManager.class.getDeclaredField("mH");
            sHField = declaredField3;
            declaredField3.setAccessible(true);
            sReflectedFieldsInitialized = 1;
        } catch (NoSuchFieldException e) {
        }
    }
}
