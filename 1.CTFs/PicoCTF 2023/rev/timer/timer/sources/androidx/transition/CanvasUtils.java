package androidx.transition;

import android.graphics.Canvas;
import android.os.Build;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
class CanvasUtils {
    private static Method sInorderBarrierMethod;
    private static boolean sOrderMethodsFetched;
    private static Method sReorderBarrierMethod;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void enableZ(Canvas canvas, boolean enable) {
        Method method;
        if (Build.VERSION.SDK_INT >= 21) {
            if (Build.VERSION.SDK_INT >= 29) {
                if (enable) {
                    canvas.enableZ();
                } else {
                    canvas.disableZ();
                }
            } else if (Build.VERSION.SDK_INT == 28) {
                throw new IllegalStateException("This method doesn't work on Pie!");
            } else {
                if (!sOrderMethodsFetched) {
                    try {
                        Method declaredMethod = Canvas.class.getDeclaredMethod("insertReorderBarrier", new Class[0]);
                        sReorderBarrierMethod = declaredMethod;
                        declaredMethod.setAccessible(true);
                        Method declaredMethod2 = Canvas.class.getDeclaredMethod("insertInorderBarrier", new Class[0]);
                        sInorderBarrierMethod = declaredMethod2;
                        declaredMethod2.setAccessible(true);
                    } catch (NoSuchMethodException e) {
                    }
                    sOrderMethodsFetched = true;
                }
                if (enable) {
                    try {
                        Method method2 = sReorderBarrierMethod;
                        if (method2 != null) {
                            method2.invoke(canvas, new Object[0]);
                        }
                    } catch (IllegalAccessException e2) {
                        return;
                    } catch (InvocationTargetException e3) {
                        throw new RuntimeException(e3.getCause());
                    }
                }
                if (!enable && (method = sInorderBarrierMethod) != null) {
                    method.invoke(canvas, new Object[0]);
                }
            }
        }
    }

    private CanvasUtils() {
    }
}
