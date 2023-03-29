package androidx.core.os;

import android.os.Build;
import android.os.Message;
/* loaded from: classes.dex */
public final class MessageCompat {
    private static boolean sTrySetAsynchronous = true;
    private static boolean sTryIsAsynchronous = true;

    public static void setAsynchronous(Message message, boolean async) {
        if (Build.VERSION.SDK_INT >= 22) {
            message.setAsynchronous(async);
        } else if (sTrySetAsynchronous && Build.VERSION.SDK_INT >= 16) {
            try {
                message.setAsynchronous(async);
            } catch (NoSuchMethodError e) {
                sTrySetAsynchronous = false;
            }
        }
    }

    public static boolean isAsynchronous(Message message) {
        if (Build.VERSION.SDK_INT >= 22) {
            return message.isAsynchronous();
        }
        if (sTryIsAsynchronous && Build.VERSION.SDK_INT >= 16) {
            try {
                return message.isAsynchronous();
            } catch (NoSuchMethodError e) {
                sTryIsAsynchronous = false;
            }
        }
        return false;
    }

    private MessageCompat() {
    }
}
