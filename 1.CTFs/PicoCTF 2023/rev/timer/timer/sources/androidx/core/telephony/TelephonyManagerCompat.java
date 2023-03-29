package androidx.core.telephony;

import android.os.Build;
import android.telephony.TelephonyManager;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public class TelephonyManagerCompat {
    private static Method sGetDeviceIdMethod;
    private static Method sGetSubIdMethod;

    public static String getImei(TelephonyManager telephonyManager) {
        int subId;
        if (Build.VERSION.SDK_INT >= 26) {
            return Api26Impl.getImei(telephonyManager);
        }
        if (Build.VERSION.SDK_INT >= 22 && (subId = getSubscriptionId(telephonyManager)) != Integer.MAX_VALUE && subId != -1) {
            int slotIndex = SubscriptionManagerCompat.getSlotIndex(subId);
            if (Build.VERSION.SDK_INT >= 23) {
                return Api23Impl.getDeviceId(telephonyManager, slotIndex);
            }
            try {
                if (sGetDeviceIdMethod == null) {
                    Method declaredMethod = TelephonyManager.class.getDeclaredMethod("getDeviceId", Integer.TYPE);
                    sGetDeviceIdMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                return (String) sGetDeviceIdMethod.invoke(telephonyManager, Integer.valueOf(slotIndex));
            } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                return null;
            }
        }
        return telephonyManager.getDeviceId();
    }

    public static int getSubscriptionId(TelephonyManager telephonyManager) {
        if (Build.VERSION.SDK_INT >= 30) {
            return Api30Impl.getSubscriptionId(telephonyManager);
        }
        if (Build.VERSION.SDK_INT >= 22) {
            try {
                if (sGetSubIdMethod == null) {
                    Method declaredMethod = TelephonyManager.class.getDeclaredMethod("getSubId", new Class[0]);
                    sGetSubIdMethod = declaredMethod;
                    declaredMethod.setAccessible(true);
                }
                Integer subId = (Integer) sGetSubIdMethod.invoke(telephonyManager, new Object[0]);
                if (subId != null && subId.intValue() != -1) {
                    return subId.intValue();
                }
                return Integer.MAX_VALUE;
            } catch (IllegalAccessException e) {
                return Integer.MAX_VALUE;
            } catch (NoSuchMethodException e2) {
                return Integer.MAX_VALUE;
            } catch (InvocationTargetException e3) {
                return Integer.MAX_VALUE;
            }
        }
        return Integer.MAX_VALUE;
    }

    private TelephonyManagerCompat() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Api30Impl {
        private Api30Impl() {
        }

        static int getSubscriptionId(TelephonyManager telephonyManager) {
            return telephonyManager.getSubscriptionId();
        }
    }

    /* loaded from: classes.dex */
    private static class Api26Impl {
        private Api26Impl() {
        }

        static String getImei(TelephonyManager telephonyManager) {
            return telephonyManager.getImei();
        }
    }

    /* loaded from: classes.dex */
    private static class Api23Impl {
        private Api23Impl() {
        }

        static String getDeviceId(TelephonyManager telephonyManager, int slotIndex) {
            return telephonyManager.getDeviceId(slotIndex);
        }
    }
}
