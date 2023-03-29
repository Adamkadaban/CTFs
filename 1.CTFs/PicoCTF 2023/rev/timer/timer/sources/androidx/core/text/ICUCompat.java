package androidx.core.text;

import android.icu.util.ULocale;
import android.os.Build;
import android.util.Log;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Locale;
/* loaded from: classes.dex */
public final class ICUCompat {
    private static final String TAG = "ICUCompat";
    private static Method sAddLikelySubtagsMethod;
    private static Method sGetScriptMethod;

    static {
        if (Build.VERSION.SDK_INT < 21) {
            try {
                Class<?> clazz = Class.forName("libcore.icu.ICU");
                if (clazz != null) {
                    sGetScriptMethod = clazz.getMethod("getScript", String.class);
                    sAddLikelySubtagsMethod = clazz.getMethod("addLikelySubtags", String.class);
                }
            } catch (Exception e) {
                sGetScriptMethod = null;
                sAddLikelySubtagsMethod = null;
                Log.w(TAG, e);
            }
        } else if (Build.VERSION.SDK_INT < 24) {
            try {
                sAddLikelySubtagsMethod = Class.forName("libcore.icu.ICU").getMethod("addLikelySubtags", Locale.class);
            } catch (Exception e2) {
                throw new IllegalStateException(e2);
            }
        }
    }

    public static String maximizeAndGetScript(Locale locale) {
        if (Build.VERSION.SDK_INT >= 24) {
            ULocale uLocale = ULocale.addLikelySubtags(ULocale.forLocale(locale));
            return uLocale.getScript();
        } else if (Build.VERSION.SDK_INT >= 21) {
            try {
                Object[] args = {locale};
                return ((Locale) sAddLikelySubtagsMethod.invoke(null, args)).getScript();
            } catch (IllegalAccessException e) {
                Log.w(TAG, e);
                return locale.getScript();
            } catch (InvocationTargetException e2) {
                Log.w(TAG, e2);
                return locale.getScript();
            }
        } else {
            String localeWithSubtags = addLikelySubtags(locale);
            if (localeWithSubtags != null) {
                return getScript(localeWithSubtags);
            }
            return null;
        }
    }

    private static String getScript(String localeStr) {
        try {
            Method method = sGetScriptMethod;
            if (method != null) {
                Object[] args = {localeStr};
                return (String) method.invoke(null, args);
            }
        } catch (IllegalAccessException e) {
            Log.w(TAG, e);
        } catch (InvocationTargetException e2) {
            Log.w(TAG, e2);
        }
        return null;
    }

    private static String addLikelySubtags(Locale locale) {
        String localeStr = locale.toString();
        try {
            Method method = sAddLikelySubtagsMethod;
            if (method != null) {
                Object[] args = {localeStr};
                return (String) method.invoke(null, args);
            }
        } catch (IllegalAccessException e) {
            Log.w(TAG, e);
        } catch (InvocationTargetException e2) {
            Log.w(TAG, e2);
        }
        return localeStr;
    }

    private ICUCompat() {
    }
}
