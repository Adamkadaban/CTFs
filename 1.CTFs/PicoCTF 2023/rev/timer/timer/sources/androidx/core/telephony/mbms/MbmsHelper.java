package androidx.core.telephony.mbms;

import android.content.Context;
import android.os.Build;
import android.os.LocaleList;
import android.telephony.mbms.ServiceInfo;
import java.util.Locale;
/* loaded from: classes.dex */
public final class MbmsHelper {
    private MbmsHelper() {
    }

    public static CharSequence getBestNameForService(Context context, ServiceInfo serviceInfo) {
        if (Build.VERSION.SDK_INT < 28) {
            return null;
        }
        LocaleList localeList = context.getResources().getConfiguration().getLocales();
        int numLanguagesSupportedByService = serviceInfo.getNamedContentLocales().size();
        if (numLanguagesSupportedByService == 0) {
            return null;
        }
        String[] supportedLanguages = new String[numLanguagesSupportedByService];
        int i = 0;
        for (Locale l : serviceInfo.getNamedContentLocales()) {
            supportedLanguages[i] = l.toLanguageTag();
            i++;
        }
        Locale bestLocale = localeList.getFirstMatch(supportedLanguages);
        if (bestLocale == null) {
            return null;
        }
        return serviceInfo.getNameForLocale(bestLocale);
    }
}
