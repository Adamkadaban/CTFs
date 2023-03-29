package androidx.core.content.pm;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ResolveInfo;
import android.content.res.XmlResourceParser;
import android.os.Bundle;
import android.util.Log;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public class ShortcutXmlParser {
    private static final String ATTR_SHORTCUT_ID = "shortcutId";
    private static final Object GET_INSTANCE_LOCK = new Object();
    private static final String META_DATA_APP_SHORTCUTS = "android.app.shortcuts";
    private static final String TAG = "ShortcutXmlParser";
    private static final String TAG_SHORTCUT = "shortcut";
    private static volatile ArrayList<String> sShortcutIds;

    public static List<String> getShortcutIds(Context context) {
        if (sShortcutIds == null) {
            synchronized (GET_INSTANCE_LOCK) {
                if (sShortcutIds == null) {
                    sShortcutIds = new ArrayList<>();
                    sShortcutIds.addAll(parseShortcutIds(context));
                }
            }
        }
        return sShortcutIds;
    }

    private ShortcutXmlParser() {
    }

    private static Set<String> parseShortcutIds(Context context) {
        Set<String> result = new HashSet<>();
        Intent mainIntent = new Intent("android.intent.action.MAIN");
        mainIntent.addCategory("android.intent.category.LAUNCHER");
        mainIntent.setPackage(context.getPackageName());
        List<ResolveInfo> resolveInfos = context.getPackageManager().queryIntentActivities(mainIntent, 128);
        if (resolveInfos == null || resolveInfos.size() == 0) {
            return result;
        }
        try {
            for (ResolveInfo info : resolveInfos) {
                ActivityInfo activityInfo = info.activityInfo;
                Bundle metaData = activityInfo.metaData;
                if (metaData != null && metaData.containsKey(META_DATA_APP_SHORTCUTS)) {
                    XmlResourceParser parser = getXmlResourceParser(context, activityInfo);
                    result.addAll(parseShortcutIds(parser));
                    if (parser != null) {
                        parser.close();
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse the Xml resource: ", e);
        }
        return result;
    }

    private static XmlResourceParser getXmlResourceParser(Context context, ActivityInfo info) {
        XmlResourceParser parser = info.loadXmlMetaData(context.getPackageManager(), META_DATA_APP_SHORTCUTS);
        if (parser == null) {
            throw new IllegalArgumentException("Failed to open android.app.shortcuts meta-data resource of " + info.name);
        }
        return parser;
    }

    public static List<String> parseShortcutIds(XmlPullParser parser) throws IOException, XmlPullParserException {
        String shortcutId;
        List<String> result = new ArrayList<>(1);
        while (true) {
            int type = parser.next();
            if (type == 1 || (type == 3 && parser.getDepth() <= 0)) {
                break;
            }
            int depth = parser.getDepth();
            String tag = parser.getName();
            if (type == 2 && depth == 2 && TAG_SHORTCUT.equals(tag) && (shortcutId = getAttributeValue(parser, ATTR_SHORTCUT_ID)) != null) {
                result.add(shortcutId);
            }
        }
        return result;
    }

    private static String getAttributeValue(XmlPullParser parser, String attribute) {
        String value = parser.getAttributeValue("http://schemas.android.com/apk/res/android", attribute);
        if (value == null) {
            return parser.getAttributeValue(null, attribute);
        }
        return value;
    }
}
