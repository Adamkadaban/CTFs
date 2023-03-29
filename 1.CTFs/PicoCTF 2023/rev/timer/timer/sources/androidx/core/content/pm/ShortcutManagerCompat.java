package androidx.core.content.pm;

import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.os.Bundle;
import android.util.DisplayMetrics;
import androidx.core.content.pm.ShortcutInfoCompat;
import androidx.core.content.pm.ShortcutInfoCompatSaver;
import androidx.core.graphics.drawable.IconCompat;
import androidx.core.util.Preconditions;
import java.io.InputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class ShortcutManagerCompat {
    static final String ACTION_INSTALL_SHORTCUT = "com.android.launcher.action.INSTALL_SHORTCUT";
    private static final int DEFAULT_MAX_ICON_DIMENSION_DP = 96;
    private static final int DEFAULT_MAX_ICON_DIMENSION_LOWRAM_DP = 48;
    public static final String EXTRA_SHORTCUT_ID = "android.intent.extra.shortcut.ID";
    public static final int FLAG_MATCH_CACHED = 8;
    public static final int FLAG_MATCH_DYNAMIC = 2;
    public static final int FLAG_MATCH_MANIFEST = 1;
    public static final int FLAG_MATCH_PINNED = 4;
    static final String INSTALL_SHORTCUT_PERMISSION = "com.android.launcher.permission.INSTALL_SHORTCUT";
    private static final String SHORTCUT_LISTENER_INTENT_FILTER_ACTION = "androidx.core.content.pm.SHORTCUT_LISTENER";
    private static final String SHORTCUT_LISTENER_META_DATA_KEY = "androidx.core.content.pm.shortcut_listener_impl";
    private static volatile ShortcutInfoCompatSaver<?> sShortcutInfoCompatSaver = null;
    private static volatile List<ShortcutInfoChangeListener> sShortcutInfoChangeListeners = null;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface ShortcutMatchFlags {
    }

    private ShortcutManagerCompat() {
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0036  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean isRequestPinShortcutSupported(android.content.Context r6) {
        /*
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 26
            if (r0 < r1) goto L13
            java.lang.Class<android.content.pm.ShortcutManager> r0 = android.content.pm.ShortcutManager.class
            java.lang.Object r0 = r6.getSystemService(r0)
            android.content.pm.ShortcutManager r0 = (android.content.pm.ShortcutManager) r0
            boolean r0 = r0.isRequestPinShortcutSupported()
            return r0
        L13:
            java.lang.String r0 = "com.android.launcher.permission.INSTALL_SHORTCUT"
            int r1 = androidx.core.content.ContextCompat.checkSelfPermission(r6, r0)
            r2 = 0
            if (r1 == 0) goto L1d
            return r2
        L1d:
            android.content.pm.PackageManager r1 = r6.getPackageManager()
            android.content.Intent r3 = new android.content.Intent
            java.lang.String r4 = "com.android.launcher.action.INSTALL_SHORTCUT"
            r3.<init>(r4)
            java.util.List r1 = r1.queryBroadcastReceivers(r3, r2)
            java.util.Iterator r1 = r1.iterator()
        L30:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto L50
            java.lang.Object r3 = r1.next()
            android.content.pm.ResolveInfo r3 = (android.content.pm.ResolveInfo) r3
            android.content.pm.ActivityInfo r4 = r3.activityInfo
            java.lang.String r4 = r4.permission
            boolean r5 = android.text.TextUtils.isEmpty(r4)
            if (r5 != 0) goto L4e
            boolean r5 = r0.equals(r4)
            if (r5 == 0) goto L4d
            goto L4e
        L4d:
            goto L30
        L4e:
            r0 = 1
            return r0
        L50:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.content.pm.ShortcutManagerCompat.isRequestPinShortcutSupported(android.content.Context):boolean");
    }

    public static boolean requestPinShortcut(Context context, ShortcutInfoCompat shortcut, final IntentSender callback) {
        if (Build.VERSION.SDK_INT >= 26) {
            return ((ShortcutManager) context.getSystemService(ShortcutManager.class)).requestPinShortcut(shortcut.toShortcutInfo(), callback);
        }
        if (!isRequestPinShortcutSupported(context)) {
            return false;
        }
        Intent intent = shortcut.addToIntent(new Intent(ACTION_INSTALL_SHORTCUT));
        if (callback == null) {
            context.sendBroadcast(intent);
            return true;
        }
        context.sendOrderedBroadcast(intent, null, new BroadcastReceiver() { // from class: androidx.core.content.pm.ShortcutManagerCompat.1
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context2, Intent intent2) {
                try {
                    callback.sendIntent(context2, 0, null, null, null);
                } catch (IntentSender.SendIntentException e) {
                }
            }
        }, null, -1, null, null);
        return true;
    }

    public static Intent createShortcutResultIntent(Context context, ShortcutInfoCompat shortcut) {
        Intent result = null;
        if (Build.VERSION.SDK_INT >= 26) {
            result = ((ShortcutManager) context.getSystemService(ShortcutManager.class)).createShortcutResultIntent(shortcut.toShortcutInfo());
        }
        if (result == null) {
            result = new Intent();
        }
        return shortcut.addToIntent(result);
    }

    public static List<ShortcutInfoCompat> getShortcuts(Context context, int matchFlags) {
        if (Build.VERSION.SDK_INT >= 30) {
            return ShortcutInfoCompat.fromShortcuts(context, ((ShortcutManager) context.getSystemService(ShortcutManager.class)).getShortcuts(matchFlags));
        }
        if (Build.VERSION.SDK_INT >= 25) {
            ShortcutManager manager = (ShortcutManager) context.getSystemService(ShortcutManager.class);
            List<ShortcutInfo> shortcuts = new ArrayList<>();
            if ((matchFlags & 1) != 0) {
                shortcuts.addAll(manager.getManifestShortcuts());
            }
            if ((matchFlags & 2) != 0) {
                shortcuts.addAll(manager.getDynamicShortcuts());
            }
            if ((matchFlags & 4) != 0) {
                shortcuts.addAll(manager.getPinnedShortcuts());
            }
            return ShortcutInfoCompat.fromShortcuts(context, shortcuts);
        }
        if ((matchFlags & 2) != 0) {
            try {
                return getShortcutInfoSaverInstance(context).getShortcuts();
            } catch (Exception e) {
            }
        }
        return Collections.emptyList();
    }

    public static boolean addDynamicShortcuts(Context context, List<ShortcutInfoCompat> shortcutInfoList) {
        if (Build.VERSION.SDK_INT <= 29) {
            convertUriIconsToBitmapIcons(context, shortcutInfoList);
        }
        if (Build.VERSION.SDK_INT >= 25) {
            ArrayList<ShortcutInfo> shortcuts = new ArrayList<>();
            for (ShortcutInfoCompat item : shortcutInfoList) {
                shortcuts.add(item.toShortcutInfo());
            }
            if (!((ShortcutManager) context.getSystemService(ShortcutManager.class)).addDynamicShortcuts(shortcuts)) {
                return false;
            }
        }
        getShortcutInfoSaverInstance(context).addShortcuts(shortcutInfoList);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutAdded(shortcutInfoList);
        }
        return true;
    }

    public static int getMaxShortcutCountPerActivity(Context context) {
        Preconditions.checkNotNull(context);
        if (Build.VERSION.SDK_INT >= 25) {
            return ((ShortcutManager) context.getSystemService(ShortcutManager.class)).getMaxShortcutCountPerActivity();
        }
        return 5;
    }

    public static boolean isRateLimitingActive(Context context) {
        Preconditions.checkNotNull(context);
        if (Build.VERSION.SDK_INT >= 25) {
            return ((ShortcutManager) context.getSystemService(ShortcutManager.class)).isRateLimitingActive();
        }
        return getShortcuts(context, 3).size() == getMaxShortcutCountPerActivity(context);
    }

    public static int getIconMaxWidth(Context context) {
        Preconditions.checkNotNull(context);
        if (Build.VERSION.SDK_INT >= 25) {
            return ((ShortcutManager) context.getSystemService(ShortcutManager.class)).getIconMaxWidth();
        }
        return getIconDimensionInternal(context, true);
    }

    public static int getIconMaxHeight(Context context) {
        Preconditions.checkNotNull(context);
        if (Build.VERSION.SDK_INT >= 25) {
            return ((ShortcutManager) context.getSystemService(ShortcutManager.class)).getIconMaxHeight();
        }
        return getIconDimensionInternal(context, false);
    }

    public static void reportShortcutUsed(Context context, String shortcutId) {
        Preconditions.checkNotNull(context);
        Preconditions.checkNotNull(shortcutId);
        if (Build.VERSION.SDK_INT >= 25) {
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).reportShortcutUsed(shortcutId);
        }
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutUsageReported(Collections.singletonList(shortcutId));
        }
    }

    public static boolean setDynamicShortcuts(Context context, List<ShortcutInfoCompat> shortcutInfoList) {
        Preconditions.checkNotNull(context);
        Preconditions.checkNotNull(shortcutInfoList);
        if (Build.VERSION.SDK_INT >= 25) {
            List<ShortcutInfo> shortcuts = new ArrayList<>(shortcutInfoList.size());
            for (ShortcutInfoCompat compat : shortcutInfoList) {
                shortcuts.add(compat.toShortcutInfo());
            }
            if (!((ShortcutManager) context.getSystemService(ShortcutManager.class)).setDynamicShortcuts(shortcuts)) {
                return false;
            }
        }
        getShortcutInfoSaverInstance(context).removeAllShortcuts();
        getShortcutInfoSaverInstance(context).addShortcuts(shortcutInfoList);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onAllShortcutsRemoved();
            listener.onShortcutAdded(shortcutInfoList);
        }
        return true;
    }

    public static List<ShortcutInfoCompat> getDynamicShortcuts(Context context) {
        if (Build.VERSION.SDK_INT >= 25) {
            List<ShortcutInfo> shortcuts = ((ShortcutManager) context.getSystemService(ShortcutManager.class)).getDynamicShortcuts();
            List<ShortcutInfoCompat> compats = new ArrayList<>(shortcuts.size());
            for (ShortcutInfo item : shortcuts) {
                compats.add(new ShortcutInfoCompat.Builder(context, item).build());
            }
            return compats;
        }
        try {
            return getShortcutInfoSaverInstance(context).getShortcuts();
        } catch (Exception e) {
            return new ArrayList();
        }
    }

    public static boolean updateShortcuts(Context context, List<ShortcutInfoCompat> shortcutInfoList) {
        if (Build.VERSION.SDK_INT <= 29) {
            convertUriIconsToBitmapIcons(context, shortcutInfoList);
        }
        if (Build.VERSION.SDK_INT >= 25) {
            ArrayList<ShortcutInfo> shortcuts = new ArrayList<>();
            for (ShortcutInfoCompat item : shortcutInfoList) {
                shortcuts.add(item.toShortcutInfo());
            }
            if (!((ShortcutManager) context.getSystemService(ShortcutManager.class)).updateShortcuts(shortcuts)) {
                return false;
            }
        }
        getShortcutInfoSaverInstance(context).addShortcuts(shortcutInfoList);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutUpdated(shortcutInfoList);
        }
        return true;
    }

    static boolean convertUriIconToBitmapIcon(Context context, ShortcutInfoCompat info) {
        Bitmap bitmap;
        IconCompat createWithBitmap;
        if (info.mIcon == null) {
            return false;
        }
        int type = info.mIcon.mType;
        if (type != 6 && type != 4) {
            return true;
        }
        InputStream is = info.mIcon.getUriInputStream(context);
        if (is == null || (bitmap = BitmapFactory.decodeStream(is)) == null) {
            return false;
        }
        if (type == 6) {
            createWithBitmap = IconCompat.createWithAdaptiveBitmap(bitmap);
        } else {
            createWithBitmap = IconCompat.createWithBitmap(bitmap);
        }
        info.mIcon = createWithBitmap;
        return true;
    }

    static void convertUriIconsToBitmapIcons(Context context, List<ShortcutInfoCompat> shortcutInfoList) {
        List<ShortcutInfoCompat> shortcuts = new ArrayList<>(shortcutInfoList);
        for (ShortcutInfoCompat info : shortcuts) {
            if (!convertUriIconToBitmapIcon(context, info)) {
                shortcutInfoList.remove(info);
            }
        }
    }

    public static void disableShortcuts(Context context, List<String> shortcutIds, CharSequence disabledMessage) {
        if (Build.VERSION.SDK_INT >= 25) {
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).disableShortcuts(shortcutIds, disabledMessage);
        }
        getShortcutInfoSaverInstance(context).removeShortcuts(shortcutIds);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutRemoved(shortcutIds);
        }
    }

    public static void enableShortcuts(Context context, List<ShortcutInfoCompat> shortcutInfoList) {
        if (Build.VERSION.SDK_INT >= 25) {
            ArrayList<String> shortcutIds = new ArrayList<>(shortcutInfoList.size());
            for (ShortcutInfoCompat shortcut : shortcutInfoList) {
                shortcutIds.add(shortcut.mId);
            }
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).enableShortcuts(shortcutIds);
        }
        getShortcutInfoSaverInstance(context).addShortcuts(shortcutInfoList);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutAdded(shortcutInfoList);
        }
    }

    public static void removeDynamicShortcuts(Context context, List<String> shortcutIds) {
        if (Build.VERSION.SDK_INT >= 25) {
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).removeDynamicShortcuts(shortcutIds);
        }
        getShortcutInfoSaverInstance(context).removeShortcuts(shortcutIds);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutRemoved(shortcutIds);
        }
    }

    public static void removeAllDynamicShortcuts(Context context) {
        if (Build.VERSION.SDK_INT >= 25) {
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).removeAllDynamicShortcuts();
        }
        getShortcutInfoSaverInstance(context).removeAllShortcuts();
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onAllShortcutsRemoved();
        }
    }

    public static void removeLongLivedShortcuts(Context context, List<String> shortcutIds) {
        if (Build.VERSION.SDK_INT < 30) {
            removeDynamicShortcuts(context, shortcutIds);
            return;
        }
        ((ShortcutManager) context.getSystemService(ShortcutManager.class)).removeLongLivedShortcuts(shortcutIds);
        getShortcutInfoSaverInstance(context).removeShortcuts(shortcutIds);
        for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
            listener.onShortcutRemoved(shortcutIds);
        }
    }

    public static boolean pushDynamicShortcut(Context context, ShortcutInfoCompat shortcut) {
        Preconditions.checkNotNull(context);
        Preconditions.checkNotNull(shortcut);
        int maxShortcutCount = getMaxShortcutCountPerActivity(context);
        if (maxShortcutCount == 0) {
            return false;
        }
        if (Build.VERSION.SDK_INT <= 29) {
            convertUriIconToBitmapIcon(context, shortcut);
        }
        if (Build.VERSION.SDK_INT >= 30) {
            ((ShortcutManager) context.getSystemService(ShortcutManager.class)).pushDynamicShortcut(shortcut.toShortcutInfo());
        } else if (Build.VERSION.SDK_INT >= 25) {
            ShortcutManager sm = (ShortcutManager) context.getSystemService(ShortcutManager.class);
            if (sm.isRateLimitingActive()) {
                return false;
            }
            List<ShortcutInfo> shortcuts = sm.getDynamicShortcuts();
            if (shortcuts.size() >= maxShortcutCount) {
                sm.removeDynamicShortcuts(Arrays.asList(Api25Impl.getShortcutInfoWithLowestRank(shortcuts)));
            }
            sm.addDynamicShortcuts(Arrays.asList(shortcut.toShortcutInfo()));
        }
        ShortcutInfoCompatSaver<?> saver = getShortcutInfoSaverInstance(context);
        try {
            List<ShortcutInfoCompat> oldShortcuts = saver.getShortcuts();
            if (oldShortcuts.size() >= maxShortcutCount) {
                saver.removeShortcuts(Arrays.asList(getShortcutInfoCompatWithLowestRank(oldShortcuts)));
            }
            saver.addShortcuts(Arrays.asList(shortcut));
            for (ShortcutInfoChangeListener listener : getShortcutInfoListeners(context)) {
                listener.onShortcutAdded(Collections.singletonList(shortcut));
            }
            reportShortcutUsed(context, shortcut.getId());
            return true;
        } catch (Exception e) {
            for (ShortcutInfoChangeListener listener2 : getShortcutInfoListeners(context)) {
                listener2.onShortcutAdded(Collections.singletonList(shortcut));
            }
            reportShortcutUsed(context, shortcut.getId());
            return false;
        } catch (Throwable th) {
            for (ShortcutInfoChangeListener listener3 : getShortcutInfoListeners(context)) {
                listener3.onShortcutAdded(Collections.singletonList(shortcut));
            }
            reportShortcutUsed(context, shortcut.getId());
            throw th;
        }
    }

    private static String getShortcutInfoCompatWithLowestRank(List<ShortcutInfoCompat> shortcuts) {
        int rank = -1;
        String target = null;
        for (ShortcutInfoCompat s : shortcuts) {
            if (s.getRank() > rank) {
                target = s.getId();
                rank = s.getRank();
            }
        }
        return target;
    }

    static void setShortcutInfoCompatSaver(ShortcutInfoCompatSaver<Void> saver) {
        sShortcutInfoCompatSaver = saver;
    }

    static void setShortcutInfoChangeListeners(List<ShortcutInfoChangeListener> listeners) {
        sShortcutInfoChangeListeners = listeners;
    }

    static List<ShortcutInfoChangeListener> getShortcutInfoChangeListeners() {
        return sShortcutInfoChangeListeners;
    }

    private static int getIconDimensionInternal(Context context, boolean isHorizontal) {
        ActivityManager am = (ActivityManager) context.getSystemService("activity");
        boolean isLowRamDevice = Build.VERSION.SDK_INT < 19 || am == null || am.isLowRamDevice();
        int iconDimensionDp = Math.max(1, isLowRamDevice ? 48 : 96);
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        float density = (isHorizontal ? displayMetrics.xdpi : displayMetrics.ydpi) / 160.0f;
        return (int) (iconDimensionDp * density);
    }

    private static ShortcutInfoCompatSaver<?> getShortcutInfoSaverInstance(Context context) {
        if (sShortcutInfoCompatSaver == null) {
            if (Build.VERSION.SDK_INT >= 23) {
                try {
                    ClassLoader loader = ShortcutManagerCompat.class.getClassLoader();
                    Class<?> saver = Class.forName("androidx.sharetarget.ShortcutInfoCompatSaverImpl", false, loader);
                    Method getInstanceMethod = saver.getMethod("getInstance", Context.class);
                    sShortcutInfoCompatSaver = (ShortcutInfoCompatSaver) getInstanceMethod.invoke(null, context);
                } catch (Exception e) {
                }
            }
            if (sShortcutInfoCompatSaver == null) {
                sShortcutInfoCompatSaver = new ShortcutInfoCompatSaver.NoopImpl();
            }
        }
        return sShortcutInfoCompatSaver;
    }

    private static List<ShortcutInfoChangeListener> getShortcutInfoListeners(Context context) {
        Bundle metaData;
        String shortcutListenerImplName;
        if (sShortcutInfoChangeListeners == null) {
            List<ShortcutInfoChangeListener> result = new ArrayList<>();
            if (Build.VERSION.SDK_INT >= 21) {
                PackageManager packageManager = context.getPackageManager();
                Intent activityIntent = new Intent(SHORTCUT_LISTENER_INTENT_FILTER_ACTION);
                activityIntent.setPackage(context.getPackageName());
                List<ResolveInfo> resolveInfos = packageManager.queryIntentActivities(activityIntent, 128);
                for (ResolveInfo resolveInfo : resolveInfos) {
                    ActivityInfo activityInfo = resolveInfo.activityInfo;
                    if (activityInfo != null && (metaData = activityInfo.metaData) != null && (shortcutListenerImplName = metaData.getString(SHORTCUT_LISTENER_META_DATA_KEY)) != null) {
                        try {
                            ClassLoader loader = ShortcutManagerCompat.class.getClassLoader();
                            Class<?> listener = Class.forName(shortcutListenerImplName, false, loader);
                            Method getInstanceMethod = listener.getMethod("getInstance", Context.class);
                            result.add((ShortcutInfoChangeListener) getInstanceMethod.invoke(null, context));
                        } catch (Exception e) {
                        }
                    }
                }
            }
            if (sShortcutInfoChangeListeners == null) {
                sShortcutInfoChangeListeners = result;
            }
        }
        return sShortcutInfoChangeListeners;
    }

    /* loaded from: classes.dex */
    private static class Api25Impl {
        private Api25Impl() {
        }

        static String getShortcutInfoWithLowestRank(List<ShortcutInfo> shortcuts) {
            int rank = -1;
            String target = null;
            for (ShortcutInfo s : shortcuts) {
                if (s.getRank() > rank) {
                    target = s.getId();
                    rank = s.getRank();
                }
            }
            return target;
        }
    }
}
