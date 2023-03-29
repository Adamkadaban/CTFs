package androidx.core.content;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import androidx.core.util.Preconditions;
/* loaded from: classes.dex */
public final class IntentCompat {
    public static final String ACTION_CREATE_REMINDER = "android.intent.action.CREATE_REMINDER";
    public static final String CATEGORY_LEANBACK_LAUNCHER = "android.intent.category.LEANBACK_LAUNCHER";
    public static final String EXTRA_HTML_TEXT = "android.intent.extra.HTML_TEXT";
    public static final String EXTRA_START_PLAYBACK = "android.intent.extra.START_PLAYBACK";
    public static final String EXTRA_TIME = "android.intent.extra.TIME";

    private IntentCompat() {
    }

    public static Intent makeMainSelectorActivity(String selectorAction, String selectorCategory) {
        if (Build.VERSION.SDK_INT >= 15) {
            return Intent.makeMainSelectorActivity(selectorAction, selectorCategory);
        }
        Intent intent = new Intent(selectorAction);
        intent.addCategory(selectorCategory);
        return intent;
    }

    public static Intent createManageUnusedAppRestrictionsIntent(Context context, String packageName) {
        if (!PackageManagerCompat.areUnusedAppRestrictionsAvailable(context.getPackageManager())) {
            throw new UnsupportedOperationException("Unused App Restriction features are not available on this device");
        }
        if (Build.VERSION.SDK_INT >= 31) {
            return new Intent("android.settings.APPLICATION_DETAILS_SETTINGS").setData(Uri.fromParts("package", packageName, null));
        }
        Intent permissionRevocationSettingsIntent = new Intent(PackageManagerCompat.ACTION_PERMISSION_REVOCATION_SETTINGS).setData(Uri.fromParts("package", packageName, null));
        if (Build.VERSION.SDK_INT >= 30) {
            return permissionRevocationSettingsIntent;
        }
        String verifierPackageName = PackageManagerCompat.getPermissionRevocationVerifierApp(context.getPackageManager());
        return permissionRevocationSettingsIntent.setPackage((String) Preconditions.checkNotNull(verifierPackageName));
    }
}
