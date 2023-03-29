package com.google.android.material.progressindicator;

import android.content.ContentResolver;
import android.os.Build;
import android.provider.Settings;
/* loaded from: classes.dex */
public class AnimatorDurationScaleProvider {
    private static float defaultSystemAnimatorDurationScale = 1.0f;

    public float getSystemAnimatorDurationScale(ContentResolver contentResolver) {
        if (Build.VERSION.SDK_INT >= 17) {
            return Settings.Global.getFloat(contentResolver, "animator_duration_scale", 1.0f);
        }
        if (Build.VERSION.SDK_INT == 16) {
            return Settings.System.getFloat(contentResolver, "animator_duration_scale", 1.0f);
        }
        return defaultSystemAnimatorDurationScale;
    }

    public static void setDefaultSystemAnimatorDurationScale(float scale) {
        defaultSystemAnimatorDurationScale = scale;
    }
}
