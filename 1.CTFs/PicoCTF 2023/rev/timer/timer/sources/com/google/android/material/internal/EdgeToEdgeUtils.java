package com.google.android.material.internal;

import android.content.Context;
import android.os.Build;
import android.view.Window;
import androidx.core.graphics.ColorUtils;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import com.google.android.material.color.MaterialColors;
/* loaded from: classes.dex */
public class EdgeToEdgeUtils {
    private static final int EDGE_TO_EDGE_BAR_ALPHA = 128;

    private EdgeToEdgeUtils() {
    }

    public static void applyEdgeToEdge(Window window, boolean edgeToEdgeEnabled) {
        applyEdgeToEdge(window, edgeToEdgeEnabled, null, null);
    }

    public static void applyEdgeToEdge(Window window, boolean edgeToEdgeEnabled, Integer statusBarOverlapBackgroundColor, Integer navigationBarOverlapBackgroundColor) {
        if (Build.VERSION.SDK_INT < 21) {
            return;
        }
        boolean useDefaultBackgroundColorForNavigationBar = false;
        boolean useDefaultBackgroundColorForStatusBar = statusBarOverlapBackgroundColor == null || statusBarOverlapBackgroundColor.intValue() == 0;
        useDefaultBackgroundColorForNavigationBar = (navigationBarOverlapBackgroundColor == null || navigationBarOverlapBackgroundColor.intValue() == 0) ? true : true;
        if (useDefaultBackgroundColorForStatusBar || useDefaultBackgroundColorForNavigationBar) {
            int defaultBackgroundColor = MaterialColors.getColor(window.getContext(), 16842801, (int) ViewCompat.MEASURED_STATE_MASK);
            if (useDefaultBackgroundColorForStatusBar) {
                statusBarOverlapBackgroundColor = Integer.valueOf(defaultBackgroundColor);
            }
            if (useDefaultBackgroundColorForNavigationBar) {
                navigationBarOverlapBackgroundColor = Integer.valueOf(defaultBackgroundColor);
            }
        }
        WindowCompat.setDecorFitsSystemWindows(window, !edgeToEdgeEnabled);
        int statusBarColor = getStatusBarColor(window.getContext(), edgeToEdgeEnabled);
        int navigationBarColor = getNavigationBarColor(window.getContext(), edgeToEdgeEnabled);
        window.setStatusBarColor(statusBarColor);
        window.setNavigationBarColor(navigationBarColor);
        boolean isLightStatusBar = isUsingLightSystemBar(statusBarColor, MaterialColors.isColorLight(statusBarOverlapBackgroundColor.intValue()));
        boolean isLightNavigationBar = isUsingLightSystemBar(navigationBarColor, MaterialColors.isColorLight(navigationBarOverlapBackgroundColor.intValue()));
        WindowInsetsControllerCompat insetsController = WindowCompat.getInsetsController(window, window.getDecorView());
        if (insetsController != null) {
            insetsController.setAppearanceLightStatusBars(isLightStatusBar);
            insetsController.setAppearanceLightNavigationBars(isLightNavigationBar);
        }
    }

    private static int getStatusBarColor(Context context, boolean isEdgeToEdgeEnabled) {
        if (isEdgeToEdgeEnabled && Build.VERSION.SDK_INT < 23) {
            int opaqueStatusBarColor = MaterialColors.getColor(context, 16843857, (int) ViewCompat.MEASURED_STATE_MASK);
            return ColorUtils.setAlphaComponent(opaqueStatusBarColor, 128);
        } else if (isEdgeToEdgeEnabled) {
            return 0;
        } else {
            return MaterialColors.getColor(context, 16843857, (int) ViewCompat.MEASURED_STATE_MASK);
        }
    }

    private static int getNavigationBarColor(Context context, boolean isEdgeToEdgeEnabled) {
        if (isEdgeToEdgeEnabled && Build.VERSION.SDK_INT < 27) {
            int opaqueNavBarColor = MaterialColors.getColor(context, 16843858, (int) ViewCompat.MEASURED_STATE_MASK);
            return ColorUtils.setAlphaComponent(opaqueNavBarColor, 128);
        } else if (isEdgeToEdgeEnabled) {
            return 0;
        } else {
            return MaterialColors.getColor(context, 16843858, (int) ViewCompat.MEASURED_STATE_MASK);
        }
    }

    private static boolean isUsingLightSystemBar(int systemBarColor, boolean isLightBackground) {
        return MaterialColors.isColorLight(systemBarColor) || (systemBarColor == 0 && isLightBackground);
    }
}
