package com.google.android.material.color;

import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import android.view.View;
import android.view.Window;
/* loaded from: classes.dex */
final class ThemeUtils {
    private ThemeUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void applyThemeOverlay(Context context, int theme) {
        Resources.Theme windowDecorViewTheme;
        context.getTheme().applyStyle(theme, true);
        if ((context instanceof Activity) && (windowDecorViewTheme = getWindowDecorViewTheme((Activity) context)) != null) {
            windowDecorViewTheme.applyStyle(theme, true);
        }
    }

    private static Resources.Theme getWindowDecorViewTheme(Activity activity) {
        View decorView;
        Context context;
        Window window = activity.getWindow();
        if (window != null && (decorView = window.peekDecorView()) != null && (context = decorView.getContext()) != null) {
            return context.getTheme();
        }
        return null;
    }
}
