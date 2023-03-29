package com.google.android.material.resources;
@Deprecated
/* loaded from: classes.dex */
public class TextAppearanceConfig {
    private static boolean shouldLoadFontSynchronously;

    public static void setShouldLoadFontSynchronously(boolean flag) {
        shouldLoadFontSynchronously = flag;
    }

    public static boolean shouldLoadFontSynchronously() {
        return shouldLoadFontSynchronously;
    }
}
