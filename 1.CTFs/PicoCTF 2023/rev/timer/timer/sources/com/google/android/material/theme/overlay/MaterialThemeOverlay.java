package com.google.android.material.theme.overlay;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.view.ContextThemeWrapper;
import com.google.android.material.R;
/* loaded from: classes.dex */
public class MaterialThemeOverlay {
    private static final int[] ANDROID_THEME_OVERLAY_ATTRS = {16842752, R.attr.theme};
    private static final int[] MATERIAL_THEME_OVERLAY_ATTR = {R.attr.materialThemeOverlay};

    private MaterialThemeOverlay() {
    }

    public static Context wrap(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        int materialThemeOverlayId = obtainMaterialThemeOverlayId(context, attrs, defStyleAttr, defStyleRes);
        boolean contextHasOverlay = (context instanceof ContextThemeWrapper) && ((ContextThemeWrapper) context).getThemeResId() == materialThemeOverlayId;
        if (materialThemeOverlayId == 0 || contextHasOverlay) {
            return context;
        }
        Context contextThemeWrapper = new ContextThemeWrapper(context, materialThemeOverlayId);
        int androidThemeOverlayId = obtainAndroidThemeOverlayId(context, attrs);
        if (androidThemeOverlayId != 0) {
            contextThemeWrapper.getTheme().applyStyle(androidThemeOverlayId, true);
        }
        return contextThemeWrapper;
    }

    private static int obtainAndroidThemeOverlayId(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, ANDROID_THEME_OVERLAY_ATTRS);
        int androidThemeId = a.getResourceId(0, 0);
        int appThemeId = a.getResourceId(1, 0);
        a.recycle();
        return androidThemeId != 0 ? androidThemeId : appThemeId;
    }

    private static int obtainMaterialThemeOverlayId(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        TypedArray a = context.obtainStyledAttributes(attrs, MATERIAL_THEME_OVERLAY_ATTR, defStyleAttr, defStyleRes);
        int materialThemeOverlayId = a.getResourceId(0, 0);
        a.recycle();
        return materialThemeOverlayId;
    }
}
