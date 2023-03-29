package com.google.android.material.elevation;

import android.content.Context;
import com.google.android.material.R;
import com.google.android.material.color.MaterialColors;
/* loaded from: classes.dex */
public enum SurfaceColors {
    SURFACE_0(R.dimen.m3_sys_elevation_level0),
    SURFACE_1(R.dimen.m3_sys_elevation_level1),
    SURFACE_2(R.dimen.m3_sys_elevation_level2),
    SURFACE_3(R.dimen.m3_sys_elevation_level3),
    SURFACE_4(R.dimen.m3_sys_elevation_level4),
    SURFACE_5(R.dimen.m3_sys_elevation_level5);
    
    private final int elevationResId;

    SurfaceColors(int elevationResId) {
        this.elevationResId = elevationResId;
    }

    public int getColor(Context context) {
        return getColorForElevation(context, context.getResources().getDimension(this.elevationResId));
    }

    public static int getColorForElevation(Context context, float elevation) {
        return new ElevationOverlayProvider(context).compositeOverlay(MaterialColors.getColor(context, R.attr.colorSurface, 0), elevation);
    }
}
