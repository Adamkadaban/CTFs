package com.google.android.material.switchmaterial;

import android.content.Context;
import android.content.res.ColorStateList;
import android.util.AttributeSet;
import androidx.appcompat.widget.SwitchCompat;
import com.google.android.material.R;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.elevation.ElevationOverlayProvider;
import com.google.android.material.internal.ViewUtils;
/* loaded from: classes.dex */
public class SwitchMaterial extends SwitchCompat {
    private static final int DEF_STYLE_RES = R.style.Widget_MaterialComponents_CompoundButton_Switch;
    private static final int[][] ENABLED_CHECKED_STATES = {new int[]{16842910, 16842912}, new int[]{16842910, -16842912}, new int[]{-16842910, 16842912}, new int[]{-16842910, -16842912}};
    private final ElevationOverlayProvider elevationOverlayProvider;
    private ColorStateList materialThemeColorsThumbTintList;
    private ColorStateList materialThemeColorsTrackTintList;
    private boolean useMaterialThemeColors;

    public SwitchMaterial(Context context) {
        this(context, null);
    }

    public SwitchMaterial(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.switchStyle);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public SwitchMaterial(android.content.Context r8, android.util.AttributeSet r9, int r10) {
        /*
            r7 = this;
            int r4 = com.google.android.material.switchmaterial.SwitchMaterial.DEF_STYLE_RES
            android.content.Context r0 = com.google.android.material.theme.overlay.MaterialThemeOverlay.wrap(r8, r9, r10, r4)
            r7.<init>(r0, r9, r10)
            android.content.Context r8 = r7.getContext()
            com.google.android.material.elevation.ElevationOverlayProvider r0 = new com.google.android.material.elevation.ElevationOverlayProvider
            r0.<init>(r8)
            r7.elevationOverlayProvider = r0
            int[] r2 = com.google.android.material.R.styleable.SwitchMaterial
            r6 = 0
            int[] r5 = new int[r6]
            r0 = r8
            r1 = r9
            r3 = r10
            android.content.res.TypedArray r0 = com.google.android.material.internal.ThemeEnforcement.obtainStyledAttributes(r0, r1, r2, r3, r4, r5)
            int r1 = com.google.android.material.R.styleable.SwitchMaterial_useMaterialThemeColors
            boolean r1 = r0.getBoolean(r1, r6)
            r7.useMaterialThemeColors = r1
            r0.recycle()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.switchmaterial.SwitchMaterial.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }

    @Override // android.widget.TextView, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.useMaterialThemeColors && getThumbTintList() == null) {
            setThumbTintList(getMaterialThemeColorsThumbTintList());
        }
        if (this.useMaterialThemeColors && getTrackTintList() == null) {
            setTrackTintList(getMaterialThemeColorsTrackTintList());
        }
    }

    public void setUseMaterialThemeColors(boolean useMaterialThemeColors) {
        this.useMaterialThemeColors = useMaterialThemeColors;
        if (useMaterialThemeColors) {
            setThumbTintList(getMaterialThemeColorsThumbTintList());
            setTrackTintList(getMaterialThemeColorsTrackTintList());
            return;
        }
        setThumbTintList(null);
        setTrackTintList(null);
    }

    public boolean isUseMaterialThemeColors() {
        return this.useMaterialThemeColors;
    }

    private ColorStateList getMaterialThemeColorsThumbTintList() {
        if (this.materialThemeColorsThumbTintList == null) {
            int colorSurface = MaterialColors.getColor(this, R.attr.colorSurface);
            int colorControlActivated = MaterialColors.getColor(this, R.attr.colorControlActivated);
            float thumbElevation = getResources().getDimension(R.dimen.mtrl_switch_thumb_elevation);
            if (this.elevationOverlayProvider.isThemeElevationOverlayEnabled()) {
                thumbElevation += ViewUtils.getParentAbsoluteElevation(this);
            }
            int colorThumbOff = this.elevationOverlayProvider.compositeOverlayIfNeeded(colorSurface, thumbElevation);
            int[][] iArr = ENABLED_CHECKED_STATES;
            int[] switchThumbColorsList = new int[iArr.length];
            switchThumbColorsList[0] = MaterialColors.layer(colorSurface, colorControlActivated, 1.0f);
            switchThumbColorsList[1] = colorThumbOff;
            switchThumbColorsList[2] = MaterialColors.layer(colorSurface, colorControlActivated, 0.38f);
            switchThumbColorsList[3] = colorThumbOff;
            this.materialThemeColorsThumbTintList = new ColorStateList(iArr, switchThumbColorsList);
        }
        return this.materialThemeColorsThumbTintList;
    }

    private ColorStateList getMaterialThemeColorsTrackTintList() {
        if (this.materialThemeColorsTrackTintList == null) {
            int[][] iArr = ENABLED_CHECKED_STATES;
            int[] switchTrackColorsList = new int[iArr.length];
            int colorSurface = MaterialColors.getColor(this, R.attr.colorSurface);
            int colorControlActivated = MaterialColors.getColor(this, R.attr.colorControlActivated);
            int colorOnSurface = MaterialColors.getColor(this, R.attr.colorOnSurface);
            switchTrackColorsList[0] = MaterialColors.layer(colorSurface, colorControlActivated, 0.54f);
            switchTrackColorsList[1] = MaterialColors.layer(colorSurface, colorOnSurface, 0.32f);
            switchTrackColorsList[2] = MaterialColors.layer(colorSurface, colorControlActivated, 0.12f);
            switchTrackColorsList[3] = MaterialColors.layer(colorSurface, colorOnSurface, 0.12f);
            this.materialThemeColorsTrackTintList = new ColorStateList(iArr, switchTrackColorsList);
        }
        return this.materialThemeColorsTrackTintList;
    }
}
