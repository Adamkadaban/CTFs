package com.google.android.material.elevation;

import android.content.Context;
import android.graphics.Color;
import android.view.View;
import androidx.core.graphics.ColorUtils;
import com.google.android.material.R;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialAttributes;
/* loaded from: classes.dex */
public class ElevationOverlayProvider {
    private static final float FORMULA_MULTIPLIER = 4.5f;
    private static final float FORMULA_OFFSET = 2.0f;
    private static final int OVERLAY_ACCENT_COLOR_ALPHA = (int) Math.round(5.1000000000000005d);
    private final int colorSurface;
    private final float displayDensity;
    private final int elevationOverlayAccentColor;
    private final int elevationOverlayColor;
    private final boolean elevationOverlayEnabled;

    public ElevationOverlayProvider(Context context) {
        this(MaterialAttributes.resolveBoolean(context, R.attr.elevationOverlayEnabled, false), MaterialColors.getColor(context, R.attr.elevationOverlayColor, 0), MaterialColors.getColor(context, R.attr.elevationOverlayAccentColor, 0), MaterialColors.getColor(context, R.attr.colorSurface, 0), context.getResources().getDisplayMetrics().density);
    }

    public ElevationOverlayProvider(boolean elevationOverlayEnabled, int elevationOverlayColor, int elevationOverlayAccentColor, int colorSurface, float displayDensity) {
        this.elevationOverlayEnabled = elevationOverlayEnabled;
        this.elevationOverlayColor = elevationOverlayColor;
        this.elevationOverlayAccentColor = elevationOverlayAccentColor;
        this.colorSurface = colorSurface;
        this.displayDensity = displayDensity;
    }

    public int compositeOverlayWithThemeSurfaceColorIfNeeded(float elevation, View overlayView) {
        return compositeOverlayWithThemeSurfaceColorIfNeeded(elevation + getParentAbsoluteElevation(overlayView));
    }

    public int compositeOverlayWithThemeSurfaceColorIfNeeded(float elevation) {
        return compositeOverlayIfNeeded(this.colorSurface, elevation);
    }

    public int compositeOverlayIfNeeded(int backgroundColor, float elevation, View overlayView) {
        return compositeOverlayIfNeeded(backgroundColor, elevation + getParentAbsoluteElevation(overlayView));
    }

    public int compositeOverlayIfNeeded(int backgroundColor, float elevation) {
        if (this.elevationOverlayEnabled && isThemeSurfaceColor(backgroundColor)) {
            return compositeOverlay(backgroundColor, elevation);
        }
        return backgroundColor;
    }

    public int compositeOverlay(int backgroundColor, float elevation, View overlayView) {
        return compositeOverlay(backgroundColor, elevation + getParentAbsoluteElevation(overlayView));
    }

    public int compositeOverlay(int backgroundColor, float elevation) {
        int i;
        float overlayAlphaFraction = calculateOverlayAlphaFraction(elevation);
        int backgroundAlpha = Color.alpha(backgroundColor);
        int backgroundColorOpaque = ColorUtils.setAlphaComponent(backgroundColor, 255);
        int overlayColorOpaque = MaterialColors.layer(backgroundColorOpaque, this.elevationOverlayColor, overlayAlphaFraction);
        if (overlayAlphaFraction > 0.0f && (i = this.elevationOverlayAccentColor) != 0) {
            int overlayAccentColor = ColorUtils.setAlphaComponent(i, OVERLAY_ACCENT_COLOR_ALPHA);
            overlayColorOpaque = MaterialColors.layer(overlayColorOpaque, overlayAccentColor);
        }
        int overlayAccentColor2 = ColorUtils.setAlphaComponent(overlayColorOpaque, backgroundAlpha);
        return overlayAccentColor2;
    }

    public int calculateOverlayAlpha(float elevation) {
        return Math.round(calculateOverlayAlphaFraction(elevation) * 255.0f);
    }

    public float calculateOverlayAlphaFraction(float elevation) {
        float f = this.displayDensity;
        if (f <= 0.0f || elevation <= 0.0f) {
            return 0.0f;
        }
        float elevationDp = elevation / f;
        float alphaFraction = ((((float) Math.log1p(elevationDp)) * FORMULA_MULTIPLIER) + FORMULA_OFFSET) / 100.0f;
        return Math.min(alphaFraction, 1.0f);
    }

    public boolean isThemeElevationOverlayEnabled() {
        return this.elevationOverlayEnabled;
    }

    public int getThemeElevationOverlayColor() {
        return this.elevationOverlayColor;
    }

    public int getThemeSurfaceColor() {
        return this.colorSurface;
    }

    public float getParentAbsoluteElevation(View overlayView) {
        return ViewUtils.getParentAbsoluteElevation(overlayView);
    }

    private boolean isThemeSurfaceColor(int color) {
        return ColorUtils.setAlphaComponent(color, 255) == this.colorSurface;
    }
}
