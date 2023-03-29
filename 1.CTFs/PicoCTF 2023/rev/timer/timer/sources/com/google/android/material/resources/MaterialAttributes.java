package com.google.android.material.resources;

import android.content.Context;
import android.util.TypedValue;
import android.view.View;
import com.google.android.material.R;
/* loaded from: classes.dex */
public class MaterialAttributes {
    public static TypedValue resolve(Context context, int attributeResId) {
        TypedValue typedValue = new TypedValue();
        if (context.getTheme().resolveAttribute(attributeResId, typedValue, true)) {
            return typedValue;
        }
        return null;
    }

    public static int resolveOrThrow(Context context, int attributeResId, String errorMessageComponent) {
        TypedValue typedValue = resolve(context, attributeResId);
        if (typedValue == null) {
            throw new IllegalArgumentException(String.format("%1$s requires a value for the %2$s attribute to be set in your app theme. You can either set the attribute in your theme or update your theme to inherit from Theme.MaterialComponents (or a descendant).", errorMessageComponent, context.getResources().getResourceName(attributeResId)));
        }
        return typedValue.data;
    }

    public static int resolveOrThrow(View componentView, int attributeResId) {
        return resolveOrThrow(componentView.getContext(), attributeResId, componentView.getClass().getCanonicalName());
    }

    public static boolean resolveBooleanOrThrow(Context context, int attributeResId, String errorMessageComponent) {
        return resolveOrThrow(context, attributeResId, errorMessageComponent) != 0;
    }

    public static boolean resolveBoolean(Context context, int attributeResId, boolean defaultValue) {
        TypedValue typedValue = resolve(context, attributeResId);
        if (typedValue == null || typedValue.type != 18) {
            return defaultValue;
        }
        return typedValue.data != 0;
    }

    public static int resolveInteger(Context context, int attributeResId, int defaultValue) {
        TypedValue typedValue = resolve(context, attributeResId);
        if (typedValue != null && typedValue.type == 16) {
            return typedValue.data;
        }
        return defaultValue;
    }

    public static int resolveMinimumAccessibleTouchTarget(Context context) {
        return resolveDimension(context, R.attr.minTouchTargetSize, R.dimen.mtrl_min_touch_target_size);
    }

    public static int resolveDimension(Context context, int attributeResId, int defaultDimenResId) {
        TypedValue dimensionValue = resolve(context, attributeResId);
        if (dimensionValue == null || dimensionValue.type != 5) {
            return (int) context.getResources().getDimension(defaultDimenResId);
        }
        return (int) dimensionValue.getDimension(context.getResources().getDisplayMetrics());
    }
}
