package com.google.android.material.color;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.content.res.loader.ResourcesLoader;
import android.os.Build;
import android.view.ContextThemeWrapper;
import androidx.core.content.ContextCompat;
import com.google.android.material.R;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class HarmonizedColors {
    private static final String TAG = HarmonizedColors.class.getSimpleName();

    private HarmonizedColors() {
    }

    public static void applyToContextIfAvailable(Context context, HarmonizedColorsOptions options) {
        if (!isHarmonizedColorAvailable()) {
            return;
        }
        Map<Integer, Integer> colorReplacementMap = createHarmonizedColorReplacementMap(context, options);
        int themeOverlay = options.getThemeOverlayResourceId(0);
        if (addResourcesLoaderToContext(context, colorReplacementMap) && themeOverlay != 0) {
            ThemeUtils.applyThemeOverlay(context, themeOverlay);
        }
    }

    public static Context wrapContextIfAvailable(Context context, HarmonizedColorsOptions options) {
        if (!isHarmonizedColorAvailable()) {
            return context;
        }
        Map<Integer, Integer> colorReplacementMap = createHarmonizedColorReplacementMap(context, options);
        int themeOverlay = options.getThemeOverlayResourceId(R.style.ThemeOverlay_Material3_HarmonizedColors_Empty);
        ContextThemeWrapper themeWrapper = new ContextThemeWrapper(context, themeOverlay);
        themeWrapper.applyOverrideConfiguration(new Configuration());
        return addResourcesLoaderToContext(themeWrapper, colorReplacementMap) ? themeWrapper : context;
    }

    public static boolean isHarmonizedColorAvailable() {
        return Build.VERSION.SDK_INT >= 30;
    }

    private static Map<Integer, Integer> createHarmonizedColorReplacementMap(Context originalContext, HarmonizedColorsOptions options) {
        int[] colorResourceIds;
        TypedArray themeOverlayAttributesTypedArray;
        Map<Integer, Integer> colorReplacementMap = new HashMap<>();
        int colorToHarmonizeWith = MaterialColors.getColor(originalContext, options.getColorAttributeToHarmonizeWith(), TAG);
        for (int colorResourceId : options.getColorResourceIds()) {
            int harmonizedColor = MaterialColors.harmonize(ContextCompat.getColor(originalContext, colorResourceId), colorToHarmonizeWith);
            colorReplacementMap.put(Integer.valueOf(colorResourceId), Integer.valueOf(harmonizedColor));
        }
        HarmonizedColorAttributes colorAttributes = options.getColorAttributes();
        if (colorAttributes != null) {
            int[] attributes = colorAttributes.getAttributes();
            if (attributes.length > 0) {
                int themeOverlay = colorAttributes.getThemeOverlay();
                TypedArray themeAttributesTypedArray = originalContext.obtainStyledAttributes(attributes);
                if (themeOverlay != 0) {
                    themeOverlayAttributesTypedArray = new ContextThemeWrapper(originalContext, themeOverlay).obtainStyledAttributes(attributes);
                } else {
                    themeOverlayAttributesTypedArray = null;
                }
                addHarmonizedColorAttributesToReplacementMap(colorReplacementMap, themeAttributesTypedArray, themeOverlayAttributesTypedArray, colorToHarmonizeWith);
                themeAttributesTypedArray.recycle();
                if (themeOverlayAttributesTypedArray != null) {
                    themeOverlayAttributesTypedArray.recycle();
                }
            }
        }
        return colorReplacementMap;
    }

    private static boolean addResourcesLoaderToContext(Context context, Map<Integer, Integer> colorReplacementMap) {
        ResourcesLoader resourcesLoader = ColorResourcesLoaderCreator.create(context, colorReplacementMap);
        if (resourcesLoader == null) {
            return false;
        }
        context.getResources().addLoaders(resourcesLoader);
        return true;
    }

    private static void addHarmonizedColorAttributesToReplacementMap(Map<Integer, Integer> colorReplacementMap, TypedArray themeAttributesTypedArray, TypedArray themeOverlayAttributesTypedArray, int colorToHarmonizeWith) {
        TypedArray resourceIdTypedArray;
        if (themeOverlayAttributesTypedArray != null) {
            resourceIdTypedArray = themeOverlayAttributesTypedArray;
        } else {
            resourceIdTypedArray = themeAttributesTypedArray;
        }
        for (int i = 0; i < themeAttributesTypedArray.getIndexCount(); i++) {
            int resourceId = resourceIdTypedArray.getResourceId(i, 0);
            if (resourceId != 0 && themeAttributesTypedArray.hasValue(i) && isColorResource(themeAttributesTypedArray.getType(i))) {
                int colorToHarmonize = themeAttributesTypedArray.getColor(i, 0);
                colorReplacementMap.put(Integer.valueOf(resourceId), Integer.valueOf(MaterialColors.harmonize(colorToHarmonize, colorToHarmonizeWith)));
            }
        }
    }

    private static boolean isColorResource(int attrType) {
        return 28 <= attrType && attrType <= 31;
    }
}
