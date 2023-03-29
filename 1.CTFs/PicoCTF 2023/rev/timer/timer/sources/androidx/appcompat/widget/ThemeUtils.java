package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import androidx.appcompat.R;
import androidx.core.graphics.ColorUtils;
/* loaded from: classes.dex */
public class ThemeUtils {
    private static final String TAG = "ThemeUtils";
    private static final ThreadLocal<TypedValue> TL_TYPED_VALUE = new ThreadLocal<>();
    static final int[] DISABLED_STATE_SET = {-16842910};
    static final int[] FOCUSED_STATE_SET = {16842908};
    static final int[] ACTIVATED_STATE_SET = {16843518};
    static final int[] PRESSED_STATE_SET = {16842919};
    static final int[] CHECKED_STATE_SET = {16842912};
    static final int[] SELECTED_STATE_SET = {16842913};
    static final int[] NOT_PRESSED_OR_FOCUSED_STATE_SET = {-16842919, -16842908};
    static final int[] EMPTY_STATE_SET = new int[0];
    private static final int[] TEMP_ARRAY = new int[1];

    public static ColorStateList createDisabledStateList(int textColor, int disabledTextColor) {
        int[][] states = new int[2];
        int[] colors = new int[2];
        states[0] = DISABLED_STATE_SET;
        colors[0] = disabledTextColor;
        int i = 0 + 1;
        states[i] = EMPTY_STATE_SET;
        colors[i] = textColor;
        int i2 = i + 1;
        return new ColorStateList(states, colors);
    }

    public static int getThemeAttrColor(Context context, int attr) {
        int[] iArr = TEMP_ARRAY;
        iArr[0] = attr;
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, (AttributeSet) null, iArr);
        try {
            return a.getColor(0, 0);
        } finally {
            a.recycle();
        }
    }

    public static ColorStateList getThemeAttrColorStateList(Context context, int attr) {
        int[] iArr = TEMP_ARRAY;
        iArr[0] = attr;
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, (AttributeSet) null, iArr);
        try {
            return a.getColorStateList(0);
        } finally {
            a.recycle();
        }
    }

    public static int getDisabledThemeAttrColor(Context context, int attr) {
        ColorStateList csl = getThemeAttrColorStateList(context, attr);
        if (csl != null && csl.isStateful()) {
            return csl.getColorForState(DISABLED_STATE_SET, csl.getDefaultColor());
        }
        TypedValue tv = getTypedValue();
        context.getTheme().resolveAttribute(16842803, tv, true);
        float disabledAlpha = tv.getFloat();
        return getThemeAttrColor(context, attr, disabledAlpha);
    }

    private static TypedValue getTypedValue() {
        ThreadLocal<TypedValue> threadLocal = TL_TYPED_VALUE;
        TypedValue typedValue = threadLocal.get();
        if (typedValue == null) {
            TypedValue typedValue2 = new TypedValue();
            threadLocal.set(typedValue2);
            return typedValue2;
        }
        return typedValue;
    }

    static int getThemeAttrColor(Context context, int attr, float alpha) {
        int color = getThemeAttrColor(context, attr);
        int originalAlpha = Color.alpha(color);
        return ColorUtils.setAlphaComponent(color, Math.round(originalAlpha * alpha));
    }

    public static void checkAppCompatTheme(View view, Context context) {
        TypedArray a = context.obtainStyledAttributes(R.styleable.AppCompatTheme);
        try {
            if (!a.hasValue(R.styleable.AppCompatTheme_windowActionBar)) {
                Log.e(TAG, "View " + view.getClass() + " is an AppCompat widget that can only be used with a Theme.AppCompat theme (or descendant).");
            }
        } finally {
            a.recycle();
        }
    }

    private ThemeUtils() {
    }
}
