package androidx.core.content.res;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.TypedValue;
import org.xmlpull.v1.XmlPullParser;
/* loaded from: classes.dex */
public class TypedArrayUtils {
    private static final String NAMESPACE = "http://schemas.android.com/apk/res/android";

    public static boolean hasAttribute(XmlPullParser parser, String attrName) {
        return parser.getAttributeValue(NAMESPACE, attrName) != null;
    }

    public static float getNamedFloat(TypedArray a, XmlPullParser parser, String attrName, int resId, float defaultValue) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return defaultValue;
        }
        return a.getFloat(resId, defaultValue);
    }

    public static boolean getNamedBoolean(TypedArray a, XmlPullParser parser, String attrName, int resId, boolean defaultValue) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return defaultValue;
        }
        return a.getBoolean(resId, defaultValue);
    }

    public static int getNamedInt(TypedArray a, XmlPullParser parser, String attrName, int resId, int defaultValue) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return defaultValue;
        }
        return a.getInt(resId, defaultValue);
    }

    public static int getNamedColor(TypedArray a, XmlPullParser parser, String attrName, int resId, int defaultValue) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return defaultValue;
        }
        return a.getColor(resId, defaultValue);
    }

    public static ComplexColorCompat getNamedComplexColor(TypedArray a, XmlPullParser parser, Resources.Theme theme, String attrName, int resId, int defaultValue) {
        if (hasAttribute(parser, attrName)) {
            TypedValue value = new TypedValue();
            a.getValue(resId, value);
            if (value.type >= 28 && value.type <= 31) {
                return ComplexColorCompat.from(value.data);
            }
            ComplexColorCompat complexColor = ComplexColorCompat.inflate(a.getResources(), a.getResourceId(resId, 0), theme);
            if (complexColor != null) {
                return complexColor;
            }
        }
        return ComplexColorCompat.from(defaultValue);
    }

    public static ColorStateList getNamedColorStateList(TypedArray a, XmlPullParser parser, Resources.Theme theme, String attrName, int resId) {
        if (hasAttribute(parser, attrName)) {
            TypedValue value = new TypedValue();
            a.getValue(resId, value);
            if (value.type == 2) {
                throw new UnsupportedOperationException("Failed to resolve attribute at index " + resId + ": " + value);
            } else if (value.type >= 28 && value.type <= 31) {
                return getNamedColorStateListFromInt(value);
            } else {
                return ColorStateListInflaterCompat.inflate(a.getResources(), a.getResourceId(resId, 0), theme);
            }
        }
        return null;
    }

    private static ColorStateList getNamedColorStateListFromInt(TypedValue value) {
        return ColorStateList.valueOf(value.data);
    }

    public static int getNamedResourceId(TypedArray a, XmlPullParser parser, String attrName, int resId, int defaultValue) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return defaultValue;
        }
        return a.getResourceId(resId, defaultValue);
    }

    public static String getNamedString(TypedArray a, XmlPullParser parser, String attrName, int resId) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return null;
        }
        return a.getString(resId);
    }

    public static TypedValue peekNamedValue(TypedArray a, XmlPullParser parser, String attrName, int resId) {
        boolean hasAttr = hasAttribute(parser, attrName);
        if (!hasAttr) {
            return null;
        }
        return a.peekValue(resId);
    }

    public static TypedArray obtainAttributes(Resources res, Resources.Theme theme, AttributeSet set, int[] attrs) {
        if (theme == null) {
            return res.obtainAttributes(set, attrs);
        }
        return theme.obtainStyledAttributes(set, attrs, 0, 0);
    }

    public static boolean getBoolean(TypedArray a, int index, int fallbackIndex, boolean defaultValue) {
        boolean val = a.getBoolean(fallbackIndex, defaultValue);
        return a.getBoolean(index, val);
    }

    public static Drawable getDrawable(TypedArray a, int index, int fallbackIndex) {
        Drawable val = a.getDrawable(index);
        if (val == null) {
            return a.getDrawable(fallbackIndex);
        }
        return val;
    }

    public static int getInt(TypedArray a, int index, int fallbackIndex, int defaultValue) {
        int val = a.getInt(fallbackIndex, defaultValue);
        return a.getInt(index, val);
    }

    public static int getResourceId(TypedArray a, int index, int fallbackIndex, int defaultValue) {
        int val = a.getResourceId(fallbackIndex, defaultValue);
        return a.getResourceId(index, val);
    }

    public static String getString(TypedArray a, int index, int fallbackIndex) {
        String val = a.getString(index);
        if (val == null) {
            return a.getString(fallbackIndex);
        }
        return val;
    }

    public static CharSequence getText(TypedArray a, int index, int fallbackIndex) {
        CharSequence val = a.getText(index);
        if (val == null) {
            return a.getText(fallbackIndex);
        }
        return val;
    }

    public static CharSequence[] getTextArray(TypedArray a, int index, int fallbackIndex) {
        CharSequence[] val = a.getTextArray(index);
        if (val == null) {
            return a.getTextArray(fallbackIndex);
        }
        return val;
    }

    public static int getAttr(Context context, int attr, int fallbackAttr) {
        TypedValue value = new TypedValue();
        context.getTheme().resolveAttribute(attr, value, true);
        if (value.resourceId != 0) {
            return attr;
        }
        return fallbackAttr;
    }

    private TypedArrayUtils() {
    }
}
