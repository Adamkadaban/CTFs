package androidx.core.content.res;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.util.AttributeSet;
import android.util.Log;
import android.util.StateSet;
import android.util.TypedValue;
import android.util.Xml;
import androidx.core.R;
import androidx.core.math.MathUtils;
import androidx.core.os.BuildCompat;
import java.io.IOException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
/* loaded from: classes.dex */
public final class ColorStateListInflaterCompat {
    private static final ThreadLocal<TypedValue> sTempTypedValue = new ThreadLocal<>();

    private ColorStateListInflaterCompat() {
    }

    public static ColorStateList inflate(Resources resources, int resId, Resources.Theme theme) {
        try {
            XmlPullParser parser = resources.getXml(resId);
            return createFromXml(resources, parser, theme);
        } catch (Exception e) {
            Log.e("CSLCompat", "Failed to inflate ColorStateList.", e);
            return null;
        }
    }

    public static ColorStateList createFromXml(Resources r, XmlPullParser parser, Resources.Theme theme) throws XmlPullParserException, IOException {
        int type;
        AttributeSet attrs = Xml.asAttributeSet(parser);
        do {
            type = parser.next();
            if (type == 2) {
                break;
            }
        } while (type != 1);
        if (type != 2) {
            throw new XmlPullParserException("No start tag found");
        }
        return createFromXmlInner(r, parser, attrs, theme);
    }

    public static ColorStateList createFromXmlInner(Resources r, XmlPullParser parser, AttributeSet attrs, Resources.Theme theme) throws XmlPullParserException, IOException {
        String name = parser.getName();
        if (!name.equals("selector")) {
            throw new XmlPullParserException(parser.getPositionDescription() + ": invalid color state list tag " + name);
        }
        return inflate(r, parser, attrs, theme);
    }

    private static ColorStateList inflate(Resources r, XmlPullParser parser, AttributeSet attrs, Resources.Theme theme) throws XmlPullParserException, IOException {
        int depth;
        int innerDepth;
        int baseColor;
        float lStar;
        Resources resources = r;
        Resources.Theme theme2 = theme;
        int i = 1;
        int innerDepth2 = parser.getDepth() + 1;
        int[][] stateSpecList = new int[20];
        int[] colorList = new int[stateSpecList.length];
        int listSize = 0;
        int[] colorList2 = colorList;
        int[][] stateSpecList2 = stateSpecList;
        while (true) {
            int next = parser.next();
            int type = next;
            if (next != i && ((depth = parser.getDepth()) >= innerDepth2 || type != 3)) {
                if (type != 2 || depth > innerDepth2) {
                    innerDepth = innerDepth2;
                } else if (!parser.getName().equals("item")) {
                    innerDepth = innerDepth2;
                } else {
                    TypedArray a = obtainAttributes(resources, theme2, attrs, R.styleable.ColorStateListItem);
                    int resourceId = a.getResourceId(R.styleable.ColorStateListItem_android_color, -1);
                    if (resourceId != -1 && !isColorInt(resources, resourceId)) {
                        try {
                            baseColor = createFromXml(resources, resources.getXml(resourceId), theme2).getDefaultColor();
                        } catch (Exception e) {
                            baseColor = a.getColor(R.styleable.ColorStateListItem_android_color, -65281);
                        }
                    } else {
                        int baseColor2 = R.styleable.ColorStateListItem_android_color;
                        baseColor = a.getColor(baseColor2, -65281);
                    }
                    float alphaMod = 1.0f;
                    if (a.hasValue(R.styleable.ColorStateListItem_android_alpha)) {
                        alphaMod = a.getFloat(R.styleable.ColorStateListItem_android_alpha, 1.0f);
                    } else if (a.hasValue(R.styleable.ColorStateListItem_alpha)) {
                        alphaMod = a.getFloat(R.styleable.ColorStateListItem_alpha, 1.0f);
                    }
                    if (BuildCompat.isAtLeastS() && a.hasValue(R.styleable.ColorStateListItem_android_lStar)) {
                        lStar = a.getFloat(R.styleable.ColorStateListItem_android_lStar, -1.0f);
                    } else {
                        lStar = a.getFloat(R.styleable.ColorStateListItem_lStar, -1.0f);
                    }
                    a.recycle();
                    int j = 0;
                    int numAttrs = attrs.getAttributeCount();
                    int[] stateSpec = new int[numAttrs];
                    int i2 = 0;
                    while (i2 < numAttrs) {
                        int innerDepth3 = innerDepth2;
                        int stateResId = attrs.getAttributeNameResource(i2);
                        int type2 = type;
                        if (stateResId != 16843173 && stateResId != 16843551 && stateResId != R.attr.alpha && stateResId != R.attr.lStar) {
                            int j2 = j + 1;
                            stateSpec[j] = attrs.getAttributeBooleanValue(i2, false) ? stateResId : -stateResId;
                            j = j2;
                        }
                        i2++;
                        innerDepth2 = innerDepth3;
                        type = type2;
                    }
                    int[] stateSpec2 = StateSet.trimStateSet(stateSpec, j);
                    int color = modulateColorAlpha(baseColor, alphaMod, lStar);
                    colorList2 = GrowingArrayUtils.append(colorList2, listSize, color);
                    stateSpecList2 = (int[][]) GrowingArrayUtils.append(stateSpecList2, listSize, stateSpec2);
                    listSize++;
                    resources = r;
                    theme2 = theme;
                    innerDepth2 = innerDepth2;
                    i = 1;
                }
                resources = r;
                theme2 = theme;
                innerDepth2 = innerDepth;
                i = 1;
            }
        }
        int[] colors = new int[listSize];
        int[][] stateSpecs = new int[listSize];
        System.arraycopy(colorList2, 0, colors, 0, listSize);
        System.arraycopy(stateSpecList2, 0, stateSpecs, 0, listSize);
        return new ColorStateList(stateSpecs, colors);
    }

    private static boolean isColorInt(Resources r, int resId) {
        TypedValue value = getTypedValue();
        r.getValue(resId, value, true);
        return value.type >= 28 && value.type <= 31;
    }

    private static TypedValue getTypedValue() {
        ThreadLocal<TypedValue> threadLocal = sTempTypedValue;
        TypedValue tv = threadLocal.get();
        if (tv == null) {
            TypedValue tv2 = new TypedValue();
            threadLocal.set(tv2);
            return tv2;
        }
        return tv;
    }

    private static TypedArray obtainAttributes(Resources res, Resources.Theme theme, AttributeSet set, int[] attrs) {
        return theme == null ? res.obtainAttributes(set, attrs) : theme.obtainStyledAttributes(set, attrs, 0, 0);
    }

    private static int modulateColorAlpha(int color, float alphaMod, float lStar) {
        boolean validLStar = lStar >= 0.0f && lStar <= 100.0f;
        if (alphaMod == 1.0f && !validLStar) {
            return color;
        }
        int baseAlpha = Color.alpha(color);
        int alpha = MathUtils.clamp((int) ((baseAlpha * alphaMod) + 0.5f), 0, 255);
        if (validLStar) {
            CamColor baseCam = CamColor.fromColor(color);
            color = CamColor.toColor(baseCam.getHue(), baseCam.getChroma(), lStar);
        }
        return (16777215 & color) | (alpha << 24);
    }
}
