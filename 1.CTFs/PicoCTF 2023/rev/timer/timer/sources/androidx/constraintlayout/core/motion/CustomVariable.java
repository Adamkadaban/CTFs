package androidx.constraintlayout.core.motion;

import androidx.constraintlayout.core.motion.utils.TypedValues;
/* loaded from: classes.dex */
public class CustomVariable {
    private static final String TAG = "TransitionLayout";
    boolean mBooleanValue;
    private float mFloatValue;
    private int mIntegerValue;
    String mName;
    private String mStringValue;
    private int mType;

    public CustomVariable copy() {
        return new CustomVariable(this);
    }

    public CustomVariable(CustomVariable c) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = c.mName;
        this.mType = c.mType;
        this.mIntegerValue = c.mIntegerValue;
        this.mFloatValue = c.mFloatValue;
        this.mStringValue = c.mStringValue;
        this.mBooleanValue = c.mBooleanValue;
    }

    public CustomVariable(String name, int type, String value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = type;
        this.mStringValue = value;
    }

    public CustomVariable(String name, int type, int value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = type;
        if (type == 901) {
            this.mFloatValue = value;
        } else {
            this.mIntegerValue = value;
        }
    }

    public CustomVariable(String name, int type, float value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = type;
        this.mFloatValue = value;
    }

    public CustomVariable(String name, int type, boolean value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = type;
        this.mBooleanValue = value;
    }

    public static String colorString(int v) {
        String str = "00000000" + Integer.toHexString(v);
        return "#" + str.substring(str.length() - 8);
    }

    public String toString() {
        String str = this.mName + ':';
        switch (this.mType) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
                return str + this.mIntegerValue;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                return str + this.mFloatValue;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                return str + colorString(this.mIntegerValue);
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                return str + this.mStringValue;
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                return str + Boolean.valueOf(this.mBooleanValue);
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                return str + this.mFloatValue;
            default:
                return str + "????";
        }
    }

    public int getType() {
        return this.mType;
    }

    public boolean getBooleanValue() {
        return this.mBooleanValue;
    }

    public float getFloatValue() {
        return this.mFloatValue;
    }

    public int getColorValue() {
        return this.mIntegerValue;
    }

    public int getIntegerValue() {
        return this.mIntegerValue;
    }

    public String getStringValue() {
        return this.mStringValue;
    }

    public boolean isContinuous() {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_STRING /* 903 */:
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                return false;
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
            default:
                return true;
        }
    }

    public void setFloatValue(float value) {
        this.mFloatValue = value;
    }

    public void setBooleanValue(boolean value) {
        this.mBooleanValue = value;
    }

    public void setIntValue(int value) {
        this.mIntegerValue = value;
    }

    public void setStringValue(String value) {
        this.mStringValue = value;
    }

    public int numberOfInterpolatedValues() {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                return 4;
            default:
                return 1;
        }
    }

    public float getValueToInterpolate() {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
                return this.mIntegerValue;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                return this.mFloatValue;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                throw new RuntimeException("Color does not have a single color to interpolate");
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                throw new RuntimeException("Cannot interpolate String");
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                return this.mBooleanValue ? 1.0f : 0.0f;
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                return this.mFloatValue;
            default:
                return Float.NaN;
        }
    }

    public void getValuesToInterpolate(float[] ret) {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
                ret[0] = this.mIntegerValue;
                return;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                ret[0] = this.mFloatValue;
                return;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                int i = this.mIntegerValue;
                int a = (i >> 24) & 255;
                int r = (i >> 16) & 255;
                int g = (i >> 8) & 255;
                int b = i & 255;
                float f_r = (float) Math.pow(r / 255.0f, 2.2d);
                float f_g = (float) Math.pow(g / 255.0f, 2.2d);
                float f_b = (float) Math.pow(b / 255.0f, 2.2d);
                ret[0] = f_r;
                ret[1] = f_g;
                ret[2] = f_b;
                ret[3] = a / 255.0f;
                return;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                throw new RuntimeException("Cannot interpolate String");
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                ret[0] = this.mBooleanValue ? 1.0f : 0.0f;
                return;
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                ret[0] = this.mFloatValue;
                return;
            default:
                return;
        }
    }

    public void setValue(float[] value) {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                this.mIntegerValue = (int) value[0];
                return;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                float f_r = value[0];
                this.mFloatValue = f_r;
                return;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                float f_r2 = value[0];
                float f_g = value[1];
                float f_b = value[2];
                int r = Math.round(((float) Math.pow(f_r2, 0.5d)) * 255.0f) & 255;
                int g = Math.round(((float) Math.pow(f_g, 0.5d)) * 255.0f) & 255;
                int b = Math.round(((float) Math.pow(f_b, 0.5d)) * 255.0f) & 255;
                int a = Math.round(value[3] * 255.0f) & 255;
                this.mIntegerValue = (a << 24) | (r << 16) | (g << 8) | b;
                return;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                throw new RuntimeException("Cannot interpolate String");
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                this.mBooleanValue = ((double) value[0]) > 0.5d;
                return;
            default:
                return;
        }
    }

    public static int hsvToRgb(float hue, float saturation, float value) {
        int h = (int) (hue * 6.0f);
        float f = (6.0f * hue) - h;
        int p = (int) ((value * 255.0f * (1.0f - saturation)) + 0.5f);
        int q = (int) ((value * 255.0f * (1.0f - (f * saturation))) + 0.5f);
        int t = (int) ((value * 255.0f * (1.0f - ((1.0f - f) * saturation))) + 0.5f);
        int v = (int) ((255.0f * value) + 0.5f);
        switch (h) {
            case 0:
                return (-16777216) | ((v << 16) + (t << 8) + p);
            case 1:
                return (-16777216) | ((q << 16) + (v << 8) + p);
            case 2:
                return (-16777216) | ((p << 16) + (v << 8) + t);
            case 3:
                return (-16777216) | ((p << 16) + (q << 8) + v);
            case 4:
                return (-16777216) | ((t << 16) + (p << 8) + v);
            case 5:
                return (-16777216) | ((v << 16) + (p << 8) + q);
            default:
                return 0;
        }
    }

    public boolean diff(CustomVariable CustomAttribute) {
        int i;
        if (CustomAttribute == null || (i = this.mType) != CustomAttribute.mType) {
            return false;
        }
        switch (i) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                return this.mIntegerValue == CustomAttribute.mIntegerValue;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                return this.mFloatValue == CustomAttribute.mFloatValue;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                return this.mIntegerValue == CustomAttribute.mIntegerValue;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                return this.mIntegerValue == CustomAttribute.mIntegerValue;
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                return this.mBooleanValue == CustomAttribute.mBooleanValue;
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                return this.mFloatValue == CustomAttribute.mFloatValue;
            default:
                return false;
        }
    }

    public CustomVariable(String name, int attributeType) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = attributeType;
    }

    public CustomVariable(String name, int attributeType, Object value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = name;
        this.mType = attributeType;
        setValue(value);
    }

    public CustomVariable(CustomVariable source, Object value) {
        this.mIntegerValue = Integer.MIN_VALUE;
        this.mFloatValue = Float.NaN;
        this.mStringValue = null;
        this.mName = source.mName;
        this.mType = source.mType;
        setValue(value);
    }

    public void setValue(Object value) {
        switch (this.mType) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                this.mIntegerValue = ((Integer) value).intValue();
                return;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                this.mFloatValue = ((Float) value).floatValue();
                return;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                this.mIntegerValue = ((Integer) value).intValue();
                return;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                this.mStringValue = (String) value;
                return;
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                this.mBooleanValue = ((Boolean) value).booleanValue();
                return;
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                this.mFloatValue = ((Float) value).floatValue();
                return;
            default:
                return;
        }
    }

    private static int clamp(int c) {
        int c2 = (c & (~(c >> 31))) - 255;
        return (c2 & (c2 >> 31)) + 255;
    }

    public int getInterpolatedColor(float[] value) {
        int r = clamp((int) (((float) Math.pow(value[0], 0.45454545454545453d)) * 255.0f));
        int g = clamp((int) (((float) Math.pow(value[1], 0.45454545454545453d)) * 255.0f));
        int b = clamp((int) (((float) Math.pow(value[2], 0.45454545454545453d)) * 255.0f));
        int a = clamp((int) (value[3] * 255.0f));
        int color = (a << 24) | (r << 16) | (g << 8) | b;
        return color;
    }

    public void setInterpolatedValue(MotionWidget view, float[] value) {
        int i = this.mType;
        switch (i) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
                view.setCustomAttribute(this.mName, i, (int) value[0]);
                return;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                view.setCustomAttribute(this.mName, i, value[0]);
                return;
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
                int r = clamp((int) (((float) Math.pow(value[0], 0.45454545454545453d)) * 255.0f));
                int g = clamp((int) (((float) Math.pow(value[1], 0.45454545454545453d)) * 255.0f));
                int b = clamp((int) (((float) Math.pow(value[2], 0.45454545454545453d)) * 255.0f));
                int a = clamp((int) (value[3] * 255.0f));
                int color = (a << 24) | (r << 16) | (g << 8) | b;
                view.setCustomAttribute(this.mName, this.mType, color);
                return;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                throw new RuntimeException("unable to interpolate " + this.mName);
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                view.setCustomAttribute(this.mName, i, value[0] > 0.5f);
                return;
            default:
                return;
        }
    }

    public static int rgbaTocColor(float r, float g, float b, float a) {
        int ir = clamp((int) (r * 255.0f));
        int ig = clamp((int) (g * 255.0f));
        int ib = clamp((int) (b * 255.0f));
        int ia = clamp((int) (255.0f * a));
        int color = (ia << 24) | (ir << 16) | (ig << 8) | ib;
        return color;
    }

    public void applyToWidget(MotionWidget view) {
        int i = this.mType;
        switch (i) {
            case TypedValues.Custom.TYPE_INT /* 900 */:
            case TypedValues.Custom.TYPE_COLOR /* 902 */:
            case TypedValues.Custom.TYPE_REFERENCE /* 906 */:
                view.setCustomAttribute(this.mName, i, this.mIntegerValue);
                return;
            case TypedValues.Custom.TYPE_FLOAT /* 901 */:
            case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                view.setCustomAttribute(this.mName, i, this.mFloatValue);
                return;
            case TypedValues.Custom.TYPE_STRING /* 903 */:
                view.setCustomAttribute(this.mName, i, this.mStringValue);
                return;
            case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                view.setCustomAttribute(this.mName, i, this.mBooleanValue);
                return;
            default:
                return;
        }
    }

    public String getName() {
        return this.mName;
    }
}
