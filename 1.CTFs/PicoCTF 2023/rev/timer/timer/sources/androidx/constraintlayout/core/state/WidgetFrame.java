package androidx.constraintlayout.core.state;

import androidx.constraintlayout.core.motion.CustomAttribute;
import androidx.constraintlayout.core.motion.CustomVariable;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.parser.CLElement;
import androidx.constraintlayout.core.parser.CLKey;
import androidx.constraintlayout.core.parser.CLNumber;
import androidx.constraintlayout.core.parser.CLObject;
import androidx.constraintlayout.core.parser.CLParsingException;
import androidx.constraintlayout.core.state.Transition;
import androidx.constraintlayout.core.widgets.ConstraintAnchor;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.core.os.EnvironmentCompat;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
/* loaded from: classes.dex */
public class WidgetFrame {
    private static final boolean OLD_SYSTEM = true;
    public static float phone_orientation = Float.NaN;
    public float alpha;
    public int bottom;
    public float interpolatedPos;
    public int left;
    public final HashMap<String, CustomVariable> mCustom;
    public String name;
    public float pivotX;
    public float pivotY;
    public int right;
    public float rotationX;
    public float rotationY;
    public float rotationZ;
    public float scaleX;
    public float scaleY;
    public int top;
    public float translationX;
    public float translationY;
    public float translationZ;
    public int visibility;
    public ConstraintWidget widget;

    public int width() {
        return Math.max(0, this.right - this.left);
    }

    public int height() {
        return Math.max(0, this.bottom - this.top);
    }

    public WidgetFrame() {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
    }

    public WidgetFrame(ConstraintWidget widget) {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
        this.widget = widget;
    }

    public WidgetFrame(WidgetFrame frame) {
        this.widget = null;
        this.left = 0;
        this.top = 0;
        this.right = 0;
        this.bottom = 0;
        this.pivotX = Float.NaN;
        this.pivotY = Float.NaN;
        this.rotationX = Float.NaN;
        this.rotationY = Float.NaN;
        this.rotationZ = Float.NaN;
        this.translationX = Float.NaN;
        this.translationY = Float.NaN;
        this.translationZ = Float.NaN;
        this.scaleX = Float.NaN;
        this.scaleY = Float.NaN;
        this.alpha = Float.NaN;
        this.interpolatedPos = Float.NaN;
        this.visibility = 0;
        this.mCustom = new HashMap<>();
        this.name = null;
        this.widget = frame.widget;
        this.left = frame.left;
        this.top = frame.top;
        this.right = frame.right;
        this.bottom = frame.bottom;
        updateAttributes(frame);
    }

    public void updateAttributes(WidgetFrame frame) {
        this.pivotX = frame.pivotX;
        this.pivotY = frame.pivotY;
        this.rotationX = frame.rotationX;
        this.rotationY = frame.rotationY;
        this.rotationZ = frame.rotationZ;
        this.translationX = frame.translationX;
        this.translationY = frame.translationY;
        this.translationZ = frame.translationZ;
        this.scaleX = frame.scaleX;
        this.scaleY = frame.scaleY;
        this.alpha = frame.alpha;
        this.visibility = frame.visibility;
        this.mCustom.clear();
        if (frame != null) {
            for (CustomVariable c : frame.mCustom.values()) {
                this.mCustom.put(c.getName(), c.copy());
            }
        }
    }

    public boolean isDefaultTransform() {
        if (Float.isNaN(this.rotationX) && Float.isNaN(this.rotationY) && Float.isNaN(this.rotationZ) && Float.isNaN(this.translationX) && Float.isNaN(this.translationY) && Float.isNaN(this.translationZ) && Float.isNaN(this.scaleX) && Float.isNaN(this.scaleY) && Float.isNaN(this.alpha)) {
            return OLD_SYSTEM;
        }
        return false;
    }

    public static void interpolate(int parentWidth, int parentHeight, WidgetFrame frame, WidgetFrame start, WidgetFrame end, Transition transition, float progress) {
        float startAlpha;
        int startWidth;
        int startHeight;
        int endHeight;
        float startAlpha2;
        float f;
        int startY;
        int startX;
        int interpolateStartFrame;
        Iterator<String> it;
        int startX2;
        int endX;
        int interpolateStartFrame2;
        int endX2;
        WidgetFrame widgetFrame = frame;
        WidgetFrame widgetFrame2 = start;
        WidgetFrame widgetFrame3 = end;
        int frameNumber = (int) (progress * 100.0f);
        int startX3 = widgetFrame2.left;
        int startY2 = widgetFrame2.top;
        int endX3 = widgetFrame3.left;
        int endY = widgetFrame3.top;
        int startWidth2 = widgetFrame2.right - widgetFrame2.left;
        int startHeight2 = widgetFrame2.bottom - widgetFrame2.top;
        int endWidth = widgetFrame3.right - widgetFrame3.left;
        int i = widgetFrame3.bottom;
        int startWidth3 = widgetFrame3.top;
        int endHeight2 = i - startWidth3;
        float progressPosition = progress;
        float progressPosition2 = widgetFrame2.alpha;
        float endAlpha = widgetFrame3.alpha;
        if (widgetFrame2.visibility != 8) {
            startAlpha = progressPosition2;
            startWidth = startWidth2;
            startHeight = startHeight2;
        } else {
            startX3 = (int) (startX3 - (endWidth / 2.0f));
            startY2 = (int) (startY2 - (endHeight2 / 2.0f));
            startHeight = endHeight2;
            if (Float.isNaN(progressPosition2)) {
                startWidth = endWidth;
                startAlpha = 0.0f;
            } else {
                startWidth = endWidth;
                startAlpha = progressPosition2;
            }
        }
        int startX4 = startX3;
        if (widgetFrame3.visibility != 8) {
            endHeight = endHeight2;
        } else {
            endX3 = (int) (endX3 - (startWidth / 2.0f));
            endY = (int) (endY - (startHeight / 2.0f));
            endWidth = startWidth;
            endHeight = startHeight;
            if (Float.isNaN(endAlpha)) {
                endAlpha = 0.0f;
            }
        }
        if (Float.isNaN(startAlpha) && !Float.isNaN(endAlpha)) {
            startAlpha = 1.0f;
        }
        if (!Float.isNaN(startAlpha) && Float.isNaN(endAlpha)) {
            endAlpha = 1.0f;
        }
        float startAlpha3 = startAlpha;
        if (widgetFrame2.visibility != 4) {
            startAlpha2 = startAlpha3;
        } else {
            startAlpha2 = 0.0f;
        }
        int startY3 = startY2;
        if (widgetFrame3.visibility == 4) {
            endAlpha = 0.0f;
        }
        if (widgetFrame.widget != null && transition.hasPositionKeyframes()) {
            Transition.KeyPosition firstPosition = transition.findPreviousPosition(widgetFrame.widget.stringId, frameNumber);
            Transition.KeyPosition lastPosition = transition.findNextPosition(widgetFrame.widget.stringId, frameNumber);
            if (firstPosition == lastPosition) {
                lastPosition = null;
            }
            int interpolateEndFrame = 100;
            if (firstPosition != null) {
                startX4 = (int) (firstPosition.x * parentWidth);
                endX = endX3;
                startX2 = parentHeight;
                interpolateStartFrame2 = firstPosition.frame;
                startY3 = (int) (firstPosition.y * startX2);
            } else {
                startX2 = parentHeight;
                endX = endX3;
                interpolateStartFrame2 = 0;
            }
            if (lastPosition != null) {
                endX2 = (int) (lastPosition.x * parentWidth);
                endY = (int) (lastPosition.y * startX2);
                interpolateEndFrame = lastPosition.frame;
            } else {
                endX2 = endX;
            }
            f = progress;
            progressPosition = ((100.0f * f) - interpolateStartFrame2) / (interpolateEndFrame - interpolateStartFrame2);
            interpolateStartFrame = endX2;
            startY = startY3;
            startX = startX4;
        } else {
            f = progress;
            startY = startY3;
            startX = startX4;
            interpolateStartFrame = endX3;
        }
        widgetFrame.widget = widgetFrame2.widget;
        int i2 = (int) (startX + ((interpolateStartFrame - startX) * progressPosition));
        widgetFrame.left = i2;
        int i3 = (int) (startY + ((endY - startY) * progressPosition));
        widgetFrame.top = i3;
        int width = (int) (((1.0f - f) * startWidth) + (endWidth * f));
        int height = (int) (((1.0f - f) * startHeight) + (endHeight * f));
        widgetFrame.right = i2 + width;
        widgetFrame.bottom = i3 + height;
        widgetFrame.pivotX = interpolate(widgetFrame2.pivotX, widgetFrame3.pivotX, 0.5f, f);
        widgetFrame.pivotY = interpolate(widgetFrame2.pivotY, widgetFrame3.pivotY, 0.5f, f);
        widgetFrame.rotationX = interpolate(widgetFrame2.rotationX, widgetFrame3.rotationX, 0.0f, f);
        widgetFrame.rotationY = interpolate(widgetFrame2.rotationY, widgetFrame3.rotationY, 0.0f, f);
        widgetFrame.rotationZ = interpolate(widgetFrame2.rotationZ, widgetFrame3.rotationZ, 0.0f, f);
        widgetFrame.scaleX = interpolate(widgetFrame2.scaleX, widgetFrame3.scaleX, 1.0f, f);
        widgetFrame.scaleY = interpolate(widgetFrame2.scaleY, widgetFrame3.scaleY, 1.0f, f);
        widgetFrame.translationX = interpolate(widgetFrame2.translationX, widgetFrame3.translationX, 0.0f, f);
        widgetFrame.translationY = interpolate(widgetFrame2.translationY, widgetFrame3.translationY, 0.0f, f);
        widgetFrame.translationZ = interpolate(widgetFrame2.translationZ, widgetFrame3.translationZ, 0.0f, f);
        widgetFrame.alpha = interpolate(startAlpha2, endAlpha, 1.0f, f);
        Set<String> keys = widgetFrame3.mCustom.keySet();
        widgetFrame.mCustom.clear();
        Iterator<String> it2 = keys.iterator();
        while (it2.hasNext()) {
            String key = it2.next();
            Set<String> keys2 = keys;
            if (!widgetFrame2.mCustom.containsKey(key)) {
                it = it2;
            } else {
                CustomVariable startVariable = widgetFrame2.mCustom.get(key);
                CustomVariable endVariable = widgetFrame3.mCustom.get(key);
                CustomVariable interpolated = new CustomVariable(startVariable);
                it = it2;
                widgetFrame.mCustom.put(key, interpolated);
                if (startVariable.numberOfInterpolatedValues() == 1) {
                    interpolated.setValue(Float.valueOf(interpolate(startVariable.getValueToInterpolate(), endVariable.getValueToInterpolate(), 0.0f, f)));
                } else {
                    int N = startVariable.numberOfInterpolatedValues();
                    float[] startValues = new float[N];
                    float[] endValues = new float[N];
                    startVariable.getValuesToInterpolate(startValues);
                    endVariable.getValuesToInterpolate(endValues);
                    int i4 = 0;
                    while (i4 < N) {
                        startValues[i4] = interpolate(startValues[i4], endValues[i4], 0.0f, f);
                        interpolated.setValue(startValues);
                        i4++;
                        N = N;
                        endVariable = endVariable;
                        endValues = endValues;
                    }
                }
            }
            widgetFrame = frame;
            widgetFrame2 = start;
            widgetFrame3 = end;
            keys = keys2;
            it2 = it;
        }
    }

    private static float interpolate(float start, float end, float defaultValue, float progress) {
        boolean isStartUnset = Float.isNaN(start);
        boolean isEndUnset = Float.isNaN(end);
        if (isStartUnset && isEndUnset) {
            return Float.NaN;
        }
        if (isStartUnset) {
            start = defaultValue;
        }
        if (isEndUnset) {
            end = defaultValue;
        }
        return ((end - start) * progress) + start;
    }

    public float centerX() {
        int i = this.left;
        return i + ((this.right - i) / 2.0f);
    }

    public float centerY() {
        int i = this.top;
        return i + ((this.bottom - i) / 2.0f);
    }

    public WidgetFrame update() {
        ConstraintWidget constraintWidget = this.widget;
        if (constraintWidget != null) {
            this.left = constraintWidget.getLeft();
            this.top = this.widget.getTop();
            this.right = this.widget.getRight();
            this.bottom = this.widget.getBottom();
            WidgetFrame frame = this.widget.frame;
            updateAttributes(frame);
        }
        return this;
    }

    public WidgetFrame update(ConstraintWidget widget) {
        if (widget == null) {
            return this;
        }
        this.widget = widget;
        update();
        return this;
    }

    public void addCustomColor(String name, int color) {
        setCustomAttribute(name, TypedValues.Custom.TYPE_COLOR, color);
    }

    public int getCustomColor(String name) {
        if (this.mCustom.containsKey(name)) {
            return this.mCustom.get(name).getColorValue();
        }
        return -21880;
    }

    public void addCustomFloat(String name, float value) {
        setCustomAttribute(name, TypedValues.Custom.TYPE_FLOAT, value);
    }

    public float getCustomFloat(String name) {
        if (this.mCustom.containsKey(name)) {
            return this.mCustom.get(name).getFloatValue();
        }
        return Float.NaN;
    }

    public void setCustomAttribute(String name, int type, float value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setFloatValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, int value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setIntValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, boolean value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setBooleanValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public void setCustomAttribute(String name, int type, String value) {
        if (this.mCustom.containsKey(name)) {
            this.mCustom.get(name).setStringValue(value);
        } else {
            this.mCustom.put(name, new CustomVariable(name, type, value));
        }
    }

    public CustomVariable getCustomAttribute(String name) {
        return this.mCustom.get(name);
    }

    public Set<String> getCustomAttributeNames() {
        return this.mCustom.keySet();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public boolean setValue(String key, CLElement value) throws CLParsingException {
        char c;
        switch (key.hashCode()) {
            case -1881940865:
                if (key.equals("phone_orientation")) {
                    c = '\f';
                    break;
                }
                c = 65535;
                break;
            case -1383228885:
                if (key.equals("bottom")) {
                    c = 16;
                    break;
                }
                c = 65535;
                break;
            case -1349088399:
                if (key.equals("custom")) {
                    c = 17;
                    break;
                }
                c = 65535;
                break;
            case -1249320806:
                if (key.equals("rotationX")) {
                    c = 2;
                    break;
                }
                c = 65535;
                break;
            case -1249320805:
                if (key.equals("rotationY")) {
                    c = 3;
                    break;
                }
                c = 65535;
                break;
            case -1249320804:
                if (key.equals("rotationZ")) {
                    c = 4;
                    break;
                }
                c = 65535;
                break;
            case -1225497657:
                if (key.equals("translationX")) {
                    c = 5;
                    break;
                }
                c = 65535;
                break;
            case -1225497656:
                if (key.equals("translationY")) {
                    c = 6;
                    break;
                }
                c = 65535;
                break;
            case -1225497655:
                if (key.equals("translationZ")) {
                    c = 7;
                    break;
                }
                c = 65535;
                break;
            case -987906986:
                if (key.equals("pivotX")) {
                    c = 0;
                    break;
                }
                c = 65535;
                break;
            case -987906985:
                if (key.equals("pivotY")) {
                    c = 1;
                    break;
                }
                c = 65535;
                break;
            case -908189618:
                if (key.equals("scaleX")) {
                    c = '\b';
                    break;
                }
                c = 65535;
                break;
            case -908189617:
                if (key.equals("scaleY")) {
                    c = '\t';
                    break;
                }
                c = 65535;
                break;
            case 115029:
                if (key.equals("top")) {
                    c = '\r';
                    break;
                }
                c = 65535;
                break;
            case 3317767:
                if (key.equals("left")) {
                    c = 14;
                    break;
                }
                c = 65535;
                break;
            case 92909918:
                if (key.equals("alpha")) {
                    c = '\n';
                    break;
                }
                c = 65535;
                break;
            case 108511772:
                if (key.equals("right")) {
                    c = 15;
                    break;
                }
                c = 65535;
                break;
            case 642850769:
                if (key.equals("interpolatedPos")) {
                    c = 11;
                    break;
                }
                c = 65535;
                break;
            default:
                c = 65535;
                break;
        }
        switch (c) {
            case 0:
                this.pivotX = value.getFloat();
                break;
            case 1:
                this.pivotY = value.getFloat();
                break;
            case 2:
                this.rotationX = value.getFloat();
                break;
            case 3:
                this.rotationY = value.getFloat();
                break;
            case 4:
                this.rotationZ = value.getFloat();
                break;
            case 5:
                this.translationX = value.getFloat();
                break;
            case 6:
                this.translationY = value.getFloat();
                break;
            case 7:
                this.translationZ = value.getFloat();
                break;
            case '\b':
                this.scaleX = value.getFloat();
                break;
            case '\t':
                this.scaleY = value.getFloat();
                break;
            case '\n':
                this.alpha = value.getFloat();
                break;
            case 11:
                this.interpolatedPos = value.getFloat();
                break;
            case '\f':
                phone_orientation = value.getFloat();
                break;
            case '\r':
                this.top = value.getInt();
                break;
            case 14:
                this.left = value.getInt();
                break;
            case 15:
                this.right = value.getInt();
                break;
            case 16:
                this.bottom = value.getInt();
                break;
            case 17:
                parseCustom(value);
                break;
            default:
                return false;
        }
        return OLD_SYSTEM;
    }

    public String getId() {
        ConstraintWidget constraintWidget = this.widget;
        if (constraintWidget == null) {
            return EnvironmentCompat.MEDIA_UNKNOWN;
        }
        return constraintWidget.stringId;
    }

    void parseCustom(CLElement custom) throws CLParsingException {
        CLObject obj = (CLObject) custom;
        int n = obj.size();
        for (int i = 0; i < n; i++) {
            CLElement tmp = obj.get(i);
            CLKey k = (CLKey) tmp;
            k.content();
            CLElement v = k.getValue();
            String vStr = v.content();
            if (vStr.matches("#[0-9a-fA-F]+")) {
                int color = Integer.parseInt(vStr.substring(1), 16);
                setCustomAttribute(k.content(), TypedValues.Custom.TYPE_COLOR, color);
            } else if (v instanceof CLNumber) {
                setCustomAttribute(k.content(), TypedValues.Custom.TYPE_FLOAT, v.getFloat());
            } else {
                setCustomAttribute(k.content(), TypedValues.Custom.TYPE_STRING, vStr);
            }
        }
    }

    public StringBuilder serialize(StringBuilder ret) {
        return serialize(ret, false);
    }

    public StringBuilder serialize(StringBuilder ret, boolean sendPhoneOrientation) {
        ConstraintAnchor.Type[] values;
        ret.append("{\n");
        add(ret, "left", this.left);
        add(ret, "top", this.top);
        add(ret, "right", this.right);
        add(ret, "bottom", this.bottom);
        add(ret, "pivotX", this.pivotX);
        add(ret, "pivotY", this.pivotY);
        add(ret, "rotationX", this.rotationX);
        add(ret, "rotationY", this.rotationY);
        add(ret, "rotationZ", this.rotationZ);
        add(ret, "translationX", this.translationX);
        add(ret, "translationY", this.translationY);
        add(ret, "translationZ", this.translationZ);
        add(ret, "scaleX", this.scaleX);
        add(ret, "scaleY", this.scaleY);
        add(ret, "alpha", this.alpha);
        add(ret, "visibility", this.visibility);
        add(ret, "interpolatedPos", this.interpolatedPos);
        if (this.widget != null) {
            for (ConstraintAnchor.Type side : ConstraintAnchor.Type.values()) {
                serializeAnchor(ret, side);
            }
        }
        if (sendPhoneOrientation) {
            add(ret, "phone_orientation", phone_orientation);
        }
        if (sendPhoneOrientation) {
            add(ret, "phone_orientation", phone_orientation);
        }
        if (this.mCustom.size() != 0) {
            ret.append("custom : {\n");
            for (String s : this.mCustom.keySet()) {
                CustomVariable value = this.mCustom.get(s);
                ret.append(s);
                ret.append(": ");
                switch (value.getType()) {
                    case TypedValues.Custom.TYPE_INT /* 900 */:
                        ret.append(value.getIntegerValue());
                        ret.append(",\n");
                        break;
                    case TypedValues.Custom.TYPE_FLOAT /* 901 */:
                    case TypedValues.Custom.TYPE_DIMENSION /* 905 */:
                        ret.append(value.getFloatValue());
                        ret.append(",\n");
                        break;
                    case TypedValues.Custom.TYPE_COLOR /* 902 */:
                        ret.append("'");
                        ret.append(CustomVariable.colorString(value.getIntegerValue()));
                        ret.append("',\n");
                        break;
                    case TypedValues.Custom.TYPE_STRING /* 903 */:
                        ret.append("'");
                        ret.append(value.getStringValue());
                        ret.append("',\n");
                        break;
                    case TypedValues.Custom.TYPE_BOOLEAN /* 904 */:
                        ret.append("'");
                        ret.append(value.getBooleanValue());
                        ret.append("',\n");
                        break;
                }
            }
            ret.append("}\n");
        }
        ret.append("}\n");
        return ret;
    }

    private void serializeAnchor(StringBuilder ret, ConstraintAnchor.Type type) {
        ConstraintAnchor anchor = this.widget.getAnchor(type);
        if (anchor == null || anchor.mTarget == null) {
            return;
        }
        ret.append("Anchor");
        ret.append(type.name());
        ret.append(": ['");
        String str = anchor.mTarget.getOwner().stringId;
        ret.append(str == null ? "#PARENT" : str);
        ret.append("', '");
        ret.append(anchor.mTarget.getType().name());
        ret.append("', '");
        ret.append(anchor.mMargin);
        ret.append("'],\n");
    }

    private static void add(StringBuilder s, String title, int value) {
        s.append(title);
        s.append(": ");
        s.append(value);
        s.append(",\n");
    }

    private static void add(StringBuilder s, String title, float value) {
        if (Float.isNaN(value)) {
            return;
        }
        s.append(title);
        s.append(": ");
        s.append(value);
        s.append(",\n");
    }

    void printCustomAttributes() {
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String ss = (".(" + s.getFileName() + ":" + s.getLineNumber() + ") " + s.getMethodName()) + " " + (hashCode() % 1000);
        String ss2 = this.widget != null ? ss + "/" + (this.widget.hashCode() % 1000) + " " : ss + "/NULL ";
        HashMap<String, CustomVariable> hashMap = this.mCustom;
        if (hashMap != null) {
            for (String key : hashMap.keySet()) {
                System.out.println(ss2 + this.mCustom.get(key).toString());
            }
        }
    }

    void logv(String str) {
        String ss;
        StackTraceElement s = new Throwable().getStackTrace()[1];
        String ss2 = (".(" + s.getFileName() + ":" + s.getLineNumber() + ") " + s.getMethodName()) + " " + (hashCode() % 1000);
        if (this.widget != null) {
            ss = ss2 + "/" + (this.widget.hashCode() % 1000);
        } else {
            ss = ss2 + "/NULL";
        }
        System.out.println(ss + " " + str);
    }

    public void setCustomValue(CustomAttribute valueAt, float[] mTempValues) {
    }
}
