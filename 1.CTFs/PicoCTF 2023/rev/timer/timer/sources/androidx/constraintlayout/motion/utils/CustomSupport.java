package androidx.constraintlayout.motion.utils;

import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.view.View;
import androidx.constraintlayout.motion.widget.Debug;
import androidx.constraintlayout.widget.ConstraintAttribute;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public class CustomSupport {
    private static final String TAG = "CustomSupport";

    public static void setInterpolatedValue(ConstraintAttribute att, View view, float[] value) {
        Class<?> cls = view.getClass();
        String methodName = "set" + att.getName();
        try {
            boolean z = true;
            switch (AnonymousClass1.$SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[att.getType().ordinal()]) {
                case 1:
                    Method method = cls.getMethod(methodName, Integer.TYPE);
                    method.invoke(view, Integer.valueOf((int) value[0]));
                    return;
                case 2:
                    Method method2 = cls.getMethod(methodName, Float.TYPE);
                    method2.invoke(view, Float.valueOf(value[0]));
                    return;
                case 3:
                    Method method3 = cls.getMethod(methodName, Drawable.class);
                    int r = clamp((int) (((float) Math.pow(value[0], 0.45454545454545453d)) * 255.0f));
                    int g = clamp((int) (((float) Math.pow(value[1], 0.45454545454545453d)) * 255.0f));
                    int b = clamp((int) (((float) Math.pow(value[2], 0.45454545454545453d)) * 255.0f));
                    int a = clamp((int) (value[3] * 255.0f));
                    int color = (a << 24) | (r << 16) | (g << 8) | b;
                    ColorDrawable drawable = new ColorDrawable();
                    drawable.setColor(color);
                    method3.invoke(view, drawable);
                    return;
                case 4:
                    Method method4 = cls.getMethod(methodName, Integer.TYPE);
                    int r2 = clamp((int) (((float) Math.pow(value[0], 0.45454545454545453d)) * 255.0f));
                    int g2 = clamp((int) (((float) Math.pow(value[1], 0.45454545454545453d)) * 255.0f));
                    int b2 = clamp((int) (((float) Math.pow(value[2], 0.45454545454545453d)) * 255.0f));
                    int a2 = clamp((int) (value[3] * 255.0f));
                    int color2 = (a2 << 24) | (r2 << 16) | (g2 << 8) | b2;
                    method4.invoke(view, Integer.valueOf(color2));
                    return;
                case 5:
                    throw new RuntimeException("unable to interpolate strings " + att.getName());
                case 6:
                    Method method5 = cls.getMethod(methodName, Boolean.TYPE);
                    Object[] objArr = new Object[1];
                    if (value[0] <= 0.5f) {
                        z = false;
                    }
                    objArr[0] = Boolean.valueOf(z);
                    method5.invoke(view, objArr);
                    return;
                case 7:
                    Method method6 = cls.getMethod(methodName, Float.TYPE);
                    method6.invoke(view, Float.valueOf(value[0]));
                    return;
                default:
                    return;
            }
        } catch (IllegalAccessException e) {
            Log.e(TAG, "cannot access method " + methodName + " on View \"" + Debug.getName(view) + "\"");
            e.printStackTrace();
        } catch (NoSuchMethodException e2) {
            Log.e(TAG, "no method " + methodName + " on View \"" + Debug.getName(view) + "\"");
            e2.printStackTrace();
        } catch (InvocationTargetException e3) {
            e3.printStackTrace();
        }
    }

    /* renamed from: androidx.constraintlayout.motion.utils.CustomSupport$1  reason: invalid class name */
    /* loaded from: classes.dex */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType;

        static {
            int[] iArr = new int[ConstraintAttribute.AttributeType.values().length];
            $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType = iArr;
            try {
                iArr[ConstraintAttribute.AttributeType.INT_TYPE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.FLOAT_TYPE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.COLOR_DRAWABLE_TYPE.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.COLOR_TYPE.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.STRING_TYPE.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.BOOLEAN_TYPE.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$androidx$constraintlayout$widget$ConstraintAttribute$AttributeType[ConstraintAttribute.AttributeType.DIMENSION_TYPE.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
        }
    }

    private static int clamp(int c) {
        int c2 = (c & (~(c >> 31))) - 255;
        return (c2 & (c2 >> 31)) + 255;
    }
}
