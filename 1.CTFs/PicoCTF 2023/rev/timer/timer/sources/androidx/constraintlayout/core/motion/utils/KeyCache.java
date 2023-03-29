package androidx.constraintlayout.core.motion.utils;

import java.util.Arrays;
import java.util.HashMap;
/* loaded from: classes.dex */
public class KeyCache {
    HashMap<Object, HashMap<String, float[]>> map = new HashMap<>();

    public void setFloatValue(Object view, String type, int element, float value) {
        if (!this.map.containsKey(view)) {
            HashMap<String, float[]> array = new HashMap<>();
            float[] vArray = new float[element + 1];
            vArray[element] = value;
            array.put(type, vArray);
            this.map.put(view, array);
            return;
        }
        HashMap<String, float[]> array2 = this.map.get(view);
        if (array2 == null) {
            array2 = new HashMap<>();
        }
        if (!array2.containsKey(type)) {
            float[] vArray2 = new float[element + 1];
            vArray2[element] = value;
            array2.put(type, vArray2);
            this.map.put(view, array2);
            return;
        }
        float[] vArray3 = array2.get(type);
        if (vArray3 == null) {
            vArray3 = new float[0];
        }
        if (vArray3.length <= element) {
            vArray3 = Arrays.copyOf(vArray3, element + 1);
        }
        vArray3[element] = value;
        array2.put(type, vArray3);
    }

    public float getFloatValue(Object view, String type, int element) {
        HashMap<String, float[]> array;
        float[] vArray;
        if (this.map.containsKey(view) && (array = this.map.get(view)) != null && array.containsKey(type) && (vArray = array.get(type)) != null && vArray.length > element) {
            return vArray[element];
        }
        return Float.NaN;
    }
}
