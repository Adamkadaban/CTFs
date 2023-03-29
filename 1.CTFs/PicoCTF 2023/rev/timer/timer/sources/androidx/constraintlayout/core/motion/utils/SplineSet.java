package androidx.constraintlayout.core.motion.utils;

import androidx.constraintlayout.core.motion.CustomAttribute;
import androidx.constraintlayout.core.motion.CustomVariable;
import androidx.constraintlayout.core.motion.MotionWidget;
import androidx.constraintlayout.core.motion.utils.KeyFrameArray;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.constraintlayout.core.state.WidgetFrame;
import java.lang.reflect.Array;
import java.text.DecimalFormat;
import java.util.Arrays;
/* loaded from: classes.dex */
public abstract class SplineSet {
    private static final String TAG = "SplineSet";
    private int count;
    protected CurveFit mCurveFit;
    private String mType;
    protected int[] mTimePoints = new int[10];
    protected float[] mValues = new float[10];

    public void setProperty(TypedValues widget, float t) {
        widget.setValue(TypedValues.AttributesType.CC.getId(this.mType), get(t));
    }

    public String toString() {
        String str = this.mType;
        DecimalFormat df = new DecimalFormat("##.##");
        for (int i = 0; i < this.count; i++) {
            str = str + "[" + this.mTimePoints[i] + " , " + df.format(this.mValues[i]) + "] ";
        }
        return str;
    }

    public void setType(String type) {
        this.mType = type;
    }

    public float get(float t) {
        return (float) this.mCurveFit.getPos(t, 0);
    }

    public float getSlope(float t) {
        return (float) this.mCurveFit.getSlope(t, 0);
    }

    public CurveFit getCurveFit() {
        return this.mCurveFit;
    }

    public void setPoint(int position, float value) {
        int[] iArr = this.mTimePoints;
        if (iArr.length < this.count + 1) {
            this.mTimePoints = Arrays.copyOf(iArr, iArr.length * 2);
            float[] fArr = this.mValues;
            this.mValues = Arrays.copyOf(fArr, fArr.length * 2);
        }
        int[] iArr2 = this.mTimePoints;
        int i = this.count;
        iArr2[i] = position;
        this.mValues[i] = value;
        this.count = i + 1;
    }

    public void setup(int curveType) {
        int i;
        int i2 = this.count;
        if (i2 == 0) {
            return;
        }
        Sort.doubleQuickSort(this.mTimePoints, this.mValues, 0, i2 - 1);
        int unique = 1;
        for (int i3 = 1; i3 < this.count; i3++) {
            int[] iArr = this.mTimePoints;
            if (iArr[i3 - 1] != iArr[i3]) {
                unique++;
            }
        }
        double[] time = new double[unique];
        double[][] values = (double[][]) Array.newInstance(double.class, unique, 1);
        int k = 0;
        while (i < this.count) {
            if (i > 0) {
                int[] iArr2 = this.mTimePoints;
                i = iArr2[i] == iArr2[i + (-1)] ? i + 1 : 0;
            }
            time[k] = this.mTimePoints[i] * 0.01d;
            values[k][0] = this.mValues[i];
            k++;
        }
        this.mCurveFit = CurveFit.get(curveType, time, values);
    }

    public static SplineSet makeCustomSpline(String str, KeyFrameArray.CustomArray attrList) {
        return new CustomSet(str, attrList);
    }

    public static SplineSet makeCustomSplineSet(String str, KeyFrameArray.CustomVar attrList) {
        return new CustomSpline(str, attrList);
    }

    public static SplineSet makeSpline(String str, long currentTime) {
        return new CoreSpline(str, currentTime);
    }

    /* loaded from: classes.dex */
    private static class Sort {
        private Sort() {
        }

        static void doubleQuickSort(int[] key, float[] value, int low, int hi) {
            int[] stack = new int[key.length + 10];
            int count = 0 + 1;
            stack[0] = hi;
            int count2 = count + 1;
            stack[count] = low;
            while (count2 > 0) {
                int count3 = count2 - 1;
                int low2 = stack[count3];
                count2 = count3 - 1;
                int hi2 = stack[count2];
                if (low2 < hi2) {
                    int p = partition(key, value, low2, hi2);
                    int count4 = count2 + 1;
                    stack[count2] = p - 1;
                    int count5 = count4 + 1;
                    stack[count4] = low2;
                    int count6 = count5 + 1;
                    stack[count5] = hi2;
                    count2 = count6 + 1;
                    stack[count6] = p + 1;
                }
            }
        }

        private static int partition(int[] array, float[] value, int low, int hi) {
            int pivot = array[hi];
            int i = low;
            for (int j = low; j < hi; j++) {
                if (array[j] <= pivot) {
                    swap(array, value, i, j);
                    i++;
                }
            }
            swap(array, value, i, hi);
            return i;
        }

        private static void swap(int[] array, float[] value, int a, int b) {
            int tmp = array[a];
            array[a] = array[b];
            array[b] = tmp;
            float tmpv = value[a];
            value[a] = value[b];
            value[b] = tmpv;
        }
    }

    /* loaded from: classes.dex */
    public static class CustomSet extends SplineSet {
        String mAttributeName;
        KeyFrameArray.CustomArray mConstraintAttributeList;
        float[] mTempValues;

        public CustomSet(String attribute, KeyFrameArray.CustomArray attrList) {
            this.mAttributeName = attribute.split(",")[1];
            this.mConstraintAttributeList = attrList;
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setup(int curveType) {
            int size = this.mConstraintAttributeList.size();
            int dimensionality = this.mConstraintAttributeList.valueAt(0).numberOfInterpolatedValues();
            double[] time = new double[size];
            this.mTempValues = new float[dimensionality];
            double[][] values = (double[][]) Array.newInstance(double.class, size, dimensionality);
            for (int i = 0; i < size; i++) {
                int key = this.mConstraintAttributeList.keyAt(i);
                CustomAttribute ca = this.mConstraintAttributeList.valueAt(i);
                time[i] = key * 0.01d;
                ca.getValuesToInterpolate(this.mTempValues);
                int k = 0;
                while (true) {
                    float[] fArr = this.mTempValues;
                    if (k < fArr.length) {
                        values[i][k] = fArr[k];
                        k++;
                    }
                }
            }
            this.mCurveFit = CurveFit.get(curveType, time, values);
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setPoint(int position, float value) {
            throw new RuntimeException("don't call for custom attribute call setPoint(pos, ConstraintAttribute)");
        }

        public void setPoint(int position, CustomAttribute value) {
            this.mConstraintAttributeList.append(position, value);
        }

        public void setProperty(WidgetFrame view, float t) {
            this.mCurveFit.getPos(t, this.mTempValues);
            view.setCustomValue(this.mConstraintAttributeList.valueAt(0), this.mTempValues);
        }
    }

    /* loaded from: classes.dex */
    private static class CoreSpline extends SplineSet {
        long start;
        String type;

        public CoreSpline(String str, long currentTime) {
            this.type = str;
            this.start = currentTime;
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setProperty(TypedValues widget, float t) {
            int id = widget.getId(this.type);
            widget.setValue(id, get(t));
        }
    }

    /* loaded from: classes.dex */
    public static class CustomSpline extends SplineSet {
        String mAttributeName;
        KeyFrameArray.CustomVar mConstraintAttributeList;
        float[] mTempValues;

        public CustomSpline(String attribute, KeyFrameArray.CustomVar attrList) {
            this.mAttributeName = attribute.split(",")[1];
            this.mConstraintAttributeList = attrList;
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setup(int curveType) {
            int size = this.mConstraintAttributeList.size();
            int dimensionality = this.mConstraintAttributeList.valueAt(0).numberOfInterpolatedValues();
            double[] time = new double[size];
            this.mTempValues = new float[dimensionality];
            double[][] values = (double[][]) Array.newInstance(double.class, size, dimensionality);
            for (int i = 0; i < size; i++) {
                int key = this.mConstraintAttributeList.keyAt(i);
                CustomVariable ca = this.mConstraintAttributeList.valueAt(i);
                time[i] = key * 0.01d;
                ca.getValuesToInterpolate(this.mTempValues);
                int k = 0;
                while (true) {
                    float[] fArr = this.mTempValues;
                    if (k < fArr.length) {
                        values[i][k] = fArr[k];
                        k++;
                    }
                }
            }
            this.mCurveFit = CurveFit.get(curveType, time, values);
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setPoint(int position, float value) {
            throw new RuntimeException("don't call for custom attribute call setPoint(pos, ConstraintAttribute)");
        }

        @Override // androidx.constraintlayout.core.motion.utils.SplineSet
        public void setProperty(TypedValues widget, float t) {
            setProperty((MotionWidget) widget, t);
        }

        public void setPoint(int position, CustomVariable value) {
            this.mConstraintAttributeList.append(position, value);
        }

        public void setProperty(MotionWidget view, float t) {
            this.mCurveFit.getPos(t, this.mTempValues);
            this.mConstraintAttributeList.valueAt(0).setInterpolatedValue(view, this.mTempValues);
        }
    }
}
