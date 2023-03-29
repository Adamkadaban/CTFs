package androidx.constraintlayout.core.motion.utils;

import androidx.constraintlayout.core.motion.MotionWidget;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.lang.reflect.Array;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
/* loaded from: classes.dex */
public abstract class KeyCycleOscillator {
    private static final String TAG = "KeyCycleOscillator";
    private CurveFit mCurveFit;
    private CycleOscillator mCycleOscillator;
    private String mType;
    private int mWaveShape = 0;
    private String mWaveString = null;
    public int mVariesBy = 0;
    ArrayList<WavePoint> mWavePoints = new ArrayList<>();

    public static KeyCycleOscillator makeWidgetCycle(String attribute) {
        if (attribute.equals("pathRotate")) {
            return new PathRotateSet(attribute);
        }
        return new CoreSpline(attribute);
    }

    /* loaded from: classes.dex */
    private static class CoreSpline extends KeyCycleOscillator {
        String type;
        int typeId;

        public CoreSpline(String str) {
            this.type = str;
            this.typeId = TypedValues.CycleType.CC.getId(str);
        }

        @Override // androidx.constraintlayout.core.motion.utils.KeyCycleOscillator
        public void setProperty(MotionWidget widget, float t) {
            widget.setValue(this.typeId, get(t));
        }
    }

    /* loaded from: classes.dex */
    public static class PathRotateSet extends KeyCycleOscillator {
        String type;
        int typeId;

        public PathRotateSet(String str) {
            this.type = str;
            this.typeId = TypedValues.CycleType.CC.getId(str);
        }

        @Override // androidx.constraintlayout.core.motion.utils.KeyCycleOscillator
        public void setProperty(MotionWidget widget, float t) {
            widget.setValue(this.typeId, get(t));
        }

        public void setPathRotate(MotionWidget view, float t, double dx, double dy) {
            view.setRotationZ(get(t) + ((float) Math.toDegrees(Math.atan2(dy, dx))));
        }
    }

    public boolean variesByPath() {
        return this.mVariesBy == 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class WavePoint {
        float mOffset;
        float mPeriod;
        float mPhase;
        int mPosition;
        float mValue;

        public WavePoint(int position, float period, float offset, float phase, float value) {
            this.mPosition = position;
            this.mValue = value;
            this.mOffset = offset;
            this.mPeriod = period;
            this.mPhase = phase;
        }
    }

    public String toString() {
        String str = this.mType;
        DecimalFormat df = new DecimalFormat("##.##");
        Iterator<WavePoint> it = this.mWavePoints.iterator();
        while (it.hasNext()) {
            WavePoint wp = it.next();
            str = str + "[" + wp.mPosition + " , " + df.format(wp.mValue) + "] ";
        }
        return str;
    }

    public void setType(String type) {
        this.mType = type;
    }

    public float get(float t) {
        return (float) this.mCycleOscillator.getValues(t);
    }

    public float getSlope(float position) {
        return (float) this.mCycleOscillator.getSlope(position);
    }

    public CurveFit getCurveFit() {
        return this.mCurveFit;
    }

    protected void setCustom(Object custom) {
    }

    public void setPoint(int framePosition, int shape, String waveString, int variesBy, float period, float offset, float phase, float value, Object custom) {
        this.mWavePoints.add(new WavePoint(framePosition, period, offset, phase, value));
        if (variesBy != -1) {
            this.mVariesBy = variesBy;
        }
        this.mWaveShape = shape;
        setCustom(custom);
        this.mWaveString = waveString;
    }

    public void setPoint(int framePosition, int shape, String waveString, int variesBy, float period, float offset, float phase, float value) {
        this.mWavePoints.add(new WavePoint(framePosition, period, offset, phase, value));
        if (variesBy != -1) {
            this.mVariesBy = variesBy;
        }
        this.mWaveShape = shape;
        this.mWaveString = waveString;
    }

    public void setup(float pathLength) {
        int count = this.mWavePoints.size();
        if (count != 0) {
            Collections.sort(this.mWavePoints, new Comparator<WavePoint>() { // from class: androidx.constraintlayout.core.motion.utils.KeyCycleOscillator.1
                @Override // java.util.Comparator
                public int compare(WavePoint lhs, WavePoint rhs) {
                    return Integer.compare(lhs.mPosition, rhs.mPosition);
                }
            });
            double[] time = new double[count];
            double[][] values = (double[][]) Array.newInstance(double.class, count, 3);
            this.mCycleOscillator = new CycleOscillator(this.mWaveShape, this.mWaveString, this.mVariesBy, count);
            int i = 0;
            Iterator<WavePoint> it = this.mWavePoints.iterator();
            while (it.hasNext()) {
                WavePoint wp = it.next();
                time[i] = wp.mPeriod * 0.01d;
                values[i][0] = wp.mValue;
                values[i][1] = wp.mOffset;
                values[i][2] = wp.mPhase;
                this.mCycleOscillator.setPoint(i, wp.mPosition, wp.mPeriod, wp.mOffset, wp.mPhase, wp.mValue);
                i++;
            }
            this.mCycleOscillator.setup(pathLength);
            this.mCurveFit = CurveFit.get(0, time, values);
        }
    }

    /* loaded from: classes.dex */
    private static class IntDoubleSort {
        private IntDoubleSort() {
        }

        static void sort(int[] key, float[] value, int low, int hi) {
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
    private static class IntFloatFloatSort {
        private IntFloatFloatSort() {
        }

        static void sort(int[] key, float[] value1, float[] value2, int low, int hi) {
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
                    int p = partition(key, value1, value2, low2, hi2);
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

        private static int partition(int[] array, float[] value1, float[] value2, int low, int hi) {
            int pivot = array[hi];
            int i = low;
            for (int j = low; j < hi; j++) {
                if (array[j] <= pivot) {
                    swap(array, value1, value2, i, j);
                    i++;
                }
            }
            swap(array, value1, value2, i, hi);
            return i;
        }

        private static void swap(int[] array, float[] value1, float[] value2, int a, int b) {
            int tmp = array[a];
            array[a] = array[b];
            array[b] = tmp;
            float tmpFloat = value1[a];
            value1[a] = value1[b];
            value1[b] = tmpFloat;
            float tmpFloat2 = value2[a];
            value2[a] = value2[b];
            value2[b] = tmpFloat2;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class CycleOscillator {
        private static final String TAG = "CycleOscillator";
        static final int UNSET = -1;
        private final int OFFST;
        private final int PHASE;
        private final int VALUE;
        CurveFit mCurveFit;
        float[] mOffset;
        Oscillator mOscillator;
        float mPathLength;
        float[] mPeriod;
        float[] mPhase;
        double[] mPosition;
        float[] mScale;
        double[] mSplineSlopeCache;
        double[] mSplineValueCache;
        float[] mValues;
        private final int mVariesBy;
        int mWaveShape;

        CycleOscillator(int waveShape, String customShape, int variesBy, int steps) {
            Oscillator oscillator = new Oscillator();
            this.mOscillator = oscillator;
            this.OFFST = 0;
            this.PHASE = 1;
            this.VALUE = 2;
            this.mWaveShape = waveShape;
            this.mVariesBy = variesBy;
            oscillator.setType(waveShape, customShape);
            this.mValues = new float[steps];
            this.mPosition = new double[steps];
            this.mPeriod = new float[steps];
            this.mOffset = new float[steps];
            this.mPhase = new float[steps];
            this.mScale = new float[steps];
        }

        public double getValues(float time) {
            CurveFit curveFit = this.mCurveFit;
            if (curveFit != null) {
                curveFit.getPos(time, this.mSplineValueCache);
            } else {
                double[] dArr = this.mSplineValueCache;
                dArr[0] = this.mOffset[0];
                dArr[1] = this.mPhase[0];
                dArr[2] = this.mValues[0];
            }
            double[] dArr2 = this.mSplineValueCache;
            double offset = dArr2[0];
            double phase = dArr2[1];
            double waveValue = this.mOscillator.getValue(time, phase);
            return (this.mSplineValueCache[2] * waveValue) + offset;
        }

        public double getLastPhase() {
            return this.mSplineValueCache[1];
        }

        public double getSlope(float time) {
            CurveFit curveFit = this.mCurveFit;
            if (curveFit != null) {
                curveFit.getSlope(time, this.mSplineSlopeCache);
                this.mCurveFit.getPos(time, this.mSplineValueCache);
            } else {
                double[] dArr = this.mSplineSlopeCache;
                dArr[0] = 0.0d;
                dArr[1] = 0.0d;
                dArr[2] = 0.0d;
            }
            double waveValue = this.mOscillator.getValue(time, this.mSplineValueCache[1]);
            double waveSlope = this.mOscillator.getSlope(time, this.mSplineValueCache[1], this.mSplineSlopeCache[1]);
            double[] dArr2 = this.mSplineSlopeCache;
            return dArr2[0] + (dArr2[2] * waveValue) + (this.mSplineValueCache[2] * waveSlope);
        }

        public void setPoint(int index, int framePosition, float wavePeriod, float offset, float phase, float values) {
            this.mPosition[index] = framePosition / 100.0d;
            this.mPeriod[index] = wavePeriod;
            this.mOffset[index] = offset;
            this.mPhase[index] = phase;
            this.mValues[index] = values;
        }

        public void setup(float pathLength) {
            this.mPathLength = pathLength;
            double[][] splineValues = (double[][]) Array.newInstance(double.class, this.mPosition.length, 3);
            float[] fArr = this.mValues;
            this.mSplineValueCache = new double[fArr.length + 2];
            this.mSplineSlopeCache = new double[fArr.length + 2];
            if (this.mPosition[0] > 0.0d) {
                this.mOscillator.addPoint(0.0d, this.mPeriod[0]);
            }
            double[] dArr = this.mPosition;
            int last = dArr.length - 1;
            if (dArr[last] < 1.0d) {
                this.mOscillator.addPoint(1.0d, this.mPeriod[last]);
            }
            for (int i = 0; i < splineValues.length; i++) {
                splineValues[i][0] = this.mOffset[i];
                splineValues[i][1] = this.mPhase[i];
                splineValues[i][2] = this.mValues[i];
                this.mOscillator.addPoint(this.mPosition[i], this.mPeriod[i]);
            }
            this.mOscillator.normalize();
            double[] dArr2 = this.mPosition;
            if (dArr2.length > 1) {
                this.mCurveFit = CurveFit.get(0, dArr2, splineValues);
            } else {
                this.mCurveFit = null;
            }
        }
    }

    public void setProperty(MotionWidget widget, float t) {
    }
}
