package androidx.constraintlayout.core.motion.utils;
/* loaded from: classes.dex */
public abstract class CurveFit {
    public static final int CONSTANT = 2;
    public static final int LINEAR = 1;
    public static final int SPLINE = 0;

    public abstract double getPos(double d, int i);

    public abstract void getPos(double d, double[] dArr);

    public abstract void getPos(double d, float[] fArr);

    public abstract double getSlope(double d, int i);

    public abstract void getSlope(double d, double[] dArr);

    public abstract double[] getTimePoints();

    public static CurveFit get(int type, double[] time, double[][] y) {
        if (time.length == 1) {
            type = 2;
        }
        switch (type) {
            case 0:
                return new MonotonicCurveFit(time, y);
            case 1:
            default:
                return new LinearCurveFit(time, y);
            case 2:
                return new Constant(time[0], y[0]);
        }
    }

    public static CurveFit getArc(int[] arcModes, double[] time, double[][] y) {
        return new ArcCurveFit(arcModes, time, y);
    }

    /* loaded from: classes.dex */
    static class Constant extends CurveFit {
        double mTime;
        double[] mValue;

        Constant(double time, double[] value) {
            this.mTime = time;
            this.mValue = value;
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public void getPos(double t, double[] v) {
            double[] dArr = this.mValue;
            System.arraycopy(dArr, 0, v, 0, dArr.length);
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public void getPos(double t, float[] v) {
            int i = 0;
            while (true) {
                double[] dArr = this.mValue;
                if (i < dArr.length) {
                    v[i] = (float) dArr[i];
                    i++;
                } else {
                    return;
                }
            }
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public double getPos(double t, int j) {
            return this.mValue[j];
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public void getSlope(double t, double[] v) {
            for (int i = 0; i < this.mValue.length; i++) {
                v[i] = 0.0d;
            }
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public double getSlope(double t, int j) {
            return 0.0d;
        }

        @Override // androidx.constraintlayout.core.motion.utils.CurveFit
        public double[] getTimePoints() {
            return new double[]{this.mTime};
        }
    }
}
