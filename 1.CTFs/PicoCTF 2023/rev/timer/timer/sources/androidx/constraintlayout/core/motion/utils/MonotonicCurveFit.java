package androidx.constraintlayout.core.motion.utils;

import java.lang.reflect.Array;
import java.util.Arrays;
/* loaded from: classes.dex */
public class MonotonicCurveFit extends CurveFit {
    private static final String TAG = "MonotonicCurveFit";
    private boolean mExtrapolate = true;
    double[] mSlopeTemp;
    private double[] mT;
    private double[][] mTangent;
    private double[][] mY;

    public MonotonicCurveFit(double[] time, double[][] y) {
        int N = time.length;
        int dim = y[0].length;
        this.mSlopeTemp = new double[dim];
        double[][] slope = (double[][]) Array.newInstance(double.class, N - 1, dim);
        double[][] tangent = (double[][]) Array.newInstance(double.class, N, dim);
        for (int j = 0; j < dim; j++) {
            for (int i = 0; i < N - 1; i++) {
                double dt = time[i + 1] - time[i];
                slope[i][j] = (y[i + 1][j] - y[i][j]) / dt;
                if (i == 0) {
                    tangent[i][j] = slope[i][j];
                } else {
                    tangent[i][j] = (slope[i - 1][j] + slope[i][j]) * 0.5d;
                }
            }
            int i2 = N - 1;
            tangent[i2][j] = slope[N - 2][j];
        }
        for (int i3 = 0; i3 < N - 1; i3++) {
            for (int j2 = 0; j2 < dim; j2++) {
                if (slope[i3][j2] == 0.0d) {
                    tangent[i3][j2] = 0.0d;
                    tangent[i3 + 1][j2] = 0.0d;
                } else {
                    double a = tangent[i3][j2] / slope[i3][j2];
                    double b = tangent[i3 + 1][j2] / slope[i3][j2];
                    double h = Math.hypot(a, b);
                    if (h > 9.0d) {
                        double t = 3.0d / h;
                        tangent[i3][j2] = t * a * slope[i3][j2];
                        tangent[i3 + 1][j2] = t * b * slope[i3][j2];
                    }
                }
            }
        }
        this.mT = time;
        this.mY = y;
        this.mTangent = tangent;
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public void getPos(double t, double[] v) {
        double[] dArr = this.mT;
        int n = dArr.length;
        int dim = this.mY[0].length;
        if (this.mExtrapolate) {
            if (t <= dArr[0]) {
                getSlope(dArr[0], this.mSlopeTemp);
                for (int j = 0; j < dim; j++) {
                    v[j] = this.mY[0][j] + ((t - this.mT[0]) * this.mSlopeTemp[j]);
                }
                return;
            } else if (t >= dArr[n - 1]) {
                getSlope(dArr[n - 1], this.mSlopeTemp);
                for (int j2 = 0; j2 < dim; j2++) {
                    v[j2] = this.mY[n - 1][j2] + ((t - this.mT[n - 1]) * this.mSlopeTemp[j2]);
                }
                return;
            }
        } else if (t <= dArr[0]) {
            for (int j3 = 0; j3 < dim; j3++) {
                v[j3] = this.mY[0][j3];
            }
            return;
        } else if (t >= dArr[n - 1]) {
            for (int j4 = 0; j4 < dim; j4++) {
                v[j4] = this.mY[n - 1][j4];
            }
            return;
        }
        for (int i = 0; i < n - 1; i++) {
            if (t == this.mT[i]) {
                for (int j5 = 0; j5 < dim; j5++) {
                    v[j5] = this.mY[i][j5];
                }
            }
            double[] dArr2 = this.mT;
            if (t < dArr2[i + 1]) {
                double h = dArr2[i + 1] - dArr2[i];
                double x = (t - dArr2[i]) / h;
                for (int j6 = 0; j6 < dim; j6++) {
                    double[][] dArr3 = this.mY;
                    double y1 = dArr3[i][j6];
                    double y2 = dArr3[i + 1][j6];
                    double[][] dArr4 = this.mTangent;
                    double t1 = dArr4[i][j6];
                    double t2 = dArr4[i + 1][j6];
                    v[j6] = interpolate(h, x, y1, y2, t1, t2);
                }
                return;
            }
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public void getPos(double t, float[] v) {
        double[] dArr = this.mT;
        int n = dArr.length;
        int dim = this.mY[0].length;
        if (this.mExtrapolate) {
            if (t <= dArr[0]) {
                getSlope(dArr[0], this.mSlopeTemp);
                for (int j = 0; j < dim; j++) {
                    v[j] = (float) (this.mY[0][j] + ((t - this.mT[0]) * this.mSlopeTemp[j]));
                }
                return;
            } else if (t >= dArr[n - 1]) {
                getSlope(dArr[n - 1], this.mSlopeTemp);
                for (int j2 = 0; j2 < dim; j2++) {
                    v[j2] = (float) (this.mY[n - 1][j2] + ((t - this.mT[n - 1]) * this.mSlopeTemp[j2]));
                }
                return;
            }
        } else if (t <= dArr[0]) {
            for (int j3 = 0; j3 < dim; j3++) {
                v[j3] = (float) this.mY[0][j3];
            }
            return;
        } else if (t >= dArr[n - 1]) {
            for (int j4 = 0; j4 < dim; j4++) {
                v[j4] = (float) this.mY[n - 1][j4];
            }
            return;
        }
        for (int i = 0; i < n - 1; i++) {
            if (t == this.mT[i]) {
                for (int j5 = 0; j5 < dim; j5++) {
                    v[j5] = (float) this.mY[i][j5];
                }
            }
            double[] dArr2 = this.mT;
            if (t < dArr2[i + 1]) {
                double h = dArr2[i + 1] - dArr2[i];
                double x = (t - dArr2[i]) / h;
                for (int j6 = 0; j6 < dim; j6++) {
                    double[][] dArr3 = this.mY;
                    double y1 = dArr3[i][j6];
                    double y2 = dArr3[i + 1][j6];
                    double[][] dArr4 = this.mTangent;
                    double t1 = dArr4[i][j6];
                    double t2 = dArr4[i + 1][j6];
                    v[j6] = (float) interpolate(h, x, y1, y2, t1, t2);
                }
                return;
            }
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public double getPos(double t, int j) {
        double[] dArr = this.mT;
        int n = dArr.length;
        if (this.mExtrapolate) {
            if (t <= dArr[0]) {
                return this.mY[0][j] + ((t - dArr[0]) * getSlope(dArr[0], j));
            }
            if (t >= dArr[n - 1]) {
                return this.mY[n - 1][j] + ((t - dArr[n - 1]) * getSlope(dArr[n - 1], j));
            }
        } else if (t <= dArr[0]) {
            return this.mY[0][j];
        } else {
            if (t >= dArr[n - 1]) {
                return this.mY[n - 1][j];
            }
        }
        for (int i = 0; i < n - 1; i++) {
            double[] dArr2 = this.mT;
            if (t == dArr2[i]) {
                return this.mY[i][j];
            }
            if (t < dArr2[i + 1]) {
                double h = dArr2[i + 1] - dArr2[i];
                double x = (t - dArr2[i]) / h;
                double[][] dArr3 = this.mY;
                double y1 = dArr3[i][j];
                double y2 = dArr3[i + 1][j];
                double[][] dArr4 = this.mTangent;
                double t1 = dArr4[i][j];
                double t2 = dArr4[i + 1][j];
                return interpolate(h, x, y1, y2, t1, t2);
            }
        }
        return 0.0d;
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public void getSlope(double t, double[] v) {
        double t2;
        double[] dArr = this.mT;
        int n = dArr.length;
        int dim = this.mY[0].length;
        if (t <= dArr[0]) {
            t2 = dArr[0];
        } else if (t < dArr[n - 1]) {
            t2 = t;
        } else {
            t2 = dArr[n - 1];
        }
        for (int i = 0; i < n - 1; i++) {
            double[] dArr2 = this.mT;
            if (t2 <= dArr2[i + 1]) {
                double h = dArr2[i + 1] - dArr2[i];
                double x = (t2 - dArr2[i]) / h;
                for (int j = 0; j < dim; j++) {
                    double[][] dArr3 = this.mY;
                    double y1 = dArr3[i][j];
                    double y2 = dArr3[i + 1][j];
                    double[][] dArr4 = this.mTangent;
                    double t1 = dArr4[i][j];
                    double t22 = dArr4[i + 1][j];
                    v[j] = diff(h, x, y1, y2, t1, t22) / h;
                }
                return;
            }
        }
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public double getSlope(double t, int j) {
        double t2;
        double[] dArr = this.mT;
        int n = dArr.length;
        if (t < dArr[0]) {
            t2 = dArr[0];
        } else if (t < dArr[n - 1]) {
            t2 = t;
        } else {
            t2 = dArr[n - 1];
        }
        for (int i = 0; i < n - 1; i++) {
            double[] dArr2 = this.mT;
            if (t2 <= dArr2[i + 1]) {
                double h = dArr2[i + 1] - dArr2[i];
                double x = (t2 - dArr2[i]) / h;
                double[][] dArr3 = this.mY;
                double y1 = dArr3[i][j];
                double y2 = dArr3[i + 1][j];
                double[][] dArr4 = this.mTangent;
                double t1 = dArr4[i][j];
                double t22 = dArr4[i + 1][j];
                return diff(h, x, y1, y2, t1, t22) / h;
            }
        }
        return 0.0d;
    }

    @Override // androidx.constraintlayout.core.motion.utils.CurveFit
    public double[] getTimePoints() {
        return this.mT;
    }

    private static double interpolate(double h, double x, double y1, double y2, double t1, double t2) {
        double x2 = x * x;
        double x3 = x2 * x;
        return (((((((((((-2.0d) * x3) * y2) + ((x2 * 3.0d) * y2)) + ((x3 * 2.0d) * y1)) - ((3.0d * x2) * y1)) + y1) + ((h * t2) * x3)) + ((h * t1) * x3)) - ((h * t2) * x2)) - (((h * 2.0d) * t1) * x2)) + (h * t1 * x);
    }

    private static double diff(double h, double x, double y1, double y2, double t1, double t2) {
        double x2 = x * x;
        return ((((((((((-6.0d) * x2) * y2) + ((x * 6.0d) * y2)) + ((x2 * 6.0d) * y1)) - ((6.0d * x) * y1)) + (((h * 3.0d) * t2) * x2)) + (((3.0d * h) * t1) * x2)) - (((2.0d * h) * t2) * x)) - (((4.0d * h) * t1) * x)) + (h * t1);
    }

    public static MonotonicCurveFit buildWave(String configString) {
        double[] values = new double[configString.length() / 2];
        int start = configString.indexOf(40) + 1;
        int off1 = configString.indexOf(44, start);
        int count = 0;
        while (off1 != -1) {
            String tmp = configString.substring(start, off1).trim();
            int count2 = count + 1;
            values[count] = Double.parseDouble(tmp);
            int i = off1 + 1;
            start = i;
            off1 = configString.indexOf(44, i);
            count = count2;
        }
        int off12 = configString.indexOf(41, start);
        String tmp2 = configString.substring(start, off12).trim();
        values[count] = Double.parseDouble(tmp2);
        return buildWave(Arrays.copyOf(values, count + 1));
    }

    private static MonotonicCurveFit buildWave(double[] values) {
        int length = (values.length * 3) - 2;
        int len = values.length - 1;
        double gap = 1.0d / len;
        double[][] points = (double[][]) Array.newInstance(double.class, length, 1);
        double[] time = new double[length];
        for (int i = 0; i < values.length; i++) {
            double v = values[i];
            points[i + len][0] = v;
            time[i + len] = i * gap;
            if (i > 0) {
                points[(len * 2) + i][0] = v + 1.0d;
                time[(len * 2) + i] = (i * gap) + 1.0d;
                points[i - 1][0] = (v - 1.0d) - gap;
                time[i - 1] = ((i * gap) - 1.0d) - gap;
            }
        }
        return new MonotonicCurveFit(time, points);
    }
}
