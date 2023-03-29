package androidx.constraintlayout.core.motion.utils;

import java.lang.reflect.Array;
/* loaded from: classes.dex */
public class HyperSpline {
    double[][] mCtl;
    Cubic[][] mCurve;
    double[] mCurveLength;
    int mDimensionality;
    int mPoints;
    double mTotalLength;

    public HyperSpline(double[][] points) {
        setup(points);
    }

    public HyperSpline() {
    }

    public void setup(double[][] points) {
        int i;
        int length = points[0].length;
        this.mDimensionality = length;
        int length2 = points.length;
        this.mPoints = length2;
        this.mCtl = (double[][]) Array.newInstance(double.class, length, length2);
        this.mCurve = new Cubic[this.mDimensionality];
        for (int d = 0; d < this.mDimensionality; d++) {
            for (int p = 0; p < this.mPoints; p++) {
                this.mCtl[d][p] = points[p][d];
            }
        }
        int d2 = 0;
        while (true) {
            i = this.mDimensionality;
            if (d2 >= i) {
                break;
            }
            Cubic[][] cubicArr = this.mCurve;
            double[][] dArr = this.mCtl;
            cubicArr[d2] = calcNaturalCubic(dArr[d2].length, dArr[d2]);
            d2++;
        }
        int d3 = this.mPoints;
        this.mCurveLength = new double[d3 - 1];
        this.mTotalLength = 0.0d;
        Cubic[] temp = new Cubic[i];
        for (int p2 = 0; p2 < this.mCurveLength.length; p2++) {
            for (int d4 = 0; d4 < this.mDimensionality; d4++) {
                temp[d4] = this.mCurve[d4][p2];
            }
            double d5 = this.mTotalLength;
            double[] dArr2 = this.mCurveLength;
            double approxLength = approxLength(temp);
            dArr2[p2] = approxLength;
            this.mTotalLength = d5 + approxLength;
        }
    }

    public void getVelocity(double p, double[] v) {
        double pos = this.mTotalLength * p;
        int k = 0;
        while (true) {
            double[] dArr = this.mCurveLength;
            if (k >= dArr.length - 1 || dArr[k] >= pos) {
                break;
            }
            pos -= dArr[k];
            k++;
        }
        for (int i = 0; i < v.length; i++) {
            v[i] = this.mCurve[i][k].vel(pos / this.mCurveLength[k]);
        }
    }

    public void getPos(double p, double[] x) {
        double pos = this.mTotalLength * p;
        int k = 0;
        while (true) {
            double[] dArr = this.mCurveLength;
            if (k >= dArr.length - 1 || dArr[k] >= pos) {
                break;
            }
            pos -= dArr[k];
            k++;
        }
        for (int i = 0; i < x.length; i++) {
            x[i] = this.mCurve[i][k].eval(pos / this.mCurveLength[k]);
        }
    }

    public void getPos(double p, float[] x) {
        double pos = this.mTotalLength * p;
        int k = 0;
        while (true) {
            double[] dArr = this.mCurveLength;
            if (k >= dArr.length - 1 || dArr[k] >= pos) {
                break;
            }
            pos -= dArr[k];
            k++;
        }
        for (int i = 0; i < x.length; i++) {
            x[i] = (float) this.mCurve[i][k].eval(pos / this.mCurveLength[k]);
        }
    }

    public double getPos(double p, int splineNumber) {
        double[] dArr;
        double pos = this.mTotalLength * p;
        int k = 0;
        while (true) {
            dArr = this.mCurveLength;
            if (k >= dArr.length - 1 || dArr[k] >= pos) {
                break;
            }
            pos -= dArr[k];
            k++;
        }
        return this.mCurve[splineNumber][k].eval(pos / dArr[k]);
    }

    public double approxLength(Cubic[] curve) {
        double sum = 0.0d;
        int length = curve.length;
        double[] old = new double[curve.length];
        for (double i = 0.0d; i < 1.0d; i += 0.1d) {
            double s = 0.0d;
            for (int j = 0; j < curve.length; j++) {
                double tmp = old[j];
                double eval = curve[j].eval(i);
                old[j] = eval;
                double tmp2 = tmp - eval;
                s += tmp2 * tmp2;
            }
            if (i > 0.0d) {
                sum += Math.sqrt(s);
            }
        }
        double s2 = 0.0d;
        for (int j2 = 0; j2 < curve.length; j2++) {
            double tmp3 = old[j2];
            double eval2 = curve[j2].eval(1.0d);
            old[j2] = eval2;
            double tmp4 = tmp3 - eval2;
            s2 += tmp4 * tmp4;
        }
        return sum + Math.sqrt(s2);
    }

    static Cubic[] calcNaturalCubic(int n, double[] x) {
        double[] gamma = new double[n];
        double[] delta = new double[n];
        double[] D = new double[n];
        int n2 = n - 1;
        gamma[0] = 0.5d;
        for (int i = 1; i < n2; i++) {
            gamma[i] = 1.0d / (4.0d - gamma[i - 1]);
        }
        int i2 = n2 - 1;
        gamma[n2] = 1.0d / (2.0d - gamma[i2]);
        delta[0] = (x[1] - x[0]) * 3.0d * gamma[0];
        for (int i3 = 1; i3 < n2; i3++) {
            delta[i3] = (((x[i3 + 1] - x[i3 - 1]) * 3.0d) - delta[i3 - 1]) * gamma[i3];
        }
        delta[n2] = (((x[n2] - x[n2 - 1]) * 3.0d) - delta[n2 - 1]) * gamma[n2];
        D[n2] = delta[n2];
        for (int i4 = n2 - 1; i4 >= 0; i4--) {
            D[i4] = delta[i4] - (gamma[i4] * D[i4 + 1]);
        }
        Cubic[] C = new Cubic[n2];
        for (int i5 = 0; i5 < n2; i5++) {
            C[i5] = new Cubic((float) x[i5], D[i5], (((x[i5 + 1] - x[i5]) * 3.0d) - (D[i5] * 2.0d)) - D[i5 + 1], ((x[i5] - x[i5 + 1]) * 2.0d) + D[i5] + D[i5 + 1]);
        }
        return C;
    }

    /* loaded from: classes.dex */
    public static class Cubic {
        double mA;
        double mB;
        double mC;
        double mD;

        public Cubic(double a, double b, double c, double d) {
            this.mA = a;
            this.mB = b;
            this.mC = c;
            this.mD = d;
        }

        public double eval(double u) {
            return (((((this.mD * u) + this.mC) * u) + this.mB) * u) + this.mA;
        }

        public double vel(double v) {
            return (((this.mD * 3.0d * v) + (this.mC * 2.0d)) * v) + this.mB;
        }
    }
}
