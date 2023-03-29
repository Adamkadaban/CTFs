package com.google.android.material.color;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class ViewingConditions {
    public static final ViewingConditions DEFAULT = make(ColorUtils.whitePointD65(), (float) ((ColorUtils.yFromLstar(50.0f) * 63.66197723675813d) / 100.0d), 50.0f, 2.0f, false);
    private final float aw;
    private final float c;
    private final float fl;
    private final float flRoot;
    private final float n;
    private final float nbb;
    private final float nc;
    private final float ncb;
    private final float[] rgbD;
    private final float z;

    public float getAw() {
        return this.aw;
    }

    public float getN() {
        return this.n;
    }

    public float getNbb() {
        return this.nbb;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getNcb() {
        return this.ncb;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getC() {
        return this.c;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getNc() {
        return this.nc;
    }

    public float[] getRgbD() {
        return this.rgbD;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getFl() {
        return this.fl;
    }

    public float getFlRoot() {
        return this.flRoot;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getZ() {
        return this.z;
    }

    static ViewingConditions make(float[] whitePoint, float adaptingLuminance, float backgroundLstar, float surround, boolean discountingIlluminant) {
        float c;
        float d;
        float[][] matrix = Cam16.XYZ_TO_CAM16RGB;
        float rW = (whitePoint[0] * matrix[0][0]) + (whitePoint[1] * matrix[0][1]) + (whitePoint[2] * matrix[0][2]);
        float gW = (whitePoint[0] * matrix[1][0]) + (whitePoint[1] * matrix[1][1]) + (whitePoint[2] * matrix[1][2]);
        float bW = (whitePoint[0] * matrix[2][0]) + (whitePoint[1] * matrix[2][1]) + (whitePoint[2] * matrix[2][2]);
        float f = (surround / 10.0f) + 0.8f;
        if (f >= 0.9d) {
            c = MathUtils.lerp(0.59f, 0.69f, (f - 0.9f) * 10.0f);
        } else {
            c = MathUtils.lerp(0.525f, 0.59f, (f - 0.8f) * 10.0f);
        }
        if (!discountingIlluminant) {
            d = (1.0f - (((float) Math.exp(((-adaptingLuminance) - 42.0f) / 92.0f)) * 0.2777778f)) * f;
        } else {
            d = 1.0f;
        }
        float d2 = ((double) d) > 1.0d ? 1.0f : ((double) d) < 0.0d ? 0.0f : d;
        float[] rgbD = {(((100.0f / rW) * d2) + 1.0f) - d2, (((100.0f / gW) * d2) + 1.0f) - d2, (((100.0f / bW) * d2) + 1.0f) - d2};
        float k = 1.0f / ((5.0f * adaptingLuminance) + 1.0f);
        float k4 = k * k * k * k;
        float k4F = 1.0f - k4;
        float fl = (k4 * adaptingLuminance) + (0.1f * k4F * k4F * ((float) Math.cbrt(adaptingLuminance * 5.0d)));
        float n = ColorUtils.yFromLstar(backgroundLstar) / whitePoint[1];
        float z = ((float) Math.sqrt(n)) + 1.48f;
        float nbb = 0.725f / ((float) Math.pow(n, 0.2d));
        float[] rgbAFactors = {(float) Math.pow(((rgbD[0] * fl) * rW) / 100.0d, 0.42d), (float) Math.pow(((rgbD[1] * fl) * gW) / 100.0d, 0.42d), (float) Math.pow(((rgbD[2] * fl) * bW) / 100.0d, 0.42d)};
        float[] rgbA = {(rgbAFactors[0] * 400.0f) / (rgbAFactors[0] + 27.13f), (rgbAFactors[1] * 400.0f) / (rgbAFactors[1] + 27.13f), (rgbAFactors[2] * 400.0f) / (rgbAFactors[2] + 27.13f)};
        float aw = ((rgbA[0] * 2.0f) + rgbA[1] + (rgbA[2] * 0.05f)) * nbb;
        return new ViewingConditions(n, aw, nbb, nbb, c, f, rgbD, fl, (float) Math.pow(fl, 0.25d), z);
    }

    private ViewingConditions(float n, float aw, float nbb, float ncb, float c, float nc, float[] rgbD, float fl, float flRoot, float z) {
        this.n = n;
        this.aw = aw;
        this.nbb = nbb;
        this.ncb = ncb;
        this.c = c;
        this.nc = nc;
        this.rgbD = rgbD;
        this.fl = fl;
        this.flRoot = flRoot;
        this.z = z;
    }
}
