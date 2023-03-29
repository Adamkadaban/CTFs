package com.google.android.material.color;

import androidx.core.view.ViewCompat;
import java.util.Arrays;
/* loaded from: classes.dex */
final class ColorUtils {
    private static final float[] WHITE_POINT_D65 = {95.047f, 100.0f, 108.883f};

    private ColorUtils() {
    }

    public static final float[] whitePointD65() {
        return Arrays.copyOf(WHITE_POINT_D65, 3);
    }

    public static int redFromInt(int argb) {
        return (16711680 & argb) >> 16;
    }

    public static int greenFromInt(int argb) {
        return (65280 & argb) >> 8;
    }

    public static int blueFromInt(int argb) {
        return argb & 255;
    }

    public static float lstarFromInt(int argb) {
        return (float) labFromInt(argb)[0];
    }

    public static String hexFromInt(int argb) {
        int red = redFromInt(argb);
        int blue = blueFromInt(argb);
        int green = greenFromInt(argb);
        return String.format("#%02x%02x%02x", Integer.valueOf(red), Integer.valueOf(green), Integer.valueOf(blue));
    }

    public static float[] xyzFromInt(int argb) {
        float r = linearized(redFromInt(argb) / 255.0f) * 100.0f;
        float g = linearized(greenFromInt(argb) / 255.0f) * 100.0f;
        float b = linearized(blueFromInt(argb) / 255.0f) * 100.0f;
        float x = (0.41233894f * r) + (0.35762063f * g) + (0.18051042f * b);
        float y = (0.2126f * r) + (0.7152f * g) + (0.0722f * b);
        float z = (0.01932141f * r) + (0.11916382f * g) + (0.9503448f * b);
        return new float[]{x, y, z};
    }

    public static int intFromRgb(int r, int g, int b) {
        return (((((r & 255) << 16) | ViewCompat.MEASURED_STATE_MASK) | ((g & 255) << 8)) | (b & 255)) >>> 0;
    }

    public static double[] labFromInt(int argb) {
        double fy;
        double fx;
        double d;
        double fz;
        float[] xyz = xyzFromInt(argb);
        float f = xyz[1];
        float[] fArr = WHITE_POINT_D65;
        double yNormalized = f / fArr[1];
        if (yNormalized > 0.008856451679035631d) {
            fy = Math.cbrt(yNormalized);
        } else {
            double fy2 = yNormalized * 903.2962962962963d;
            fy = (fy2 + 16.0d) / 116.0d;
        }
        double xNormalized = xyz[0] / fArr[0];
        if (xNormalized > 0.008856451679035631d) {
            fx = Math.cbrt(xNormalized);
        } else {
            double fx2 = xNormalized * 903.2962962962963d;
            fx = (fx2 + 16.0d) / 116.0d;
        }
        double zNormalized = xyz[2] / fArr[2];
        if (zNormalized > 0.008856451679035631d) {
            fz = Math.cbrt(zNormalized);
            d = 116.0d;
        } else {
            double fz2 = 903.2962962962963d * zNormalized;
            d = 116.0d;
            fz = (fz2 + 16.0d) / 116.0d;
        }
        double l = (d * fy) - 16.0d;
        double a = (fx - fy) * 500.0d;
        double b = (fy - fz) * 200.0d;
        return new double[]{l, a, b};
    }

    public static int intFromLab(double l, double a, double b) {
        double fy = (l + 16.0d) / 116.0d;
        double fx = (a / 500.0d) + fy;
        double fz = fy - (b / 200.0d);
        double fx3 = fx * fx * fx;
        double xNormalized = fx3 > 0.008856451679035631d ? fx3 : ((fx * 116.0d) - 16.0d) / 903.2962962962963d;
        double yNormalized = l > 8.0d ? fy * fy * fy : l / 903.2962962962963d;
        double fz3 = fz * fz * fz;
        double zNormalized = fz3 > 0.008856451679035631d ? fz3 : ((116.0d * fz) - 16.0d) / 903.2962962962963d;
        float[] fArr = WHITE_POINT_D65;
        double e = fArr[0];
        double x = e * xNormalized;
        double kappa = fArr[1];
        double y = kappa * yNormalized;
        double z = fArr[2] * zNormalized;
        return intFromXyzComponents((float) x, (float) y, (float) z);
    }

    public static int intFromXyzComponents(float x, float y, float z) {
        float x2 = x / 100.0f;
        float y2 = y / 100.0f;
        float z2 = z / 100.0f;
        float rL = (3.2406f * x2) + ((-1.5372f) * y2) + ((-0.4986f) * z2);
        float gL = ((-0.9689f) * x2) + (1.8758f * y2) + (0.0415f * z2);
        float bL = (0.0557f * x2) + ((-0.204f) * y2) + (1.057f * z2);
        float r = delinearized(rL);
        float g = delinearized(gL);
        float b = delinearized(bL);
        int rInt = Math.max(Math.min(255, Math.round(r * 255.0f)), 0);
        int gInt = Math.max(Math.min(255, Math.round(g * 255.0f)), 0);
        int bInt = Math.max(Math.min(255, Math.round(255.0f * b)), 0);
        return intFromRgb(rInt, gInt, bInt);
    }

    public static int intFromXyz(float[] xyz) {
        return intFromXyzComponents(xyz[0], xyz[1], xyz[2]);
    }

    public static int intFromLstar(float lstar) {
        float x;
        float z;
        float fy = (lstar + 16.0f) / 116.0f;
        boolean cubeExceedEpsilon = (fy * fy) * fy > 0.008856452f;
        boolean lExceedsEpsilonKappa = lstar > 8.0f;
        float y = lExceedsEpsilonKappa ? fy * fy * fy : lstar / 903.2963f;
        if (cubeExceedEpsilon) {
            x = fy * fy * fy;
        } else {
            x = ((fy * 116.0f) - 16.0f) / 903.2963f;
        }
        if (cubeExceedEpsilon) {
            z = fy * fy * fy;
        } else {
            z = ((116.0f * fy) - 16.0f) / 903.2963f;
        }
        float[] fArr = WHITE_POINT_D65;
        float[] xyz = {fArr[0] * x, fArr[1] * y, fArr[2] * z};
        return intFromXyz(xyz);
    }

    public static float yFromLstar(float lstar) {
        return lstar > 8.0f ? ((float) Math.pow((lstar + 16.0d) / 116.0d, 3.0d)) * 100.0f : (lstar / 903.2963f) * 100.0f;
    }

    public static float linearized(float rgb) {
        if (rgb <= 0.04045f) {
            return rgb / 12.92f;
        }
        return (float) Math.pow((0.055f + rgb) / 1.055f, 2.4000000953674316d);
    }

    public static float delinearized(float rgb) {
        if (rgb <= 0.0031308f) {
            return 12.92f * rgb;
        }
        return (((float) Math.pow(rgb, 0.4166666567325592d)) * 1.055f) - 0.055f;
    }
}
