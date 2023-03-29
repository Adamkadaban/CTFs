package androidx.core.graphics;

import android.graphics.Color;
import java.util.Objects;
/* loaded from: classes.dex */
public final class ColorUtils {
    private static final int MIN_ALPHA_SEARCH_MAX_ITERATIONS = 10;
    private static final int MIN_ALPHA_SEARCH_PRECISION = 1;
    private static final ThreadLocal<double[]> TEMP_ARRAY = new ThreadLocal<>();
    private static final double XYZ_EPSILON = 0.008856d;
    private static final double XYZ_KAPPA = 903.3d;
    private static final double XYZ_WHITE_REFERENCE_X = 95.047d;
    private static final double XYZ_WHITE_REFERENCE_Y = 100.0d;
    private static final double XYZ_WHITE_REFERENCE_Z = 108.883d;

    private ColorUtils() {
    }

    public static int compositeColors(int foreground, int background) {
        int bgAlpha = Color.alpha(background);
        int fgAlpha = Color.alpha(foreground);
        int a = compositeAlpha(fgAlpha, bgAlpha);
        int r = compositeComponent(Color.red(foreground), fgAlpha, Color.red(background), bgAlpha, a);
        int g = compositeComponent(Color.green(foreground), fgAlpha, Color.green(background), bgAlpha, a);
        int b = compositeComponent(Color.blue(foreground), fgAlpha, Color.blue(background), bgAlpha, a);
        return Color.argb(a, r, g, b);
    }

    public static Color compositeColors(Color foreground, Color background) {
        Color s;
        if (!Objects.equals(foreground.getModel(), background.getModel())) {
            throw new IllegalArgumentException("Color models must match (" + foreground.getModel() + " vs. " + background.getModel() + ")");
        }
        if (Objects.equals(background.getColorSpace(), foreground.getColorSpace())) {
            s = foreground;
        } else {
            s = foreground.convert(background.getColorSpace());
        }
        float[] src = s.getComponents();
        float[] dst = background.getComponents();
        float sa = s.alpha();
        float da = background.alpha() * (1.0f - sa);
        int ai = background.getComponentCount() - 1;
        dst[ai] = sa + da;
        if (dst[ai] > 0.0f) {
            sa /= dst[ai];
            da /= dst[ai];
        }
        for (int i = 0; i < ai; i++) {
            dst[i] = (src[i] * sa) + (dst[i] * da);
        }
        return Color.valueOf(dst, background.getColorSpace());
    }

    private static int compositeAlpha(int foregroundAlpha, int backgroundAlpha) {
        return 255 - (((255 - backgroundAlpha) * (255 - foregroundAlpha)) / 255);
    }

    private static int compositeComponent(int fgC, int fgA, int bgC, int bgA, int a) {
        if (a == 0) {
            return 0;
        }
        return (((fgC * 255) * fgA) + ((bgC * bgA) * (255 - fgA))) / (a * 255);
    }

    public static double calculateLuminance(int color) {
        double[] result = getTempDouble3Array();
        colorToXYZ(color, result);
        return result[1] / XYZ_WHITE_REFERENCE_Y;
    }

    public static double calculateContrast(int foreground, int background) {
        if (Color.alpha(background) != 255) {
            throw new IllegalArgumentException("background can not be translucent: #" + Integer.toHexString(background));
        }
        if (Color.alpha(foreground) < 255) {
            foreground = compositeColors(foreground, background);
        }
        double luminance1 = calculateLuminance(foreground) + 0.05d;
        double luminance2 = calculateLuminance(background) + 0.05d;
        return Math.max(luminance1, luminance2) / Math.min(luminance1, luminance2);
    }

    public static int calculateMinimumAlpha(int foreground, int background, float minContrastRatio) {
        if (Color.alpha(background) != 255) {
            throw new IllegalArgumentException("background can not be translucent: #" + Integer.toHexString(background));
        }
        int testForeground = setAlphaComponent(foreground, 255);
        double testRatio = calculateContrast(testForeground, background);
        if (testRatio < minContrastRatio) {
            return -1;
        }
        int minAlpha = 0;
        int maxAlpha = 255;
        for (int numIterations = 0; numIterations <= 10 && maxAlpha - minAlpha > 1; numIterations++) {
            int testAlpha = (minAlpha + maxAlpha) / 2;
            int testForeground2 = setAlphaComponent(foreground, testAlpha);
            double testRatio2 = calculateContrast(testForeground2, background);
            if (testRatio2 < minContrastRatio) {
                minAlpha = testAlpha;
            } else {
                maxAlpha = testAlpha;
            }
        }
        return maxAlpha;
    }

    public static void RGBToHSL(int r, int g, int b, float[] outHsl) {
        float h;
        float s;
        float rf = r / 255.0f;
        float gf = g / 255.0f;
        float bf = b / 255.0f;
        float max = Math.max(rf, Math.max(gf, bf));
        float min = Math.min(rf, Math.min(gf, bf));
        float deltaMaxMin = max - min;
        float l = (max + min) / 2.0f;
        if (max == min) {
            s = 0.0f;
            h = 0.0f;
        } else {
            if (max == rf) {
                h = ((gf - bf) / deltaMaxMin) % 6.0f;
            } else if (max == gf) {
                h = ((bf - rf) / deltaMaxMin) + 2.0f;
            } else {
                float h2 = rf - gf;
                h = (h2 / deltaMaxMin) + 4.0f;
            }
            s = deltaMaxMin / (1.0f - Math.abs((2.0f * l) - 1.0f));
        }
        float h3 = (60.0f * h) % 360.0f;
        if (h3 < 0.0f) {
            h3 += 360.0f;
        }
        outHsl[0] = constrain(h3, 0.0f, 360.0f);
        outHsl[1] = constrain(s, 0.0f, 1.0f);
        outHsl[2] = constrain(l, 0.0f, 1.0f);
    }

    public static void colorToHSL(int color, float[] outHsl) {
        RGBToHSL(Color.red(color), Color.green(color), Color.blue(color), outHsl);
    }

    public static int HSLToColor(float[] hsl) {
        float h = hsl[0];
        float s = hsl[1];
        float l = hsl[2];
        float c = (1.0f - Math.abs((l * 2.0f) - 1.0f)) * s;
        float m = l - (0.5f * c);
        float x = (1.0f - Math.abs(((h / 60.0f) % 2.0f) - 1.0f)) * c;
        int hueSegment = ((int) h) / 60;
        int r = 0;
        int g = 0;
        int b = 0;
        switch (hueSegment) {
            case 0:
                r = Math.round((c + m) * 255.0f);
                g = Math.round((x + m) * 255.0f);
                b = Math.round(255.0f * m);
                break;
            case 1:
                r = Math.round((x + m) * 255.0f);
                g = Math.round((c + m) * 255.0f);
                b = Math.round(255.0f * m);
                break;
            case 2:
                r = Math.round(m * 255.0f);
                g = Math.round((c + m) * 255.0f);
                b = Math.round((x + m) * 255.0f);
                break;
            case 3:
                r = Math.round(m * 255.0f);
                g = Math.round((x + m) * 255.0f);
                b = Math.round((c + m) * 255.0f);
                break;
            case 4:
                r = Math.round((x + m) * 255.0f);
                g = Math.round(m * 255.0f);
                b = Math.round((c + m) * 255.0f);
                break;
            case 5:
            case 6:
                r = Math.round((c + m) * 255.0f);
                g = Math.round(m * 255.0f);
                b = Math.round((x + m) * 255.0f);
                break;
        }
        return Color.rgb(constrain(r, 0, 255), constrain(g, 0, 255), constrain(b, 0, 255));
    }

    public static int setAlphaComponent(int color, int alpha) {
        if (alpha < 0 || alpha > 255) {
            throw new IllegalArgumentException("alpha must be between 0 and 255.");
        }
        return (16777215 & color) | (alpha << 24);
    }

    public static void colorToLAB(int color, double[] outLab) {
        RGBToLAB(Color.red(color), Color.green(color), Color.blue(color), outLab);
    }

    public static void RGBToLAB(int r, int g, int b, double[] outLab) {
        RGBToXYZ(r, g, b, outLab);
        XYZToLAB(outLab[0], outLab[1], outLab[2], outLab);
    }

    public static void colorToXYZ(int color, double[] outXyz) {
        RGBToXYZ(Color.red(color), Color.green(color), Color.blue(color), outXyz);
    }

    public static void RGBToXYZ(int r, int g, int b, double[] outXyz) {
        if (outXyz.length != 3) {
            throw new IllegalArgumentException("outXyz must have a length of 3.");
        }
        double sr = r / 255.0d;
        double sr2 = sr < 0.04045d ? sr / 12.92d : Math.pow((sr + 0.055d) / 1.055d, 2.4d);
        double sg = g / 255.0d;
        double sg2 = sg < 0.04045d ? sg / 12.92d : Math.pow((sg + 0.055d) / 1.055d, 2.4d);
        double sb = b / 255.0d;
        double sb2 = sb < 0.04045d ? sb / 12.92d : Math.pow((0.055d + sb) / 1.055d, 2.4d);
        outXyz[0] = ((0.4124d * sr2) + (0.3576d * sg2) + (0.1805d * sb2)) * XYZ_WHITE_REFERENCE_Y;
        outXyz[1] = ((0.2126d * sr2) + (0.7152d * sg2) + (0.0722d * sb2)) * XYZ_WHITE_REFERENCE_Y;
        outXyz[2] = ((0.0193d * sr2) + (0.1192d * sg2) + (0.9505d * sb2)) * XYZ_WHITE_REFERENCE_Y;
    }

    public static void XYZToLAB(double x, double y, double z, double[] outLab) {
        if (outLab.length != 3) {
            throw new IllegalArgumentException("outLab must have a length of 3.");
        }
        double x2 = pivotXyzComponent(x / XYZ_WHITE_REFERENCE_X);
        double y2 = pivotXyzComponent(y / XYZ_WHITE_REFERENCE_Y);
        double z2 = pivotXyzComponent(z / XYZ_WHITE_REFERENCE_Z);
        outLab[0] = Math.max(0.0d, (116.0d * y2) - 16.0d);
        outLab[1] = (x2 - y2) * 500.0d;
        outLab[2] = (y2 - z2) * 200.0d;
    }

    public static void LABToXYZ(double l, double a, double b, double[] outXyz) {
        double fy = (l + 16.0d) / 116.0d;
        double fx = (a / 500.0d) + fy;
        double fz = fy - (b / 200.0d);
        double tmp = Math.pow(fx, 3.0d);
        double xr = tmp > XYZ_EPSILON ? tmp : ((fx * 116.0d) - 16.0d) / XYZ_KAPPA;
        double yr = l > 7.9996247999999985d ? Math.pow(fy, 3.0d) : l / XYZ_KAPPA;
        double tmp2 = Math.pow(fz, 3.0d);
        double zr = tmp2 > XYZ_EPSILON ? tmp2 : ((116.0d * fz) - 16.0d) / XYZ_KAPPA;
        outXyz[0] = XYZ_WHITE_REFERENCE_X * xr;
        outXyz[1] = XYZ_WHITE_REFERENCE_Y * yr;
        outXyz[2] = XYZ_WHITE_REFERENCE_Z * zr;
    }

    public static int XYZToColor(double x, double y, double z) {
        double r = (((3.2406d * x) + ((-1.5372d) * y)) + ((-0.4986d) * z)) / XYZ_WHITE_REFERENCE_Y;
        double g = ((((-0.9689d) * x) + (1.8758d * y)) + (0.0415d * z)) / XYZ_WHITE_REFERENCE_Y;
        double b = (((0.0557d * x) + ((-0.204d) * y)) + (1.057d * z)) / XYZ_WHITE_REFERENCE_Y;
        return Color.rgb(constrain((int) Math.round((r > 0.0031308d ? (Math.pow(r, 0.4166666666666667d) * 1.055d) - 0.055d : r * 12.92d) * 255.0d), 0, 255), constrain((int) Math.round((g > 0.0031308d ? (Math.pow(g, 0.4166666666666667d) * 1.055d) - 0.055d : g * 12.92d) * 255.0d), 0, 255), constrain((int) Math.round(255.0d * (b > 0.0031308d ? (Math.pow(b, 0.4166666666666667d) * 1.055d) - 0.055d : b * 12.92d)), 0, 255));
    }

    public static int LABToColor(double l, double a, double b) {
        double[] result = getTempDouble3Array();
        LABToXYZ(l, a, b, result);
        return XYZToColor(result[0], result[1], result[2]);
    }

    public static double distanceEuclidean(double[] labX, double[] labY) {
        return Math.sqrt(Math.pow(labX[0] - labY[0], 2.0d) + Math.pow(labX[1] - labY[1], 2.0d) + Math.pow(labX[2] - labY[2], 2.0d));
    }

    private static float constrain(float amount, float low, float high) {
        return amount < low ? low : amount > high ? high : amount;
    }

    private static int constrain(int amount, int low, int high) {
        return amount < low ? low : amount > high ? high : amount;
    }

    private static double pivotXyzComponent(double component) {
        if (component > XYZ_EPSILON) {
            return Math.pow(component, 0.3333333333333333d);
        }
        return ((XYZ_KAPPA * component) + 16.0d) / 116.0d;
    }

    public static int blendARGB(int color1, int color2, float ratio) {
        float inverseRatio = 1.0f - ratio;
        float a = (Color.alpha(color1) * inverseRatio) + (Color.alpha(color2) * ratio);
        float r = (Color.red(color1) * inverseRatio) + (Color.red(color2) * ratio);
        float g = (Color.green(color1) * inverseRatio) + (Color.green(color2) * ratio);
        float b = (Color.blue(color1) * inverseRatio) + (Color.blue(color2) * ratio);
        return Color.argb((int) a, (int) r, (int) g, (int) b);
    }

    public static void blendHSL(float[] hsl1, float[] hsl2, float ratio, float[] outResult) {
        if (outResult.length != 3) {
            throw new IllegalArgumentException("result must have a length of 3.");
        }
        float inverseRatio = 1.0f - ratio;
        outResult[0] = circularInterpolate(hsl1[0], hsl2[0], ratio);
        outResult[1] = (hsl1[1] * inverseRatio) + (hsl2[1] * ratio);
        outResult[2] = (hsl1[2] * inverseRatio) + (hsl2[2] * ratio);
    }

    public static void blendLAB(double[] lab1, double[] lab2, double ratio, double[] outResult) {
        if (outResult.length != 3) {
            throw new IllegalArgumentException("outResult must have a length of 3.");
        }
        double inverseRatio = 1.0d - ratio;
        outResult[0] = (lab1[0] * inverseRatio) + (lab2[0] * ratio);
        outResult[1] = (lab1[1] * inverseRatio) + (lab2[1] * ratio);
        outResult[2] = (lab1[2] * inverseRatio) + (lab2[2] * ratio);
    }

    static float circularInterpolate(float a, float b, float f) {
        if (Math.abs(b - a) > 180.0f) {
            if (b > a) {
                a += 360.0f;
            } else {
                b += 360.0f;
            }
        }
        return (((b - a) * f) + a) % 360.0f;
    }

    private static double[] getTempDouble3Array() {
        ThreadLocal<double[]> threadLocal = TEMP_ARRAY;
        double[] result = threadLocal.get();
        if (result == null) {
            double[] result2 = new double[3];
            threadLocal.set(result2);
            return result2;
        }
        return result;
    }
}
