package androidx.core.content.res;

import android.graphics.Color;
import androidx.core.graphics.ColorUtils;
import androidx.core.view.ViewCompat;
/* loaded from: classes.dex */
final class CamUtils {
    static final float[][] XYZ_TO_CAM16RGB = {new float[]{0.401288f, 0.650173f, -0.051461f}, new float[]{-0.250268f, 1.204414f, 0.045854f}, new float[]{-0.002079f, 0.048952f, 0.953127f}};
    static final float[][] CAM16RGB_TO_XYZ = {new float[]{1.8620678f, -1.0112547f, 0.14918678f}, new float[]{0.38752654f, 0.62144744f, -0.00897398f}, new float[]{-0.0158415f, -0.03412294f, 1.0499644f}};
    static final float[] WHITE_POINT_D65 = {95.047f, 100.0f, 108.883f};
    static final float[][] SRGB_TO_XYZ = {new float[]{0.41233894f, 0.35762063f, 0.18051042f}, new float[]{0.2126f, 0.7152f, 0.0722f}, new float[]{0.01932141f, 0.11916382f, 0.9503448f}};

    private CamUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int intFromLStar(float lStar) {
        float xT;
        float zT;
        if (lStar < 1.0f) {
            return ViewCompat.MEASURED_STATE_MASK;
        }
        if (lStar > 99.0f) {
            return -1;
        }
        float fy = (lStar + 16.0f) / 116.0f;
        boolean lExceedsEpsilonKappa = lStar > 8.0f;
        float yT = lExceedsEpsilonKappa ? fy * fy * fy : lStar / 903.2963f;
        boolean cubeExceedEpsilon = (fy * fy) * fy > 0.008856452f;
        if (cubeExceedEpsilon) {
            xT = fy * fy * fy;
        } else {
            xT = ((fy * 116.0f) - 16.0f) / 903.2963f;
        }
        if (cubeExceedEpsilon) {
            zT = fy * fy * fy;
        } else {
            zT = ((116.0f * fy) - 16.0f) / 903.2963f;
        }
        float[] fArr = WHITE_POINT_D65;
        return ColorUtils.XYZToColor(fArr[0] * xT, fArr[1] * yT, fArr[2] * zT);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lerp(float start, float stop, float amount) {
        return ((stop - start) * amount) + start;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float lStarFromInt(int argb) {
        return lStarFromY(yFromInt(argb));
    }

    static float lStarFromY(float y) {
        float y2 = y / 100.0f;
        if (y2 <= 0.008856452f) {
            return 903.2963f * y2;
        }
        float yIntermediate = (float) Math.cbrt(y2);
        return (116.0f * yIntermediate) - 16.0f;
    }

    static float yFromInt(int argb) {
        float r = linearized(Color.red(argb));
        float g = linearized(Color.green(argb));
        float b = linearized(Color.blue(argb));
        float[][] matrix = SRGB_TO_XYZ;
        float y = (matrix[1][0] * r) + (matrix[1][1] * g) + (matrix[1][2] * b);
        return y;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float[] xyzFromInt(int argb) {
        float r = linearized(Color.red(argb));
        float g = linearized(Color.green(argb));
        float b = linearized(Color.blue(argb));
        float[][] matrix = SRGB_TO_XYZ;
        float x = (matrix[0][0] * r) + (matrix[0][1] * g) + (matrix[0][2] * b);
        float y = (matrix[1][0] * r) + (matrix[1][1] * g) + (matrix[1][2] * b);
        float z = (matrix[2][0] * r) + (matrix[2][1] * g) + (matrix[2][2] * b);
        return new float[]{x, y, z};
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float yFromLStar(float lstar) {
        return lstar > 8.0f ? ((float) Math.pow((lstar + 16.0d) / 116.0d, 3.0d)) * 100.0f : (lstar / 903.2963f) * 100.0f;
    }

    static float linearized(int rgbComponent) {
        float normalized = rgbComponent / 255.0f;
        return normalized <= 0.04045f ? (normalized / 12.92f) * 100.0f : ((float) Math.pow((0.055f + normalized) / 1.055f, 2.4000000953674316d)) * 100.0f;
    }
}
