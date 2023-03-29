package com.google.android.material.color;
/* loaded from: classes.dex */
final class MathUtils {
    private MathUtils() {
    }

    static float clamp(float min, float max, float input) {
        return Math.min(Math.max(input, min), max);
    }

    public static float lerp(float start, float stop, float amount) {
        return ((1.0f - amount) * start) + (amount * stop);
    }

    public static float differenceDegrees(float a, float b) {
        return 180.0f - Math.abs(Math.abs(a - b) - 180.0f);
    }

    public static float sanitizeDegrees(float degrees) {
        if (degrees < 0.0f) {
            return (degrees % 360.0f) + 360.0f;
        }
        if (degrees >= 360.0f) {
            return degrees % 360.0f;
        }
        return degrees;
    }

    public static int sanitizeDegrees(int degrees) {
        if (degrees < 0) {
            return (degrees % 360) + 360;
        }
        if (degrees >= 360) {
            return degrees % 360;
        }
        return degrees;
    }

    static float toDegrees(float radians) {
        return (180.0f * radians) / 3.1415927f;
    }

    static float toRadians(float degrees) {
        return (degrees / 180.0f) * 3.1415927f;
    }
}
