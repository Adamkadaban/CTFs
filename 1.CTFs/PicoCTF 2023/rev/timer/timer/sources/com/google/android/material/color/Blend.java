package com.google.android.material.color;
/* loaded from: classes.dex */
final class Blend {
    private static final float HARMONIZE_MAX_DEGREES = 15.0f;
    private static final float HARMONIZE_PERCENTAGE = 0.5f;

    private Blend() {
    }

    public static int harmonize(int designColor, int sourceColor) {
        Hct fromHct = Hct.fromInt(designColor);
        Hct toHct = Hct.fromInt(sourceColor);
        float differenceDegrees = MathUtils.differenceDegrees(fromHct.getHue(), toHct.getHue());
        float rotationDegrees = Math.min(0.5f * differenceDegrees, (float) HARMONIZE_MAX_DEGREES);
        float outputHue = MathUtils.sanitizeDegrees(fromHct.getHue() + (rotationDirection(fromHct.getHue(), toHct.getHue()) * rotationDegrees));
        return Hct.from(outputHue, fromHct.getChroma(), fromHct.getTone()).toInt();
    }

    public static int blendHctHue(int from, int to, float amount) {
        int ucs = blendCam16Ucs(from, to, amount);
        Cam16 ucsCam = Cam16.fromInt(ucs);
        Cam16 fromCam = Cam16.fromInt(from);
        return Hct.from(ucsCam.getHue(), fromCam.getChroma(), ColorUtils.lstarFromInt(from)).toInt();
    }

    public static int blendCam16Ucs(int from, int to, float amount) {
        Cam16 fromCam = Cam16.fromInt(from);
        Cam16 toCam = Cam16.fromInt(to);
        float aJ = fromCam.getJStar();
        float aA = fromCam.getAStar();
        float aB = fromCam.getBStar();
        float bJ = toCam.getJStar();
        float bA = toCam.getAStar();
        float bB = toCam.getBStar();
        float j = ((bJ - aJ) * amount) + aJ;
        float a = ((bA - aA) * amount) + aA;
        float b = ((bB - aB) * amount) + aB;
        Cam16 blended = Cam16.fromUcs(j, a, b);
        return blended.getInt();
    }

    private static float rotationDirection(float from, float to) {
        float a = to - from;
        float b = (to - from) + 360.0f;
        float c = (to - from) - 360.0f;
        float aAbs = Math.abs(a);
        float bAbs = Math.abs(b);
        float cAbs = Math.abs(c);
        return (aAbs > bAbs || aAbs > cAbs) ? (bAbs > aAbs || bAbs > cAbs) ? ((double) c) >= 0.0d ? 1.0f : -1.0f : ((double) b) >= 0.0d ? 1.0f : -1.0f : ((double) a) >= 0.0d ? 1.0f : -1.0f;
    }
}
