package androidx.vectordrawable.graphics.drawable;

import android.animation.TypeEvaluator;
/* loaded from: classes.dex */
public class ArgbEvaluator implements TypeEvaluator {
    private static final ArgbEvaluator sInstance = new ArgbEvaluator();

    public static ArgbEvaluator getInstance() {
        return sInstance;
    }

    @Override // android.animation.TypeEvaluator
    public Object evaluate(float fraction, Object startValue, Object endValue) {
        int startInt = ((Integer) startValue).intValue();
        float startA = ((startInt >> 24) & 255) / 255.0f;
        int endInt = ((Integer) endValue).intValue();
        float endA = ((endInt >> 24) & 255) / 255.0f;
        float endR = ((endInt >> 16) & 255) / 255.0f;
        float endG = ((endInt >> 8) & 255) / 255.0f;
        float endB = (endInt & 255) / 255.0f;
        float startR = (float) Math.pow(((startInt >> 16) & 255) / 255.0f, 2.2d);
        float startG = (float) Math.pow(((startInt >> 8) & 255) / 255.0f, 2.2d);
        float startB = (float) Math.pow((startInt & 255) / 255.0f, 2.2d);
        float endR2 = (float) Math.pow(endR, 2.2d);
        float endG2 = (float) Math.pow(endG, 2.2d);
        float a = ((endA - startA) * fraction) + startA;
        float r = ((endR2 - startR) * fraction) + startR;
        float g = ((endG2 - startG) * fraction) + startG;
        float b = ((((float) Math.pow(endB, 2.2d)) - startB) * fraction) + startB;
        return Integer.valueOf((Math.round(a * 255.0f) << 24) | (Math.round(((float) Math.pow(r, 0.45454545454545453d)) * 255.0f) << 16) | (Math.round(((float) Math.pow(g, 0.45454545454545453d)) * 255.0f) << 8) | Math.round(((float) Math.pow(b, 0.45454545454545453d)) * 255.0f));
    }
}
