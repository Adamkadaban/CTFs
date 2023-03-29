package com.google.android.material.transition;
/* loaded from: classes.dex */
class FadeModeResult {
    final int endAlpha;
    final boolean endOnTop;
    final int startAlpha;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FadeModeResult startOnTop(int startAlpha, int endAlpha) {
        return new FadeModeResult(startAlpha, endAlpha, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FadeModeResult endOnTop(int startAlpha, int endAlpha) {
        return new FadeModeResult(startAlpha, endAlpha, true);
    }

    private FadeModeResult(int startAlpha, int endAlpha, boolean endOnTop) {
        this.startAlpha = startAlpha;
        this.endAlpha = endAlpha;
        this.endOnTop = endOnTop;
    }
}
