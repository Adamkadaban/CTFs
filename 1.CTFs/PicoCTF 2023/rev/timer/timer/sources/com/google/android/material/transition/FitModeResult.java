package com.google.android.material.transition;
/* loaded from: classes.dex */
class FitModeResult {
    final float currentEndHeight;
    final float currentEndWidth;
    final float currentStartHeight;
    final float currentStartWidth;
    final float endScale;
    final float startScale;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FitModeResult(float startScale, float endScale, float currentStartWidth, float currentStartHeight, float currentEndWidth, float currentEndHeight) {
        this.startScale = startScale;
        this.endScale = endScale;
        this.currentStartWidth = currentStartWidth;
        this.currentStartHeight = currentStartHeight;
        this.currentEndWidth = currentEndWidth;
        this.currentEndHeight = currentEndHeight;
    }
}
