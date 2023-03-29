package com.google.android.material.transition.platform;
/* loaded from: classes.dex */
class FadeModeEvaluators {
    private static final FadeModeEvaluator IN = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.1
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float progress, float fadeStartFraction, float fadeEndFraction, float threshold) {
            int endAlpha = TransitionUtils.lerp(0, 255, fadeStartFraction, fadeEndFraction, progress);
            return FadeModeResult.endOnTop(255, endAlpha);
        }
    };
    private static final FadeModeEvaluator OUT = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.2
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float progress, float fadeStartFraction, float fadeEndFraction, float threshold) {
            int startAlpha = TransitionUtils.lerp(255, 0, fadeStartFraction, fadeEndFraction, progress);
            return FadeModeResult.startOnTop(startAlpha, 255);
        }
    };
    private static final FadeModeEvaluator CROSS = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.3
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float progress, float fadeStartFraction, float fadeEndFraction, float threshold) {
            int startAlpha = TransitionUtils.lerp(255, 0, fadeStartFraction, fadeEndFraction, progress);
            int endAlpha = TransitionUtils.lerp(0, 255, fadeStartFraction, fadeEndFraction, progress);
            return FadeModeResult.startOnTop(startAlpha, endAlpha);
        }
    };
    private static final FadeModeEvaluator THROUGH = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.4
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float progress, float fadeStartFraction, float fadeEndFraction, float threshold) {
            float fadeFractionDiff = fadeEndFraction - fadeStartFraction;
            float fadeFractionThreshold = (fadeFractionDiff * threshold) + fadeStartFraction;
            int startAlpha = TransitionUtils.lerp(255, 0, fadeStartFraction, fadeFractionThreshold, progress);
            int endAlpha = TransitionUtils.lerp(0, 255, fadeFractionThreshold, fadeEndFraction, progress);
            return FadeModeResult.startOnTop(startAlpha, endAlpha);
        }
    };

    /* JADX INFO: Access modifiers changed from: package-private */
    public static FadeModeEvaluator get(int fadeMode, boolean entering) {
        switch (fadeMode) {
            case 0:
                return entering ? IN : OUT;
            case 1:
                return entering ? OUT : IN;
            case 2:
                return CROSS;
            case 3:
                return THROUGH;
            default:
                throw new IllegalArgumentException("Invalid fade mode: " + fadeMode);
        }
    }

    private FadeModeEvaluators() {
    }
}
