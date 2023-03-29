package com.google.android.material.color;

import android.app.Activity;
import com.google.android.material.color.DynamicColors;
/* loaded from: classes.dex */
public class DynamicColorsOptions {
    private static final DynamicColors.Precondition ALWAYS_ALLOW = new DynamicColors.Precondition() { // from class: com.google.android.material.color.DynamicColorsOptions.1
        @Override // com.google.android.material.color.DynamicColors.Precondition
        public boolean shouldApplyDynamicColors(Activity activity, int theme) {
            return true;
        }
    };
    private static final DynamicColors.OnAppliedCallback NO_OP_CALLBACK = new DynamicColors.OnAppliedCallback() { // from class: com.google.android.material.color.DynamicColorsOptions.2
        @Override // com.google.android.material.color.DynamicColors.OnAppliedCallback
        public void onApplied(Activity activity) {
        }
    };
    private final DynamicColors.OnAppliedCallback onAppliedCallback;
    private final DynamicColors.Precondition precondition;
    private final int themeOverlay;

    private DynamicColorsOptions(Builder builder) {
        this.themeOverlay = builder.themeOverlay;
        this.precondition = builder.precondition;
        this.onAppliedCallback = builder.onAppliedCallback;
    }

    public int getThemeOverlay() {
        return this.themeOverlay;
    }

    public DynamicColors.Precondition getPrecondition() {
        return this.precondition;
    }

    public DynamicColors.OnAppliedCallback getOnAppliedCallback() {
        return this.onAppliedCallback;
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private int themeOverlay;
        private DynamicColors.Precondition precondition = DynamicColorsOptions.ALWAYS_ALLOW;
        private DynamicColors.OnAppliedCallback onAppliedCallback = DynamicColorsOptions.NO_OP_CALLBACK;

        public Builder setThemeOverlay(int themeOverlay) {
            this.themeOverlay = themeOverlay;
            return this;
        }

        public Builder setPrecondition(DynamicColors.Precondition precondition) {
            this.precondition = precondition;
            return this;
        }

        public Builder setOnAppliedCallback(DynamicColors.OnAppliedCallback onAppliedCallback) {
            this.onAppliedCallback = onAppliedCallback;
            return this;
        }

        public DynamicColorsOptions build() {
            return new DynamicColorsOptions(this);
        }
    }
}
