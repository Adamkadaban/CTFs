package com.google.android.material.circularreveal;

import android.animation.TypeEvaluator;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.util.Property;
import com.google.android.material.circularreveal.CircularRevealHelper;
import com.google.android.material.math.MathUtils;
/* loaded from: classes.dex */
public interface CircularRevealWidget extends CircularRevealHelper.Delegate {
    void buildCircularRevealCache();

    void destroyCircularRevealCache();

    void draw(Canvas canvas);

    Drawable getCircularRevealOverlayDrawable();

    int getCircularRevealScrimColor();

    RevealInfo getRevealInfo();

    boolean isOpaque();

    void setCircularRevealOverlayDrawable(Drawable drawable);

    void setCircularRevealScrimColor(int i);

    void setRevealInfo(RevealInfo revealInfo);

    /* loaded from: classes.dex */
    public static class RevealInfo {
        public static final float INVALID_RADIUS = Float.MAX_VALUE;
        public float centerX;
        public float centerY;
        public float radius;

        private RevealInfo() {
        }

        public RevealInfo(float centerX, float centerY, float radius) {
            this.centerX = centerX;
            this.centerY = centerY;
            this.radius = radius;
        }

        public RevealInfo(RevealInfo other) {
            this(other.centerX, other.centerY, other.radius);
        }

        public void set(float centerX, float centerY, float radius) {
            this.centerX = centerX;
            this.centerY = centerY;
            this.radius = radius;
        }

        public void set(RevealInfo other) {
            set(other.centerX, other.centerY, other.radius);
        }

        public boolean isInvalid() {
            return this.radius == Float.MAX_VALUE;
        }
    }

    /* loaded from: classes.dex */
    public static class CircularRevealProperty extends Property<CircularRevealWidget, RevealInfo> {
        public static final Property<CircularRevealWidget, RevealInfo> CIRCULAR_REVEAL = new CircularRevealProperty("circularReveal");

        private CircularRevealProperty(String name) {
            super(RevealInfo.class, name);
        }

        @Override // android.util.Property
        public RevealInfo get(CircularRevealWidget object) {
            return object.getRevealInfo();
        }

        @Override // android.util.Property
        public void set(CircularRevealWidget object, RevealInfo value) {
            object.setRevealInfo(value);
        }
    }

    /* loaded from: classes.dex */
    public static class CircularRevealEvaluator implements TypeEvaluator<RevealInfo> {
        public static final TypeEvaluator<RevealInfo> CIRCULAR_REVEAL = new CircularRevealEvaluator();
        private final RevealInfo revealInfo = new RevealInfo();

        @Override // android.animation.TypeEvaluator
        public RevealInfo evaluate(float fraction, RevealInfo startValue, RevealInfo endValue) {
            this.revealInfo.set(MathUtils.lerp(startValue.centerX, endValue.centerX, fraction), MathUtils.lerp(startValue.centerY, endValue.centerY, fraction), MathUtils.lerp(startValue.radius, endValue.radius, fraction));
            return this.revealInfo;
        }
    }

    /* loaded from: classes.dex */
    public static class CircularRevealScrimColorProperty extends Property<CircularRevealWidget, Integer> {
        public static final Property<CircularRevealWidget, Integer> CIRCULAR_REVEAL_SCRIM_COLOR = new CircularRevealScrimColorProperty("circularRevealScrimColor");

        private CircularRevealScrimColorProperty(String name) {
            super(Integer.class, name);
        }

        @Override // android.util.Property
        public Integer get(CircularRevealWidget object) {
            return Integer.valueOf(object.getCircularRevealScrimColor());
        }

        @Override // android.util.Property
        public void set(CircularRevealWidget object, Integer value) {
            object.setCircularRevealScrimColor(value.intValue());
        }
    }
}
