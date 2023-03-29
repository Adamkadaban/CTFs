package com.google.android.material.animation;

import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.Property;
import java.util.WeakHashMap;
/* loaded from: classes.dex */
public class DrawableAlphaProperty extends Property<Drawable, Integer> {
    public static final Property<Drawable, Integer> DRAWABLE_ALPHA_COMPAT = new DrawableAlphaProperty();
    private final WeakHashMap<Drawable, Integer> alphaCache;

    private DrawableAlphaProperty() {
        super(Integer.class, "drawableAlphaCompat");
        this.alphaCache = new WeakHashMap<>();
    }

    @Override // android.util.Property
    public Integer get(Drawable object) {
        if (Build.VERSION.SDK_INT >= 19) {
            return Integer.valueOf(object.getAlpha());
        }
        if (this.alphaCache.containsKey(object)) {
            return this.alphaCache.get(object);
        }
        return 255;
    }

    @Override // android.util.Property
    public void set(Drawable object, Integer value) {
        if (Build.VERSION.SDK_INT < 19) {
            this.alphaCache.put(object, value);
        }
        object.setAlpha(value.intValue());
    }
}
