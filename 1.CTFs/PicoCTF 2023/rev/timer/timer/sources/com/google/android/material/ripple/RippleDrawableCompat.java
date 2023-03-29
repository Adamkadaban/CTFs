package com.google.android.material.ripple;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import androidx.core.graphics.drawable.TintAwareDrawable;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.shape.Shapeable;
/* loaded from: classes.dex */
public class RippleDrawableCompat extends Drawable implements Shapeable, TintAwareDrawable {
    private RippleDrawableCompatState drawableState;

    public RippleDrawableCompat(ShapeAppearanceModel shapeAppearanceModel) {
        this(new RippleDrawableCompatState(new MaterialShapeDrawable(shapeAppearanceModel)));
    }

    private RippleDrawableCompat(RippleDrawableCompatState state) {
        this.drawableState = state;
    }

    @Override // android.graphics.drawable.Drawable, androidx.core.graphics.drawable.TintAwareDrawable
    public void setTint(int tintColor) {
        this.drawableState.delegate.setTint(tintColor);
    }

    @Override // android.graphics.drawable.Drawable, androidx.core.graphics.drawable.TintAwareDrawable
    public void setTintMode(PorterDuff.Mode tintMode) {
        this.drawableState.delegate.setTintMode(tintMode);
    }

    @Override // android.graphics.drawable.Drawable, androidx.core.graphics.drawable.TintAwareDrawable
    public void setTintList(ColorStateList tintList) {
        this.drawableState.delegate.setTintList(tintList);
    }

    @Override // com.google.android.material.shape.Shapeable
    public void setShapeAppearanceModel(ShapeAppearanceModel shapeAppearanceModel) {
        this.drawableState.delegate.setShapeAppearanceModel(shapeAppearanceModel);
    }

    @Override // com.google.android.material.shape.Shapeable
    public ShapeAppearanceModel getShapeAppearanceModel() {
        return this.drawableState.delegate.getShapeAppearanceModel();
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isStateful() {
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    protected boolean onStateChange(int[] stateSet) {
        boolean changed = super.onStateChange(stateSet);
        if (this.drawableState.delegate.setState(stateSet)) {
            changed = true;
        }
        boolean shouldDrawRipple = RippleUtils.shouldDrawRippleCompat(stateSet);
        if (this.drawableState.shouldDrawDelegate != shouldDrawRipple) {
            this.drawableState.shouldDrawDelegate = shouldDrawRipple;
            return true;
        }
        return changed;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (this.drawableState.shouldDrawDelegate) {
            this.drawableState.delegate.draw(canvas);
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        this.drawableState.delegate.setBounds(bounds);
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable.ConstantState getConstantState() {
        return this.drawableState;
    }

    @Override // android.graphics.drawable.Drawable
    public RippleDrawableCompat mutate() {
        RippleDrawableCompatState newDrawableState = new RippleDrawableCompatState(this.drawableState);
        this.drawableState = newDrawableState;
        return this;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.drawableState.delegate.setAlpha(alpha);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.drawableState.delegate.setColorFilter(colorFilter);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return this.drawableState.delegate.getOpacity();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class RippleDrawableCompatState extends Drawable.ConstantState {
        MaterialShapeDrawable delegate;
        boolean shouldDrawDelegate;

        public RippleDrawableCompatState(MaterialShapeDrawable delegate) {
            this.delegate = delegate;
            this.shouldDrawDelegate = false;
        }

        public RippleDrawableCompatState(RippleDrawableCompatState orig) {
            this.delegate = (MaterialShapeDrawable) orig.delegate.getConstantState().newDrawable();
            this.shouldDrawDelegate = orig.shouldDrawDelegate;
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        public RippleDrawableCompat newDrawable() {
            return new RippleDrawableCompat(new RippleDrawableCompatState(this));
        }

        @Override // android.graphics.drawable.Drawable.ConstantState
        public int getChangingConfigurations() {
            return 0;
        }
    }
}
