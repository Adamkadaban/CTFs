package androidx.cardview.widget;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import androidx.cardview.R;
/* loaded from: classes.dex */
class RoundRectDrawableWithShadow extends Drawable {
    private static final double COS_45 = Math.cos(Math.toRadians(45.0d));
    private static final float SHADOW_MULTIPLIER = 1.5f;
    static RoundRectHelper sRoundRectHelper;
    private ColorStateList mBackground;
    private final RectF mCardBounds;
    private float mCornerRadius;
    private Paint mCornerShadowPaint;
    private Path mCornerShadowPath;
    private Paint mEdgeShadowPaint;
    private final int mInsetShadow;
    private float mRawMaxShadowSize;
    private float mRawShadowSize;
    private final int mShadowEndColor;
    private float mShadowSize;
    private final int mShadowStartColor;
    private boolean mDirty = true;
    private boolean mAddPaddingForCorners = true;
    private boolean mPrintedShadowClipWarning = false;
    private Paint mPaint = new Paint(5);

    /* loaded from: classes.dex */
    interface RoundRectHelper {
        void drawRoundRect(Canvas canvas, RectF rectF, float f, Paint paint);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RoundRectDrawableWithShadow(Resources resources, ColorStateList backgroundColor, float radius, float shadowSize, float maxShadowSize) {
        this.mShadowStartColor = resources.getColor(R.color.cardview_shadow_start_color);
        this.mShadowEndColor = resources.getColor(R.color.cardview_shadow_end_color);
        this.mInsetShadow = resources.getDimensionPixelSize(R.dimen.cardview_compat_inset_shadow);
        setBackground(backgroundColor);
        Paint paint = new Paint(5);
        this.mCornerShadowPaint = paint;
        paint.setStyle(Paint.Style.FILL);
        this.mCornerRadius = (int) (0.5f + radius);
        this.mCardBounds = new RectF();
        Paint paint2 = new Paint(this.mCornerShadowPaint);
        this.mEdgeShadowPaint = paint2;
        paint2.setAntiAlias(false);
        setShadowSize(shadowSize, maxShadowSize);
    }

    private void setBackground(ColorStateList color) {
        ColorStateList valueOf = color == null ? ColorStateList.valueOf(0) : color;
        this.mBackground = valueOf;
        this.mPaint.setColor(valueOf.getColorForState(getState(), this.mBackground.getDefaultColor()));
    }

    private int toEven(float value) {
        int i = (int) (0.5f + value);
        if (i % 2 == 1) {
            return i - 1;
        }
        return i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAddPaddingForCorners(boolean addPaddingForCorners) {
        this.mAddPaddingForCorners = addPaddingForCorners;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.mPaint.setAlpha(alpha);
        this.mCornerShadowPaint.setAlpha(alpha);
        this.mEdgeShadowPaint.setAlpha(alpha);
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        this.mDirty = true;
    }

    private void setShadowSize(float shadowSize, float maxShadowSize) {
        if (shadowSize < 0.0f) {
            throw new IllegalArgumentException("Invalid shadow size " + shadowSize + ". Must be >= 0");
        } else if (maxShadowSize < 0.0f) {
            throw new IllegalArgumentException("Invalid max shadow size " + maxShadowSize + ". Must be >= 0");
        } else {
            float shadowSize2 = toEven(shadowSize);
            float maxShadowSize2 = toEven(maxShadowSize);
            if (shadowSize2 > maxShadowSize2) {
                shadowSize2 = maxShadowSize2;
                if (!this.mPrintedShadowClipWarning) {
                    this.mPrintedShadowClipWarning = true;
                }
            }
            if (this.mRawShadowSize == shadowSize2 && this.mRawMaxShadowSize == maxShadowSize2) {
                return;
            }
            this.mRawShadowSize = shadowSize2;
            this.mRawMaxShadowSize = maxShadowSize2;
            this.mShadowSize = (int) ((SHADOW_MULTIPLIER * shadowSize2) + this.mInsetShadow + 0.5f);
            this.mDirty = true;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public boolean getPadding(Rect padding) {
        int vOffset = (int) Math.ceil(calculateVerticalPadding(this.mRawMaxShadowSize, this.mCornerRadius, this.mAddPaddingForCorners));
        int hOffset = (int) Math.ceil(calculateHorizontalPadding(this.mRawMaxShadowSize, this.mCornerRadius, this.mAddPaddingForCorners));
        padding.set(hOffset, vOffset, hOffset, vOffset);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float calculateVerticalPadding(float maxShadowSize, float cornerRadius, boolean addPaddingForCorners) {
        if (addPaddingForCorners) {
            return (float) ((SHADOW_MULTIPLIER * maxShadowSize) + ((1.0d - COS_45) * cornerRadius));
        }
        return SHADOW_MULTIPLIER * maxShadowSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static float calculateHorizontalPadding(float maxShadowSize, float cornerRadius, boolean addPaddingForCorners) {
        if (addPaddingForCorners) {
            return (float) (maxShadowSize + ((1.0d - COS_45) * cornerRadius));
        }
        return maxShadowSize;
    }

    @Override // android.graphics.drawable.Drawable
    protected boolean onStateChange(int[] stateSet) {
        ColorStateList colorStateList = this.mBackground;
        int newColor = colorStateList.getColorForState(stateSet, colorStateList.getDefaultColor());
        if (this.mPaint.getColor() == newColor) {
            return false;
        }
        this.mPaint.setColor(newColor);
        this.mDirty = true;
        invalidateSelf();
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isStateful() {
        ColorStateList colorStateList = this.mBackground;
        return (colorStateList != null && colorStateList.isStateful()) || super.isStateful();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
        this.mPaint.setColorFilter(cf);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCornerRadius(float radius) {
        if (radius < 0.0f) {
            throw new IllegalArgumentException("Invalid radius " + radius + ". Must be >= 0");
        }
        float radius2 = (int) (0.5f + radius);
        if (this.mCornerRadius == radius2) {
            return;
        }
        this.mCornerRadius = radius2;
        this.mDirty = true;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (this.mDirty) {
            buildComponents(getBounds());
            this.mDirty = false;
        }
        canvas.translate(0.0f, this.mRawShadowSize / 2.0f);
        drawShadow(canvas);
        canvas.translate(0.0f, (-this.mRawShadowSize) / 2.0f);
        sRoundRectHelper.drawRoundRect(canvas, this.mCardBounds, this.mCornerRadius, this.mPaint);
    }

    private void drawShadow(Canvas canvas) {
        float f = this.mCornerRadius;
        float edgeShadowTop = (-f) - this.mShadowSize;
        float inset = f + this.mInsetShadow + (this.mRawShadowSize / 2.0f);
        boolean drawHorizontalEdges = this.mCardBounds.width() - (inset * 2.0f) > 0.0f;
        boolean drawVerticalEdges = this.mCardBounds.height() - (inset * 2.0f) > 0.0f;
        int saved = canvas.save();
        canvas.translate(this.mCardBounds.left + inset, this.mCardBounds.top + inset);
        canvas.drawPath(this.mCornerShadowPath, this.mCornerShadowPaint);
        if (drawHorizontalEdges) {
            canvas.drawRect(0.0f, edgeShadowTop, this.mCardBounds.width() - (inset * 2.0f), -this.mCornerRadius, this.mEdgeShadowPaint);
        }
        canvas.restoreToCount(saved);
        int saved2 = canvas.save();
        canvas.translate(this.mCardBounds.right - inset, this.mCardBounds.bottom - inset);
        canvas.rotate(180.0f);
        canvas.drawPath(this.mCornerShadowPath, this.mCornerShadowPaint);
        if (drawHorizontalEdges) {
            canvas.drawRect(0.0f, edgeShadowTop, this.mCardBounds.width() - (inset * 2.0f), (-this.mCornerRadius) + this.mShadowSize, this.mEdgeShadowPaint);
        }
        canvas.restoreToCount(saved2);
        int saved3 = canvas.save();
        canvas.translate(this.mCardBounds.left + inset, this.mCardBounds.bottom - inset);
        canvas.rotate(270.0f);
        canvas.drawPath(this.mCornerShadowPath, this.mCornerShadowPaint);
        if (drawVerticalEdges) {
            canvas.drawRect(0.0f, edgeShadowTop, this.mCardBounds.height() - (inset * 2.0f), -this.mCornerRadius, this.mEdgeShadowPaint);
        }
        canvas.restoreToCount(saved3);
        int saved4 = canvas.save();
        canvas.translate(this.mCardBounds.right - inset, this.mCardBounds.top + inset);
        canvas.rotate(90.0f);
        canvas.drawPath(this.mCornerShadowPath, this.mCornerShadowPaint);
        if (drawVerticalEdges) {
            canvas.drawRect(0.0f, edgeShadowTop, this.mCardBounds.height() - (2.0f * inset), -this.mCornerRadius, this.mEdgeShadowPaint);
        }
        canvas.restoreToCount(saved4);
    }

    private void buildShadowCorners() {
        float f = this.mCornerRadius;
        RectF innerBounds = new RectF(-f, -f, f, f);
        RectF outerBounds = new RectF(innerBounds);
        float f2 = this.mShadowSize;
        outerBounds.inset(-f2, -f2);
        Path path = this.mCornerShadowPath;
        if (path == null) {
            this.mCornerShadowPath = new Path();
        } else {
            path.reset();
        }
        this.mCornerShadowPath.setFillType(Path.FillType.EVEN_ODD);
        this.mCornerShadowPath.moveTo(-this.mCornerRadius, 0.0f);
        this.mCornerShadowPath.rLineTo(-this.mShadowSize, 0.0f);
        this.mCornerShadowPath.arcTo(outerBounds, 180.0f, 90.0f, false);
        this.mCornerShadowPath.arcTo(innerBounds, 270.0f, -90.0f, false);
        this.mCornerShadowPath.close();
        float f3 = this.mCornerRadius;
        float startRatio = f3 / (this.mShadowSize + f3);
        Paint paint = this.mCornerShadowPaint;
        float f4 = this.mShadowSize + this.mCornerRadius;
        int i = this.mShadowStartColor;
        paint.setShader(new RadialGradient(0.0f, 0.0f, f4, new int[]{i, i, this.mShadowEndColor}, new float[]{0.0f, startRatio, 1.0f}, Shader.TileMode.CLAMP));
        Paint paint2 = this.mEdgeShadowPaint;
        float f5 = this.mCornerRadius;
        float f6 = this.mShadowSize;
        int i2 = this.mShadowStartColor;
        paint2.setShader(new LinearGradient(0.0f, (-f5) + f6, 0.0f, (-f5) - f6, new int[]{i2, i2, this.mShadowEndColor}, new float[]{0.0f, 0.5f, 1.0f}, Shader.TileMode.CLAMP));
        this.mEdgeShadowPaint.setAntiAlias(false);
    }

    private void buildComponents(Rect bounds) {
        float verticalOffset = this.mRawMaxShadowSize * SHADOW_MULTIPLIER;
        this.mCardBounds.set(bounds.left + this.mRawMaxShadowSize, bounds.top + verticalOffset, bounds.right - this.mRawMaxShadowSize, bounds.bottom - verticalOffset);
        buildShadowCorners();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getCornerRadius() {
        return this.mCornerRadius;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void getMaxShadowAndCornerPadding(Rect into) {
        getPadding(into);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setShadowSize(float size) {
        setShadowSize(size, this.mRawMaxShadowSize);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setMaxShadowSize(float size) {
        setShadowSize(this.mRawShadowSize, size);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getShadowSize() {
        return this.mRawShadowSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getMaxShadowSize() {
        return this.mRawMaxShadowSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getMinWidth() {
        float f = this.mRawMaxShadowSize;
        float content = Math.max(f, this.mCornerRadius + this.mInsetShadow + (f / 2.0f)) * 2.0f;
        return ((this.mRawMaxShadowSize + this.mInsetShadow) * 2.0f) + content;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getMinHeight() {
        float f = this.mRawMaxShadowSize;
        float content = Math.max(f, this.mCornerRadius + this.mInsetShadow + ((f * SHADOW_MULTIPLIER) / 2.0f)) * 2.0f;
        return (((this.mRawMaxShadowSize * SHADOW_MULTIPLIER) + this.mInsetShadow) * 2.0f) + content;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setColor(ColorStateList color) {
        setBackground(color);
        invalidateSelf();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ColorStateList getColor() {
        return this.mBackground;
    }
}
