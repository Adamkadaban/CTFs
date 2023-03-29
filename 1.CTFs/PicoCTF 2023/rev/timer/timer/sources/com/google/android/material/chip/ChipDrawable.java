package com.google.android.material.chip;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.OvalShape;
import android.os.Build;
import android.text.TextUtils;
import android.util.AttributeSet;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.graphics.ColorUtils;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.graphics.drawable.TintAwareDrawable;
import androidx.core.internal.view.SupportMenu;
import androidx.core.text.BidiFormatter;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.canvas.CanvasCompat;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.drawable.DrawableUtils;
import com.google.android.material.internal.TextDrawableHelper;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.resources.TextAppearance;
import com.google.android.material.ripple.RippleUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import java.lang.ref.WeakReference;
import java.util.Arrays;
/* loaded from: classes.dex */
public class ChipDrawable extends MaterialShapeDrawable implements TintAwareDrawable, Drawable.Callback, TextDrawableHelper.TextDrawableDelegate {
    private static final boolean DEBUG = false;
    private static final int MAX_CHIP_ICON_HEIGHT = 24;
    private static final String NAMESPACE_APP = "http://schemas.android.com/apk/res-auto";
    private int alpha;
    private boolean checkable;
    private Drawable checkedIcon;
    private ColorStateList checkedIconTint;
    private boolean checkedIconVisible;
    private ColorStateList chipBackgroundColor;
    private float chipCornerRadius;
    private float chipEndPadding;
    private Drawable chipIcon;
    private float chipIconSize;
    private ColorStateList chipIconTint;
    private boolean chipIconVisible;
    private float chipMinHeight;
    private final Paint chipPaint;
    private float chipStartPadding;
    private ColorStateList chipStrokeColor;
    private float chipStrokeWidth;
    private ColorStateList chipSurfaceColor;
    private Drawable closeIcon;
    private CharSequence closeIconContentDescription;
    private float closeIconEndPadding;
    private Drawable closeIconRipple;
    private float closeIconSize;
    private float closeIconStartPadding;
    private int[] closeIconStateSet;
    private ColorStateList closeIconTint;
    private boolean closeIconVisible;
    private ColorFilter colorFilter;
    private ColorStateList compatRippleColor;
    private final Context context;
    private boolean currentChecked;
    private int currentChipBackgroundColor;
    private int currentChipStrokeColor;
    private int currentChipSurfaceColor;
    private int currentCompatRippleColor;
    private int currentCompositeSurfaceBackgroundColor;
    private int currentTextColor;
    private int currentTint;
    private final Paint debugPaint;
    private WeakReference<Delegate> delegate;
    private final Paint.FontMetrics fontMetrics;
    private boolean hasChipIconTint;
    private MotionSpec hideMotionSpec;
    private float iconEndPadding;
    private float iconStartPadding;
    private boolean isShapeThemingEnabled;
    private int maxWidth;
    private final PointF pointF;
    private final RectF rectF;
    private ColorStateList rippleColor;
    private final Path shapePath;
    private boolean shouldDrawText;
    private MotionSpec showMotionSpec;
    private CharSequence text;
    private final TextDrawableHelper textDrawableHelper;
    private float textEndPadding;
    private float textStartPadding;
    private ColorStateList tint;
    private PorterDuffColorFilter tintFilter;
    private PorterDuff.Mode tintMode;
    private TextUtils.TruncateAt truncateAt;
    private boolean useCompatRipple;
    private static final int[] DEFAULT_STATE = {16842910};
    private static final ShapeDrawable closeIconRippleMask = new ShapeDrawable(new OvalShape());

    /* loaded from: classes.dex */
    public interface Delegate {
        void onChipDrawableSizeChange();
    }

    public static ChipDrawable createFromAttributes(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        ChipDrawable chip = new ChipDrawable(context, attrs, defStyleAttr, defStyleRes);
        chip.loadFromAttributes(attrs, defStyleAttr, defStyleRes);
        return chip;
    }

    public static ChipDrawable createFromResource(Context context, int id) {
        AttributeSet attrs = DrawableUtils.parseDrawableXml(context, id, "chip");
        int style = attrs.getStyleAttribute();
        if (style == 0) {
            style = R.style.Widget_MaterialComponents_Chip_Entry;
        }
        return createFromAttributes(context, attrs, R.attr.chipStandaloneStyle, style);
    }

    private ChipDrawable(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        this.chipCornerRadius = -1.0f;
        this.chipPaint = new Paint(1);
        this.fontMetrics = new Paint.FontMetrics();
        this.rectF = new RectF();
        this.pointF = new PointF();
        this.shapePath = new Path();
        this.alpha = 255;
        this.tintMode = PorterDuff.Mode.SRC_IN;
        this.delegate = new WeakReference<>(null);
        initializeElevationOverlay(context);
        this.context = context;
        TextDrawableHelper textDrawableHelper = new TextDrawableHelper(this);
        this.textDrawableHelper = textDrawableHelper;
        this.text = "";
        textDrawableHelper.getTextPaint().density = context.getResources().getDisplayMetrics().density;
        this.debugPaint = null;
        int[] iArr = DEFAULT_STATE;
        setState(iArr);
        setCloseIconState(iArr);
        this.shouldDrawText = true;
        if (RippleUtils.USE_FRAMEWORK_RIPPLE) {
            closeIconRippleMask.setTint(-1);
        }
    }

    private void loadFromAttributes(AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(this.context, attrs, R.styleable.Chip, defStyleAttr, defStyleRes, new int[0]);
        this.isShapeThemingEnabled = a.hasValue(R.styleable.Chip_shapeAppearance);
        setChipSurfaceColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_chipSurfaceColor));
        setChipBackgroundColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_chipBackgroundColor));
        setChipMinHeight(a.getDimension(R.styleable.Chip_chipMinHeight, 0.0f));
        if (a.hasValue(R.styleable.Chip_chipCornerRadius)) {
            setChipCornerRadius(a.getDimension(R.styleable.Chip_chipCornerRadius, 0.0f));
        }
        setChipStrokeColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_chipStrokeColor));
        setChipStrokeWidth(a.getDimension(R.styleable.Chip_chipStrokeWidth, 0.0f));
        setRippleColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_rippleColor));
        setText(a.getText(R.styleable.Chip_android_text));
        TextAppearance textAppearance = MaterialResources.getTextAppearance(this.context, a, R.styleable.Chip_android_textAppearance);
        float textSize = a.getDimension(R.styleable.Chip_android_textSize, textAppearance.getTextSize());
        textAppearance.setTextSize(textSize);
        if (Build.VERSION.SDK_INT < 23) {
            textAppearance.setTextColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_android_textColor));
        }
        setTextAppearance(textAppearance);
        int ellipsize = a.getInt(R.styleable.Chip_android_ellipsize, 0);
        switch (ellipsize) {
            case 1:
                setEllipsize(TextUtils.TruncateAt.START);
                break;
            case 2:
                setEllipsize(TextUtils.TruncateAt.MIDDLE);
                break;
            case 3:
                setEllipsize(TextUtils.TruncateAt.END);
                break;
        }
        setChipIconVisible(a.getBoolean(R.styleable.Chip_chipIconVisible, false));
        if (attrs != null && attrs.getAttributeValue(NAMESPACE_APP, "chipIconEnabled") != null && attrs.getAttributeValue(NAMESPACE_APP, "chipIconVisible") == null) {
            setChipIconVisible(a.getBoolean(R.styleable.Chip_chipIconEnabled, false));
        }
        setChipIcon(MaterialResources.getDrawable(this.context, a, R.styleable.Chip_chipIcon));
        if (a.hasValue(R.styleable.Chip_chipIconTint)) {
            setChipIconTint(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_chipIconTint));
        }
        setChipIconSize(a.getDimension(R.styleable.Chip_chipIconSize, -1.0f));
        setCloseIconVisible(a.getBoolean(R.styleable.Chip_closeIconVisible, false));
        if (attrs != null && attrs.getAttributeValue(NAMESPACE_APP, "closeIconEnabled") != null && attrs.getAttributeValue(NAMESPACE_APP, "closeIconVisible") == null) {
            setCloseIconVisible(a.getBoolean(R.styleable.Chip_closeIconEnabled, false));
        }
        setCloseIcon(MaterialResources.getDrawable(this.context, a, R.styleable.Chip_closeIcon));
        setCloseIconTint(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_closeIconTint));
        setCloseIconSize(a.getDimension(R.styleable.Chip_closeIconSize, 0.0f));
        setCheckable(a.getBoolean(R.styleable.Chip_android_checkable, false));
        setCheckedIconVisible(a.getBoolean(R.styleable.Chip_checkedIconVisible, false));
        if (attrs != null && attrs.getAttributeValue(NAMESPACE_APP, "checkedIconEnabled") != null && attrs.getAttributeValue(NAMESPACE_APP, "checkedIconVisible") == null) {
            setCheckedIconVisible(a.getBoolean(R.styleable.Chip_checkedIconEnabled, false));
        }
        setCheckedIcon(MaterialResources.getDrawable(this.context, a, R.styleable.Chip_checkedIcon));
        if (a.hasValue(R.styleable.Chip_checkedIconTint)) {
            setCheckedIconTint(MaterialResources.getColorStateList(this.context, a, R.styleable.Chip_checkedIconTint));
        }
        setShowMotionSpec(MotionSpec.createFromAttribute(this.context, a, R.styleable.Chip_showMotionSpec));
        setHideMotionSpec(MotionSpec.createFromAttribute(this.context, a, R.styleable.Chip_hideMotionSpec));
        setChipStartPadding(a.getDimension(R.styleable.Chip_chipStartPadding, 0.0f));
        setIconStartPadding(a.getDimension(R.styleable.Chip_iconStartPadding, 0.0f));
        setIconEndPadding(a.getDimension(R.styleable.Chip_iconEndPadding, 0.0f));
        setTextStartPadding(a.getDimension(R.styleable.Chip_textStartPadding, 0.0f));
        setTextEndPadding(a.getDimension(R.styleable.Chip_textEndPadding, 0.0f));
        setCloseIconStartPadding(a.getDimension(R.styleable.Chip_closeIconStartPadding, 0.0f));
        setCloseIconEndPadding(a.getDimension(R.styleable.Chip_closeIconEndPadding, 0.0f));
        setChipEndPadding(a.getDimension(R.styleable.Chip_chipEndPadding, 0.0f));
        setMaxWidth(a.getDimensionPixelSize(R.styleable.Chip_android_maxWidth, Integer.MAX_VALUE));
        a.recycle();
    }

    public void setUseCompatRipple(boolean useCompatRipple) {
        if (this.useCompatRipple != useCompatRipple) {
            this.useCompatRipple = useCompatRipple;
            updateCompatRippleColor();
            onStateChange(getState());
        }
    }

    public boolean getUseCompatRipple() {
        return this.useCompatRipple;
    }

    public void setDelegate(Delegate delegate) {
        this.delegate = new WeakReference<>(delegate);
    }

    protected void onSizeChange() {
        Delegate delegate = this.delegate.get();
        if (delegate != null) {
            delegate.onChipDrawableSizeChange();
        }
    }

    public void getChipTouchBounds(RectF bounds) {
        calculateChipTouchBounds(getBounds(), bounds);
    }

    public void getCloseIconTouchBounds(RectF bounds) {
        calculateCloseIconTouchBounds(getBounds(), bounds);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        int calculatedWidth = Math.round(this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding + this.textDrawableHelper.getTextWidth(getText().toString()) + this.textEndPadding + calculateCloseIconWidth() + this.chipEndPadding);
        return Math.min(calculatedWidth, this.maxWidth);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return (int) this.chipMinHeight;
    }

    private boolean showsChipIcon() {
        return this.chipIconVisible && this.chipIcon != null;
    }

    private boolean showsCheckedIcon() {
        return this.checkedIconVisible && this.checkedIcon != null && this.currentChecked;
    }

    private boolean showsCloseIcon() {
        return this.closeIconVisible && this.closeIcon != null;
    }

    private boolean canShowCheckedIcon() {
        return this.checkedIconVisible && this.checkedIcon != null && this.checkable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float calculateChipIconWidth() {
        if (showsChipIcon() || showsCheckedIcon()) {
            return this.iconStartPadding + getCurrentChipIconWidth() + this.iconEndPadding;
        }
        return 0.0f;
    }

    private float getCurrentChipIconWidth() {
        Drawable iconDrawable = this.currentChecked ? this.checkedIcon : this.chipIcon;
        float f = this.chipIconSize;
        if (f <= 0.0f && iconDrawable != null) {
            return iconDrawable.getIntrinsicWidth();
        }
        return f;
    }

    private float getCurrentChipIconHeight() {
        Drawable icon = this.currentChecked ? this.checkedIcon : this.chipIcon;
        float maxChipIconHeight = this.chipIconSize;
        if (maxChipIconHeight <= 0.0f && icon != null) {
            float maxChipIconHeight2 = (float) Math.ceil(ViewUtils.dpToPx(this.context, 24));
            if (icon.getIntrinsicHeight() <= maxChipIconHeight2) {
                return icon.getIntrinsicHeight();
            }
            return maxChipIconHeight2;
        }
        return maxChipIconHeight;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float calculateCloseIconWidth() {
        if (showsCloseIcon()) {
            return this.closeIconStartPadding + this.closeIconSize + this.closeIconEndPadding;
        }
        return 0.0f;
    }

    boolean isShapeThemingEnabled() {
        return this.isShapeThemingEnabled;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        if (bounds.isEmpty() || getAlpha() == 0) {
            return;
        }
        int saveCount = 0;
        if (this.alpha < 255) {
            saveCount = CanvasCompat.saveLayerAlpha(canvas, bounds.left, bounds.top, bounds.right, bounds.bottom, this.alpha);
        }
        drawChipSurface(canvas, bounds);
        drawChipBackground(canvas, bounds);
        if (this.isShapeThemingEnabled) {
            super.draw(canvas);
        }
        drawChipStroke(canvas, bounds);
        drawCompatRipple(canvas, bounds);
        drawChipIcon(canvas, bounds);
        drawCheckedIcon(canvas, bounds);
        if (this.shouldDrawText) {
            drawText(canvas, bounds);
        }
        drawCloseIcon(canvas, bounds);
        drawDebug(canvas, bounds);
        if (this.alpha < 255) {
            canvas.restoreToCount(saveCount);
        }
    }

    private void drawChipSurface(Canvas canvas, Rect bounds) {
        if (!this.isShapeThemingEnabled) {
            this.chipPaint.setColor(this.currentChipSurfaceColor);
            this.chipPaint.setStyle(Paint.Style.FILL);
            this.rectF.set(bounds);
            canvas.drawRoundRect(this.rectF, getChipCornerRadius(), getChipCornerRadius(), this.chipPaint);
        }
    }

    private void drawChipBackground(Canvas canvas, Rect bounds) {
        if (!this.isShapeThemingEnabled) {
            this.chipPaint.setColor(this.currentChipBackgroundColor);
            this.chipPaint.setStyle(Paint.Style.FILL);
            this.chipPaint.setColorFilter(getTintColorFilter());
            this.rectF.set(bounds);
            canvas.drawRoundRect(this.rectF, getChipCornerRadius(), getChipCornerRadius(), this.chipPaint);
        }
    }

    private void drawChipStroke(Canvas canvas, Rect bounds) {
        if (this.chipStrokeWidth > 0.0f && !this.isShapeThemingEnabled) {
            this.chipPaint.setColor(this.currentChipStrokeColor);
            this.chipPaint.setStyle(Paint.Style.STROKE);
            if (!this.isShapeThemingEnabled) {
                this.chipPaint.setColorFilter(getTintColorFilter());
            }
            this.rectF.set(bounds.left + (this.chipStrokeWidth / 2.0f), bounds.top + (this.chipStrokeWidth / 2.0f), bounds.right - (this.chipStrokeWidth / 2.0f), bounds.bottom - (this.chipStrokeWidth / 2.0f));
            float strokeCornerRadius = this.chipCornerRadius - (this.chipStrokeWidth / 2.0f);
            canvas.drawRoundRect(this.rectF, strokeCornerRadius, strokeCornerRadius, this.chipPaint);
        }
    }

    private void drawCompatRipple(Canvas canvas, Rect bounds) {
        this.chipPaint.setColor(this.currentCompatRippleColor);
        this.chipPaint.setStyle(Paint.Style.FILL);
        this.rectF.set(bounds);
        if (!this.isShapeThemingEnabled) {
            canvas.drawRoundRect(this.rectF, getChipCornerRadius(), getChipCornerRadius(), this.chipPaint);
            return;
        }
        calculatePathForSize(new RectF(bounds), this.shapePath);
        super.drawShape(canvas, this.chipPaint, this.shapePath, getBoundsAsRectF());
    }

    private void drawChipIcon(Canvas canvas, Rect bounds) {
        if (showsChipIcon()) {
            calculateChipIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.chipIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            this.chipIcon.draw(canvas);
            canvas.translate(-tx, -ty);
        }
    }

    private void drawCheckedIcon(Canvas canvas, Rect bounds) {
        if (showsCheckedIcon()) {
            calculateChipIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.checkedIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            this.checkedIcon.draw(canvas);
            canvas.translate(-tx, -ty);
        }
    }

    private void drawText(Canvas canvas, Rect bounds) {
        if (this.text != null) {
            Paint.Align align = calculateTextOriginAndAlignment(bounds, this.pointF);
            calculateTextBounds(bounds, this.rectF);
            if (this.textDrawableHelper.getTextAppearance() != null) {
                this.textDrawableHelper.getTextPaint().drawableState = getState();
                this.textDrawableHelper.updateTextPaintDrawState(this.context);
            }
            this.textDrawableHelper.getTextPaint().setTextAlign(align);
            boolean clip = Math.round(this.textDrawableHelper.getTextWidth(getText().toString())) > Math.round(this.rectF.width());
            int saveCount = 0;
            if (clip) {
                saveCount = canvas.save();
                canvas.clipRect(this.rectF);
            }
            CharSequence finalText = this.text;
            if (clip && this.truncateAt != null) {
                finalText = TextUtils.ellipsize(this.text, this.textDrawableHelper.getTextPaint(), this.rectF.width(), this.truncateAt);
            }
            canvas.drawText(finalText, 0, finalText.length(), this.pointF.x, this.pointF.y, this.textDrawableHelper.getTextPaint());
            if (clip) {
                canvas.restoreToCount(saveCount);
            }
        }
    }

    private void drawCloseIcon(Canvas canvas, Rect bounds) {
        if (showsCloseIcon()) {
            calculateCloseIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.closeIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            if (RippleUtils.USE_FRAMEWORK_RIPPLE) {
                this.closeIconRipple.setBounds(this.closeIcon.getBounds());
                this.closeIconRipple.jumpToCurrentState();
                this.closeIconRipple.draw(canvas);
            } else {
                this.closeIcon.draw(canvas);
            }
            canvas.translate(-tx, -ty);
        }
    }

    private void drawDebug(Canvas canvas, Rect bounds) {
        Paint paint = this.debugPaint;
        if (paint != null) {
            paint.setColor(ColorUtils.setAlphaComponent(ViewCompat.MEASURED_STATE_MASK, 127));
            canvas.drawRect(bounds, this.debugPaint);
            if (showsChipIcon() || showsCheckedIcon()) {
                calculateChipIconBounds(bounds, this.rectF);
                canvas.drawRect(this.rectF, this.debugPaint);
            }
            if (this.text != null) {
                canvas.drawLine(bounds.left, bounds.exactCenterY(), bounds.right, bounds.exactCenterY(), this.debugPaint);
            }
            if (showsCloseIcon()) {
                calculateCloseIconBounds(bounds, this.rectF);
                canvas.drawRect(this.rectF, this.debugPaint);
            }
            this.debugPaint.setColor(ColorUtils.setAlphaComponent(SupportMenu.CATEGORY_MASK, 127));
            calculateChipTouchBounds(bounds, this.rectF);
            canvas.drawRect(this.rectF, this.debugPaint);
            this.debugPaint.setColor(ColorUtils.setAlphaComponent(-16711936, 127));
            calculateCloseIconTouchBounds(bounds, this.rectF);
            canvas.drawRect(this.rectF, this.debugPaint);
        }
    }

    private void calculateChipIconBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsChipIcon() || showsCheckedIcon()) {
            float offsetFromStart = this.chipStartPadding + this.iconStartPadding;
            float chipWidth = getCurrentChipIconWidth();
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.left = bounds.left + offsetFromStart;
                outBounds.right = outBounds.left + chipWidth;
            } else {
                outBounds.right = bounds.right - offsetFromStart;
                outBounds.left = outBounds.right - chipWidth;
            }
            float chipHeight = getCurrentChipIconHeight();
            outBounds.top = bounds.exactCenterY() - (chipHeight / 2.0f);
            outBounds.bottom = outBounds.top + chipHeight;
        }
    }

    Paint.Align calculateTextOriginAndAlignment(Rect bounds, PointF pointF) {
        pointF.set(0.0f, 0.0f);
        Paint.Align align = Paint.Align.LEFT;
        if (this.text != null) {
            float offsetFromStart = this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                pointF.x = bounds.left + offsetFromStart;
                align = Paint.Align.LEFT;
            } else {
                pointF.x = bounds.right - offsetFromStart;
                align = Paint.Align.RIGHT;
            }
            pointF.y = bounds.centerY() - calculateTextCenterFromBaseline();
        }
        return align;
    }

    private float calculateTextCenterFromBaseline() {
        this.textDrawableHelper.getTextPaint().getFontMetrics(this.fontMetrics);
        return (this.fontMetrics.descent + this.fontMetrics.ascent) / 2.0f;
    }

    private void calculateTextBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (this.text != null) {
            float offsetFromStart = this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding;
            float offsetFromEnd = this.chipEndPadding + calculateCloseIconWidth() + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.left = bounds.left + offsetFromStart;
                outBounds.right = bounds.right - offsetFromEnd;
            } else {
                outBounds.left = bounds.left + offsetFromEnd;
                outBounds.right = bounds.right - offsetFromStart;
            }
            outBounds.top = bounds.top;
            outBounds.bottom = bounds.bottom;
        }
    }

    private void calculateCloseIconBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = bounds.right - offsetFromEnd;
                outBounds.left = outBounds.right - this.closeIconSize;
            } else {
                outBounds.left = bounds.left + offsetFromEnd;
                outBounds.right = outBounds.left + this.closeIconSize;
            }
            outBounds.top = bounds.exactCenterY() - (this.closeIconSize / 2.0f);
            outBounds.bottom = outBounds.top + this.closeIconSize;
        }
    }

    private void calculateChipTouchBounds(Rect bounds, RectF outBounds) {
        outBounds.set(bounds);
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding + this.closeIconSize + this.closeIconStartPadding + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = bounds.right - offsetFromEnd;
            } else {
                outBounds.left = bounds.left + offsetFromEnd;
            }
        }
    }

    private void calculateCloseIconTouchBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding + this.closeIconSize + this.closeIconStartPadding + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = bounds.right;
                outBounds.left = outBounds.right - offsetFromEnd;
            } else {
                outBounds.left = bounds.left;
                outBounds.right = bounds.left + offsetFromEnd;
            }
            outBounds.top = bounds.top;
            outBounds.bottom = bounds.bottom;
        }
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public boolean isStateful() {
        return isStateful(this.chipSurfaceColor) || isStateful(this.chipBackgroundColor) || isStateful(this.chipStrokeColor) || (this.useCompatRipple && isStateful(this.compatRippleColor)) || isStateful(this.textDrawableHelper.getTextAppearance()) || canShowCheckedIcon() || isStateful(this.chipIcon) || isStateful(this.checkedIcon) || isStateful(this.tint);
    }

    public boolean isCloseIconStateful() {
        return isStateful(this.closeIcon);
    }

    public boolean setCloseIconState(int[] stateSet) {
        if (!Arrays.equals(this.closeIconStateSet, stateSet)) {
            this.closeIconStateSet = stateSet;
            if (showsCloseIcon()) {
                return onStateChange(getState(), stateSet);
            }
            return false;
        }
        return false;
    }

    public int[] getCloseIconState() {
        return this.closeIconStateSet;
    }

    @Override // com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public void onTextSizeChange() {
        onSizeChange();
        invalidateSelf();
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable, com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public boolean onStateChange(int[] state) {
        if (this.isShapeThemingEnabled) {
            super.onStateChange(state);
        }
        return onStateChange(state, getCloseIconState());
    }

    private boolean onStateChange(int[] chipState, int[] closeIconState) {
        int newChipSurfaceColor;
        int newChipBackgroundColor;
        int newChipStrokeColor;
        int newCompatRippleColor;
        int newTextColor;
        boolean invalidate = super.onStateChange(chipState);
        boolean sizeChanged = false;
        ColorStateList colorStateList = this.chipSurfaceColor;
        if (colorStateList != null) {
            newChipSurfaceColor = colorStateList.getColorForState(chipState, this.currentChipSurfaceColor);
        } else {
            newChipSurfaceColor = 0;
        }
        int newChipSurfaceColor2 = compositeElevationOverlayIfNeeded(newChipSurfaceColor);
        if (this.currentChipSurfaceColor != newChipSurfaceColor2) {
            this.currentChipSurfaceColor = newChipSurfaceColor2;
            invalidate = true;
        }
        ColorStateList colorStateList2 = this.chipBackgroundColor;
        if (colorStateList2 != null) {
            newChipBackgroundColor = colorStateList2.getColorForState(chipState, this.currentChipBackgroundColor);
        } else {
            newChipBackgroundColor = 0;
        }
        int newChipBackgroundColor2 = compositeElevationOverlayIfNeeded(newChipBackgroundColor);
        if (this.currentChipBackgroundColor != newChipBackgroundColor2) {
            this.currentChipBackgroundColor = newChipBackgroundColor2;
            invalidate = true;
        }
        int newCompositeSurfaceBackgroundColor = MaterialColors.layer(newChipSurfaceColor2, newChipBackgroundColor2);
        boolean newChecked = true;
        boolean shouldUpdate = this.currentCompositeSurfaceBackgroundColor != newCompositeSurfaceBackgroundColor;
        if (shouldUpdate | (getFillColor() == null)) {
            this.currentCompositeSurfaceBackgroundColor = newCompositeSurfaceBackgroundColor;
            setFillColor(ColorStateList.valueOf(newCompositeSurfaceBackgroundColor));
            invalidate = true;
        }
        ColorStateList colorStateList3 = this.chipStrokeColor;
        if (colorStateList3 != null) {
            newChipStrokeColor = colorStateList3.getColorForState(chipState, this.currentChipStrokeColor);
        } else {
            newChipStrokeColor = 0;
        }
        if (this.currentChipStrokeColor != newChipStrokeColor) {
            this.currentChipStrokeColor = newChipStrokeColor;
            invalidate = true;
        }
        if (this.compatRippleColor != null && RippleUtils.shouldDrawRippleCompat(chipState)) {
            newCompatRippleColor = this.compatRippleColor.getColorForState(chipState, this.currentCompatRippleColor);
        } else {
            newCompatRippleColor = 0;
        }
        if (this.currentCompatRippleColor != newCompatRippleColor) {
            this.currentCompatRippleColor = newCompatRippleColor;
            if (this.useCompatRipple) {
                invalidate = true;
            }
        }
        if (this.textDrawableHelper.getTextAppearance() != null && this.textDrawableHelper.getTextAppearance().getTextColor() != null) {
            newTextColor = this.textDrawableHelper.getTextAppearance().getTextColor().getColorForState(chipState, this.currentTextColor);
        } else {
            newTextColor = 0;
        }
        if (this.currentTextColor != newTextColor) {
            this.currentTextColor = newTextColor;
            invalidate = true;
        }
        newChecked = (hasState(getState(), 16842912) && this.checkable) ? false : false;
        if (this.currentChecked != newChecked && this.checkedIcon != null) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.currentChecked = newChecked;
            float newChipIconWidth = calculateChipIconWidth();
            invalidate = true;
            if (oldChipIconWidth != newChipIconWidth) {
                sizeChanged = true;
            }
        }
        ColorStateList colorStateList4 = this.tint;
        int newTint = colorStateList4 != null ? colorStateList4.getColorForState(chipState, this.currentTint) : 0;
        if (this.currentTint != newTint) {
            this.currentTint = newTint;
            this.tintFilter = DrawableUtils.updateTintFilter(this, this.tint, this.tintMode);
            invalidate = true;
        }
        if (isStateful(this.chipIcon)) {
            invalidate |= this.chipIcon.setState(chipState);
        }
        if (isStateful(this.checkedIcon)) {
            invalidate |= this.checkedIcon.setState(chipState);
        }
        if (isStateful(this.closeIcon)) {
            int[] closeIconMergedState = new int[chipState.length + closeIconState.length];
            System.arraycopy(chipState, 0, closeIconMergedState, 0, chipState.length);
            System.arraycopy(closeIconState, 0, closeIconMergedState, chipState.length, closeIconState.length);
            invalidate |= this.closeIcon.setState(closeIconMergedState);
        }
        if (RippleUtils.USE_FRAMEWORK_RIPPLE && isStateful(this.closeIconRipple)) {
            invalidate |= this.closeIconRipple.setState(closeIconState);
        }
        if (invalidate) {
            invalidateSelf();
        }
        if (sizeChanged) {
            onSizeChange();
        }
        return invalidate;
    }

    private static boolean isStateful(ColorStateList colorStateList) {
        return colorStateList != null && colorStateList.isStateful();
    }

    private static boolean isStateful(Drawable drawable) {
        return drawable != null && drawable.isStateful();
    }

    private static boolean isStateful(TextAppearance textAppearance) {
        return (textAppearance == null || textAppearance.getTextColor() == null || !textAppearance.getTextColor().isStateful()) ? false : true;
    }

    @Override // android.graphics.drawable.Drawable
    public boolean onLayoutDirectionChanged(int layoutDirection) {
        boolean invalidate = super.onLayoutDirectionChanged(layoutDirection);
        if (showsChipIcon()) {
            invalidate |= DrawableCompat.setLayoutDirection(this.chipIcon, layoutDirection);
        }
        if (showsCheckedIcon()) {
            invalidate |= DrawableCompat.setLayoutDirection(this.checkedIcon, layoutDirection);
        }
        if (showsCloseIcon()) {
            invalidate |= DrawableCompat.setLayoutDirection(this.closeIcon, layoutDirection);
        }
        if (invalidate) {
            invalidateSelf();
            return true;
        }
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    protected boolean onLevelChange(int level) {
        boolean invalidate = super.onLevelChange(level);
        if (showsChipIcon()) {
            invalidate |= this.chipIcon.setLevel(level);
        }
        if (showsCheckedIcon()) {
            invalidate |= this.checkedIcon.setLevel(level);
        }
        if (showsCloseIcon()) {
            invalidate |= this.closeIcon.setLevel(level);
        }
        if (invalidate) {
            invalidateSelf();
        }
        return invalidate;
    }

    @Override // android.graphics.drawable.Drawable
    public boolean setVisible(boolean visible, boolean restart) {
        boolean invalidate = super.setVisible(visible, restart);
        if (showsChipIcon()) {
            invalidate |= this.chipIcon.setVisible(visible, restart);
        }
        if (showsCheckedIcon()) {
            invalidate |= this.checkedIcon.setVisible(visible, restart);
        }
        if (showsCloseIcon()) {
            invalidate |= this.closeIcon.setVisible(visible, restart);
        }
        if (invalidate) {
            invalidateSelf();
        }
        return invalidate;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        if (this.alpha != alpha) {
            this.alpha = alpha;
            invalidateSelf();
        }
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.alpha;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        if (this.colorFilter != colorFilter) {
            this.colorFilter = colorFilter;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public ColorFilter getColorFilter() {
        return this.colorFilter;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable, androidx.core.graphics.drawable.TintAwareDrawable
    public void setTintList(ColorStateList tint) {
        if (this.tint != tint) {
            this.tint = tint;
            onStateChange(getState());
        }
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable, androidx.core.graphics.drawable.TintAwareDrawable
    public void setTintMode(PorterDuff.Mode tintMode) {
        if (this.tintMode != tintMode) {
            this.tintMode = tintMode;
            this.tintFilter = DrawableUtils.updateTintFilter(this, this.tint, tintMode);
            invalidateSelf();
        }
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void getOutline(Outline outline) {
        if (this.isShapeThemingEnabled) {
            super.getOutline(outline);
            return;
        }
        Rect bounds = getBounds();
        if (!bounds.isEmpty()) {
            outline.setRoundRect(bounds, this.chipCornerRadius);
        } else {
            outline.setRoundRect(0, 0, getIntrinsicWidth(), getIntrinsicHeight(), this.chipCornerRadius);
        }
        outline.setAlpha(getAlpha() / 255.0f);
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.invalidateDrawable(this);
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable who, Runnable what, long when) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.scheduleDrawable(this, what, when);
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable who, Runnable what) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.unscheduleDrawable(this, what);
        }
    }

    private void unapplyChildDrawable(Drawable drawable) {
        if (drawable != null) {
            drawable.setCallback(null);
        }
    }

    private void applyChildDrawable(Drawable drawable) {
        if (drawable == null) {
            return;
        }
        drawable.setCallback(this);
        DrawableCompat.setLayoutDirection(drawable, DrawableCompat.getLayoutDirection(this));
        drawable.setLevel(getLevel());
        drawable.setVisible(isVisible(), false);
        if (drawable == this.closeIcon) {
            if (drawable.isStateful()) {
                drawable.setState(getCloseIconState());
            }
            DrawableCompat.setTintList(drawable, this.closeIconTint);
            return;
        }
        Drawable drawable2 = this.chipIcon;
        if (drawable == drawable2 && this.hasChipIconTint) {
            DrawableCompat.setTintList(drawable2, this.chipIconTint);
        }
        if (drawable.isStateful()) {
            drawable.setState(getState());
        }
    }

    private ColorFilter getTintColorFilter() {
        ColorFilter colorFilter = this.colorFilter;
        return colorFilter != null ? colorFilter : this.tintFilter;
    }

    private void updateCompatRippleColor() {
        this.compatRippleColor = this.useCompatRipple ? RippleUtils.sanitizeRippleDrawableColor(this.rippleColor) : null;
    }

    private void setChipSurfaceColor(ColorStateList chipSurfaceColor) {
        if (this.chipSurfaceColor != chipSurfaceColor) {
            this.chipSurfaceColor = chipSurfaceColor;
            onStateChange(getState());
        }
    }

    private static boolean hasState(int[] stateSet, int state) {
        if (stateSet == null) {
            return false;
        }
        for (int s : stateSet) {
            if (s == state) {
                return true;
            }
        }
        return false;
    }

    public void setTextSize(float size) {
        TextAppearance textAppearance = getTextAppearance();
        if (textAppearance != null) {
            textAppearance.setTextSize(size);
            this.textDrawableHelper.getTextPaint().setTextSize(size);
            onTextSizeChange();
        }
    }

    public void setTextColor(int color) {
        setTextColor(ColorStateList.valueOf(color));
    }

    public void setTextColor(ColorStateList color) {
        TextAppearance textAppearance = getTextAppearance();
        if (textAppearance != null) {
            textAppearance.setTextColor(color);
            invalidateSelf();
        }
    }

    public ColorStateList getChipBackgroundColor() {
        return this.chipBackgroundColor;
    }

    public void setChipBackgroundColorResource(int id) {
        setChipBackgroundColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipBackgroundColor(ColorStateList chipBackgroundColor) {
        if (this.chipBackgroundColor != chipBackgroundColor) {
            this.chipBackgroundColor = chipBackgroundColor;
            onStateChange(getState());
        }
    }

    public float getChipMinHeight() {
        return this.chipMinHeight;
    }

    public void setChipMinHeightResource(int id) {
        setChipMinHeight(this.context.getResources().getDimension(id));
    }

    public void setChipMinHeight(float chipMinHeight) {
        if (this.chipMinHeight != chipMinHeight) {
            this.chipMinHeight = chipMinHeight;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getChipCornerRadius() {
        return this.isShapeThemingEnabled ? getTopLeftCornerResolvedSize() : this.chipCornerRadius;
    }

    @Deprecated
    public void setChipCornerRadiusResource(int id) {
        setChipCornerRadius(this.context.getResources().getDimension(id));
    }

    @Deprecated
    public void setChipCornerRadius(float chipCornerRadius) {
        if (this.chipCornerRadius != chipCornerRadius) {
            this.chipCornerRadius = chipCornerRadius;
            setShapeAppearanceModel(getShapeAppearanceModel().withCornerSize(chipCornerRadius));
        }
    }

    public ColorStateList getChipStrokeColor() {
        return this.chipStrokeColor;
    }

    public void setChipStrokeColorResource(int id) {
        setChipStrokeColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipStrokeColor(ColorStateList chipStrokeColor) {
        if (this.chipStrokeColor != chipStrokeColor) {
            this.chipStrokeColor = chipStrokeColor;
            if (this.isShapeThemingEnabled) {
                setStrokeColor(chipStrokeColor);
            }
            onStateChange(getState());
        }
    }

    public float getChipStrokeWidth() {
        return this.chipStrokeWidth;
    }

    public void setChipStrokeWidthResource(int id) {
        setChipStrokeWidth(this.context.getResources().getDimension(id));
    }

    public void setChipStrokeWidth(float chipStrokeWidth) {
        if (this.chipStrokeWidth != chipStrokeWidth) {
            this.chipStrokeWidth = chipStrokeWidth;
            this.chipPaint.setStrokeWidth(chipStrokeWidth);
            if (this.isShapeThemingEnabled) {
                super.setStrokeWidth(chipStrokeWidth);
            }
            invalidateSelf();
        }
    }

    public ColorStateList getRippleColor() {
        return this.rippleColor;
    }

    public void setRippleColorResource(int id) {
        setRippleColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setRippleColor(ColorStateList rippleColor) {
        if (this.rippleColor != rippleColor) {
            this.rippleColor = rippleColor;
            updateCompatRippleColor();
            onStateChange(getState());
        }
    }

    public CharSequence getText() {
        return this.text;
    }

    public void setTextResource(int id) {
        setText(this.context.getResources().getString(id));
    }

    public void setText(CharSequence text) {
        if (text == null) {
            text = "";
        }
        if (!TextUtils.equals(this.text, text)) {
            this.text = text;
            this.textDrawableHelper.setTextWidthDirty(true);
            invalidateSelf();
            onSizeChange();
        }
    }

    public TextAppearance getTextAppearance() {
        return this.textDrawableHelper.getTextAppearance();
    }

    public void setTextAppearanceResource(int id) {
        setTextAppearance(new TextAppearance(this.context, id));
    }

    public void setTextAppearance(TextAppearance textAppearance) {
        this.textDrawableHelper.setTextAppearance(textAppearance, this.context);
    }

    public TextUtils.TruncateAt getEllipsize() {
        return this.truncateAt;
    }

    public void setEllipsize(TextUtils.TruncateAt truncateAt) {
        this.truncateAt = truncateAt;
    }

    public boolean isChipIconVisible() {
        return this.chipIconVisible;
    }

    @Deprecated
    public boolean isChipIconEnabled() {
        return isChipIconVisible();
    }

    public void setChipIconVisible(int id) {
        setChipIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setChipIconVisible(boolean chipIconVisible) {
        if (this.chipIconVisible != chipIconVisible) {
            boolean oldShowsChipIcon = showsChipIcon();
            this.chipIconVisible = chipIconVisible;
            boolean newShowsChipIcon = showsChipIcon();
            boolean changed = oldShowsChipIcon != newShowsChipIcon;
            if (changed) {
                if (newShowsChipIcon) {
                    applyChildDrawable(this.chipIcon);
                } else {
                    unapplyChildDrawable(this.chipIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setChipIconEnabledResource(int id) {
        setChipIconVisible(id);
    }

    @Deprecated
    public void setChipIconEnabled(boolean chipIconEnabled) {
        setChipIconVisible(chipIconEnabled);
    }

    public Drawable getChipIcon() {
        Drawable drawable = this.chipIcon;
        if (drawable != null) {
            return DrawableCompat.unwrap(drawable);
        }
        return null;
    }

    public void setChipIconResource(int id) {
        setChipIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setChipIcon(Drawable chipIcon) {
        Drawable oldChipIcon = getChipIcon();
        if (oldChipIcon != chipIcon) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.chipIcon = chipIcon != null ? DrawableCompat.wrap(chipIcon).mutate() : null;
            float newChipIconWidth = calculateChipIconWidth();
            unapplyChildDrawable(oldChipIcon);
            if (showsChipIcon()) {
                applyChildDrawable(this.chipIcon);
            }
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public ColorStateList getChipIconTint() {
        return this.chipIconTint;
    }

    public void setChipIconTintResource(int id) {
        setChipIconTint(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipIconTint(ColorStateList chipIconTint) {
        this.hasChipIconTint = true;
        if (this.chipIconTint != chipIconTint) {
            this.chipIconTint = chipIconTint;
            if (showsChipIcon()) {
                DrawableCompat.setTintList(this.chipIcon, chipIconTint);
            }
            onStateChange(getState());
        }
    }

    public float getChipIconSize() {
        return this.chipIconSize;
    }

    public void setChipIconSizeResource(int id) {
        setChipIconSize(this.context.getResources().getDimension(id));
    }

    public void setChipIconSize(float chipIconSize) {
        if (this.chipIconSize != chipIconSize) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.chipIconSize = chipIconSize;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public boolean isCloseIconVisible() {
        return this.closeIconVisible;
    }

    @Deprecated
    public boolean isCloseIconEnabled() {
        return isCloseIconVisible();
    }

    public void setCloseIconVisible(int id) {
        setCloseIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setCloseIconVisible(boolean closeIconVisible) {
        if (this.closeIconVisible != closeIconVisible) {
            boolean oldShowsCloseIcon = showsCloseIcon();
            this.closeIconVisible = closeIconVisible;
            boolean newShowsCloseIcon = showsCloseIcon();
            boolean changed = oldShowsCloseIcon != newShowsCloseIcon;
            if (changed) {
                if (newShowsCloseIcon) {
                    applyChildDrawable(this.closeIcon);
                } else {
                    unapplyChildDrawable(this.closeIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setCloseIconEnabledResource(int id) {
        setCloseIconVisible(id);
    }

    @Deprecated
    public void setCloseIconEnabled(boolean closeIconEnabled) {
        setCloseIconVisible(closeIconEnabled);
    }

    public Drawable getCloseIcon() {
        Drawable drawable = this.closeIcon;
        if (drawable != null) {
            return DrawableCompat.unwrap(drawable);
        }
        return null;
    }

    public void setCloseIconResource(int id) {
        setCloseIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setCloseIcon(Drawable closeIcon) {
        Drawable oldCloseIcon = getCloseIcon();
        if (oldCloseIcon != closeIcon) {
            float oldCloseIconWidth = calculateCloseIconWidth();
            this.closeIcon = closeIcon != null ? DrawableCompat.wrap(closeIcon).mutate() : null;
            if (RippleUtils.USE_FRAMEWORK_RIPPLE) {
                updateFrameworkCloseIconRipple();
            }
            float newCloseIconWidth = calculateCloseIconWidth();
            unapplyChildDrawable(oldCloseIcon);
            if (showsCloseIcon()) {
                applyChildDrawable(this.closeIcon);
            }
            invalidateSelf();
            if (oldCloseIconWidth != newCloseIconWidth) {
                onSizeChange();
            }
        }
    }

    private void updateFrameworkCloseIconRipple() {
        this.closeIconRipple = new RippleDrawable(RippleUtils.sanitizeRippleDrawableColor(getRippleColor()), this.closeIcon, closeIconRippleMask);
    }

    public ColorStateList getCloseIconTint() {
        return this.closeIconTint;
    }

    public void setCloseIconTintResource(int id) {
        setCloseIconTint(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setCloseIconTint(ColorStateList closeIconTint) {
        if (this.closeIconTint != closeIconTint) {
            this.closeIconTint = closeIconTint;
            if (showsCloseIcon()) {
                DrawableCompat.setTintList(this.closeIcon, closeIconTint);
            }
            onStateChange(getState());
        }
    }

    public float getCloseIconSize() {
        return this.closeIconSize;
    }

    public void setCloseIconSizeResource(int id) {
        setCloseIconSize(this.context.getResources().getDimension(id));
    }

    public void setCloseIconSize(float closeIconSize) {
        if (this.closeIconSize != closeIconSize) {
            this.closeIconSize = closeIconSize;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public void setCloseIconContentDescription(CharSequence closeIconContentDescription) {
        if (this.closeIconContentDescription != closeIconContentDescription) {
            this.closeIconContentDescription = BidiFormatter.getInstance().unicodeWrap(closeIconContentDescription);
            invalidateSelf();
        }
    }

    public CharSequence getCloseIconContentDescription() {
        return this.closeIconContentDescription;
    }

    public boolean isCheckable() {
        return this.checkable;
    }

    public void setCheckableResource(int id) {
        setCheckable(this.context.getResources().getBoolean(id));
    }

    public void setCheckable(boolean checkable) {
        if (this.checkable != checkable) {
            this.checkable = checkable;
            float oldChipIconWidth = calculateChipIconWidth();
            if (!checkable && this.currentChecked) {
                this.currentChecked = false;
            }
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public boolean isCheckedIconVisible() {
        return this.checkedIconVisible;
    }

    @Deprecated
    public boolean isCheckedIconEnabled() {
        return isCheckedIconVisible();
    }

    public void setCheckedIconVisible(int id) {
        setCheckedIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setCheckedIconVisible(boolean checkedIconVisible) {
        if (this.checkedIconVisible != checkedIconVisible) {
            boolean oldShowsCheckedIcon = showsCheckedIcon();
            this.checkedIconVisible = checkedIconVisible;
            boolean newShowsCheckedIcon = showsCheckedIcon();
            boolean changed = oldShowsCheckedIcon != newShowsCheckedIcon;
            if (changed) {
                if (newShowsCheckedIcon) {
                    applyChildDrawable(this.checkedIcon);
                } else {
                    unapplyChildDrawable(this.checkedIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setCheckedIconEnabledResource(int id) {
        setCheckedIconVisible(this.context.getResources().getBoolean(id));
    }

    @Deprecated
    public void setCheckedIconEnabled(boolean checkedIconEnabled) {
        setCheckedIconVisible(checkedIconEnabled);
    }

    public Drawable getCheckedIcon() {
        return this.checkedIcon;
    }

    public void setCheckedIconResource(int id) {
        setCheckedIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setCheckedIcon(Drawable checkedIcon) {
        Drawable oldCheckedIcon = this.checkedIcon;
        if (oldCheckedIcon != checkedIcon) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.checkedIcon = checkedIcon;
            float newChipIconWidth = calculateChipIconWidth();
            unapplyChildDrawable(this.checkedIcon);
            applyChildDrawable(this.checkedIcon);
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public ColorStateList getCheckedIconTint() {
        return this.checkedIconTint;
    }

    public void setCheckedIconTintResource(int id) {
        setCheckedIconTint(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setCheckedIconTint(ColorStateList checkedIconTint) {
        if (this.checkedIconTint != checkedIconTint) {
            this.checkedIconTint = checkedIconTint;
            if (canShowCheckedIcon()) {
                DrawableCompat.setTintList(this.checkedIcon, checkedIconTint);
            }
            onStateChange(getState());
        }
    }

    public MotionSpec getShowMotionSpec() {
        return this.showMotionSpec;
    }

    public void setShowMotionSpecResource(int id) {
        setShowMotionSpec(MotionSpec.createFromResource(this.context, id));
    }

    public void setShowMotionSpec(MotionSpec showMotionSpec) {
        this.showMotionSpec = showMotionSpec;
    }

    public MotionSpec getHideMotionSpec() {
        return this.hideMotionSpec;
    }

    public void setHideMotionSpecResource(int id) {
        setHideMotionSpec(MotionSpec.createFromResource(this.context, id));
    }

    public void setHideMotionSpec(MotionSpec hideMotionSpec) {
        this.hideMotionSpec = hideMotionSpec;
    }

    public float getChipStartPadding() {
        return this.chipStartPadding;
    }

    public void setChipStartPaddingResource(int id) {
        setChipStartPadding(this.context.getResources().getDimension(id));
    }

    public void setChipStartPadding(float chipStartPadding) {
        if (this.chipStartPadding != chipStartPadding) {
            this.chipStartPadding = chipStartPadding;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getIconStartPadding() {
        return this.iconStartPadding;
    }

    public void setIconStartPaddingResource(int id) {
        setIconStartPadding(this.context.getResources().getDimension(id));
    }

    public void setIconStartPadding(float iconStartPadding) {
        if (this.iconStartPadding != iconStartPadding) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.iconStartPadding = iconStartPadding;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public float getIconEndPadding() {
        return this.iconEndPadding;
    }

    public void setIconEndPaddingResource(int id) {
        setIconEndPadding(this.context.getResources().getDimension(id));
    }

    public void setIconEndPadding(float iconEndPadding) {
        if (this.iconEndPadding != iconEndPadding) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.iconEndPadding = iconEndPadding;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public float getTextStartPadding() {
        return this.textStartPadding;
    }

    public void setTextStartPaddingResource(int id) {
        setTextStartPadding(this.context.getResources().getDimension(id));
    }

    public void setTextStartPadding(float textStartPadding) {
        if (this.textStartPadding != textStartPadding) {
            this.textStartPadding = textStartPadding;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getTextEndPadding() {
        return this.textEndPadding;
    }

    public void setTextEndPaddingResource(int id) {
        setTextEndPadding(this.context.getResources().getDimension(id));
    }

    public void setTextEndPadding(float textEndPadding) {
        if (this.textEndPadding != textEndPadding) {
            this.textEndPadding = textEndPadding;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getCloseIconStartPadding() {
        return this.closeIconStartPadding;
    }

    public void setCloseIconStartPaddingResource(int id) {
        setCloseIconStartPadding(this.context.getResources().getDimension(id));
    }

    public void setCloseIconStartPadding(float closeIconStartPadding) {
        if (this.closeIconStartPadding != closeIconStartPadding) {
            this.closeIconStartPadding = closeIconStartPadding;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public float getCloseIconEndPadding() {
        return this.closeIconEndPadding;
    }

    public void setCloseIconEndPaddingResource(int id) {
        setCloseIconEndPadding(this.context.getResources().getDimension(id));
    }

    public void setCloseIconEndPadding(float closeIconEndPadding) {
        if (this.closeIconEndPadding != closeIconEndPadding) {
            this.closeIconEndPadding = closeIconEndPadding;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public float getChipEndPadding() {
        return this.chipEndPadding;
    }

    public void setChipEndPaddingResource(int id) {
        setChipEndPadding(this.context.getResources().getDimension(id));
    }

    public void setChipEndPadding(float chipEndPadding) {
        if (this.chipEndPadding != chipEndPadding) {
            this.chipEndPadding = chipEndPadding;
            invalidateSelf();
            onSizeChange();
        }
    }

    public int getMaxWidth() {
        return this.maxWidth;
    }

    public void setMaxWidth(int maxWidth) {
        this.maxWidth = maxWidth;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean shouldDrawText() {
        return this.shouldDrawText;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setShouldDrawText(boolean shouldDrawText) {
        this.shouldDrawText = shouldDrawText;
    }
}
