package com.google.android.material.tooltip;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.graphics.ColorUtils;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.TextDrawableHelper;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.resources.TextAppearance;
import com.google.android.material.shape.EdgeTreatment;
import com.google.android.material.shape.MarkerEdgeTreatment;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.OffsetEdgeTreatment;
/* loaded from: classes.dex */
public class TooltipDrawable extends MaterialShapeDrawable implements TextDrawableHelper.TextDrawableDelegate {
    private static final int DEFAULT_STYLE = R.style.Widget_MaterialComponents_Tooltip;
    private static final int DEFAULT_THEME_ATTR = R.attr.tooltipStyle;
    private int arrowSize;
    private final View.OnLayoutChangeListener attachedViewLayoutChangeListener;
    private final Context context;
    private final Rect displayFrame;
    private final Paint.FontMetrics fontMetrics;
    private float labelOpacity;
    private int layoutMargin;
    private int locationOnScreenX;
    private int minHeight;
    private int minWidth;
    private int padding;
    private CharSequence text;
    private final TextDrawableHelper textDrawableHelper;
    private final float tooltipPivotX;
    private float tooltipPivotY;
    private float tooltipScaleX;
    private float tooltipScaleY;

    public static TooltipDrawable createFromAttributes(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        TooltipDrawable tooltip = new TooltipDrawable(context, attrs, defStyleAttr, defStyleRes);
        tooltip.loadFromAttributes(attrs, defStyleAttr, defStyleRes);
        return tooltip;
    }

    public static TooltipDrawable createFromAttributes(Context context, AttributeSet attrs) {
        return createFromAttributes(context, attrs, DEFAULT_THEME_ATTR, DEFAULT_STYLE);
    }

    public static TooltipDrawable create(Context context) {
        return createFromAttributes(context, null, DEFAULT_THEME_ATTR, DEFAULT_STYLE);
    }

    private TooltipDrawable(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        this.fontMetrics = new Paint.FontMetrics();
        TextDrawableHelper textDrawableHelper = new TextDrawableHelper(this);
        this.textDrawableHelper = textDrawableHelper;
        this.attachedViewLayoutChangeListener = new View.OnLayoutChangeListener() { // from class: com.google.android.material.tooltip.TooltipDrawable.1
            @Override // android.view.View.OnLayoutChangeListener
            public void onLayoutChange(View v, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                TooltipDrawable.this.updateLocationOnScreen(v);
            }
        };
        this.displayFrame = new Rect();
        this.tooltipScaleX = 1.0f;
        this.tooltipScaleY = 1.0f;
        this.tooltipPivotX = 0.5f;
        this.tooltipPivotY = 0.5f;
        this.labelOpacity = 1.0f;
        this.context = context;
        textDrawableHelper.getTextPaint().density = context.getResources().getDisplayMetrics().density;
        textDrawableHelper.getTextPaint().setTextAlign(Paint.Align.CENTER);
    }

    private void loadFromAttributes(AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(this.context, attrs, R.styleable.Tooltip, defStyleAttr, defStyleRes, new int[0]);
        this.arrowSize = this.context.getResources().getDimensionPixelSize(R.dimen.mtrl_tooltip_arrowSize);
        setShapeAppearanceModel(getShapeAppearanceModel().toBuilder().setBottomEdge(createMarkerEdge()).build());
        setText(a.getText(R.styleable.Tooltip_android_text));
        TextAppearance textAppearance = MaterialResources.getTextAppearance(this.context, a, R.styleable.Tooltip_android_textAppearance);
        if (textAppearance != null && a.hasValue(R.styleable.Tooltip_android_textColor)) {
            textAppearance.setTextColor(MaterialResources.getColorStateList(this.context, a, R.styleable.Tooltip_android_textColor));
        }
        setTextAppearance(textAppearance);
        int onBackground = MaterialColors.getColor(this.context, R.attr.colorOnBackground, TooltipDrawable.class.getCanonicalName());
        int background = MaterialColors.getColor(this.context, 16842801, TooltipDrawable.class.getCanonicalName());
        int backgroundTintDefault = MaterialColors.layer(ColorUtils.setAlphaComponent(background, 229), ColorUtils.setAlphaComponent(onBackground, 153));
        setFillColor(ColorStateList.valueOf(a.getColor(R.styleable.Tooltip_backgroundTint, backgroundTintDefault)));
        setStrokeColor(ColorStateList.valueOf(MaterialColors.getColor(this.context, R.attr.colorSurface, TooltipDrawable.class.getCanonicalName())));
        this.padding = a.getDimensionPixelSize(R.styleable.Tooltip_android_padding, 0);
        this.minWidth = a.getDimensionPixelSize(R.styleable.Tooltip_android_minWidth, 0);
        this.minHeight = a.getDimensionPixelSize(R.styleable.Tooltip_android_minHeight, 0);
        this.layoutMargin = a.getDimensionPixelSize(R.styleable.Tooltip_android_layout_margin, 0);
        a.recycle();
    }

    public CharSequence getText() {
        return this.text;
    }

    public void setTextResource(int id) {
        setText(this.context.getResources().getString(id));
    }

    public void setText(CharSequence text) {
        if (!TextUtils.equals(this.text, text)) {
            this.text = text;
            this.textDrawableHelper.setTextWidthDirty(true);
            invalidateSelf();
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

    public int getMinWidth() {
        return this.minWidth;
    }

    public void setMinWidth(int minWidth) {
        this.minWidth = minWidth;
        invalidateSelf();
    }

    public int getMinHeight() {
        return this.minHeight;
    }

    public void setMinHeight(int minHeight) {
        this.minHeight = minHeight;
        invalidateSelf();
    }

    public int getTextPadding() {
        return this.padding;
    }

    public void setTextPadding(int padding) {
        this.padding = padding;
        invalidateSelf();
    }

    public int getLayoutMargin() {
        return this.layoutMargin;
    }

    public void setLayoutMargin(int layoutMargin) {
        this.layoutMargin = layoutMargin;
        invalidateSelf();
    }

    public void setRevealFraction(float fraction) {
        this.tooltipPivotY = 1.2f;
        this.tooltipScaleX = fraction;
        this.tooltipScaleY = fraction;
        this.labelOpacity = AnimationUtils.lerp(0.0f, 1.0f, 0.19f, 1.0f, fraction);
        invalidateSelf();
    }

    public void setRelativeToView(View view) {
        if (view == null) {
            return;
        }
        updateLocationOnScreen(view);
        view.addOnLayoutChangeListener(this.attachedViewLayoutChangeListener);
    }

    public void detachView(View view) {
        if (view == null) {
            return;
        }
        view.removeOnLayoutChangeListener(this.attachedViewLayoutChangeListener);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return (int) Math.max((this.padding * 2) + getTextWidth(), this.minWidth);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return (int) Math.max(this.textDrawableHelper.getTextPaint().getTextSize(), this.minHeight);
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        canvas.save();
        float translateX = calculatePointerOffset();
        float translateY = (float) (-((this.arrowSize * Math.sqrt(2.0d)) - this.arrowSize));
        canvas.scale(this.tooltipScaleX, this.tooltipScaleY, getBounds().left + (getBounds().width() * 0.5f), getBounds().top + (getBounds().height() * this.tooltipPivotY));
        canvas.translate(translateX, translateY);
        super.draw(canvas);
        drawText(canvas);
        canvas.restore();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        setShapeAppearanceModel(getShapeAppearanceModel().toBuilder().setBottomEdge(createMarkerEdge()).build());
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable, com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public boolean onStateChange(int[] state) {
        return super.onStateChange(state);
    }

    @Override // com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public void onTextSizeChange() {
        invalidateSelf();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLocationOnScreen(View v) {
        int[] locationOnScreen = new int[2];
        v.getLocationOnScreen(locationOnScreen);
        this.locationOnScreenX = locationOnScreen[0];
        v.getWindowVisibleDisplayFrame(this.displayFrame);
    }

    private float calculatePointerOffset() {
        if (((this.displayFrame.right - getBounds().right) - this.locationOnScreenX) - this.layoutMargin < 0) {
            float pointerOffset = ((this.displayFrame.right - getBounds().right) - this.locationOnScreenX) - this.layoutMargin;
            return pointerOffset;
        } else if (((this.displayFrame.left - getBounds().left) - this.locationOnScreenX) + this.layoutMargin <= 0) {
            return 0.0f;
        } else {
            float pointerOffset2 = ((this.displayFrame.left - getBounds().left) - this.locationOnScreenX) + this.layoutMargin;
            return pointerOffset2;
        }
    }

    private EdgeTreatment createMarkerEdge() {
        float offset = -calculatePointerOffset();
        float maxArrowOffset = ((float) (getBounds().width() - (this.arrowSize * Math.sqrt(2.0d)))) / 2.0f;
        return new OffsetEdgeTreatment(new MarkerEdgeTreatment(this.arrowSize), Math.min(Math.max(offset, -maxArrowOffset), maxArrowOffset));
    }

    private void drawText(Canvas canvas) {
        if (this.text == null) {
            return;
        }
        Rect bounds = getBounds();
        int y = (int) calculateTextOriginAndAlignment(bounds);
        if (this.textDrawableHelper.getTextAppearance() != null) {
            this.textDrawableHelper.getTextPaint().drawableState = getState();
            this.textDrawableHelper.updateTextPaintDrawState(this.context);
            this.textDrawableHelper.getTextPaint().setAlpha((int) (this.labelOpacity * 255.0f));
        }
        CharSequence charSequence = this.text;
        canvas.drawText(charSequence, 0, charSequence.length(), bounds.centerX(), y, this.textDrawableHelper.getTextPaint());
    }

    private float getTextWidth() {
        CharSequence charSequence = this.text;
        if (charSequence == null) {
            return 0.0f;
        }
        return this.textDrawableHelper.getTextWidth(charSequence.toString());
    }

    private float calculateTextOriginAndAlignment(Rect bounds) {
        return bounds.centerY() - calculateTextCenterFromBaseline();
    }

    private float calculateTextCenterFromBaseline() {
        this.textDrawableHelper.getTextPaint().getFontMetrics(this.fontMetrics);
        return (this.fontMetrics.descent + this.fontMetrics.ascent) / 2.0f;
    }
}
