package com.google.android.material.datepicker;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.widget.TextView;
import androidx.core.util.Preconditions;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
/* loaded from: classes.dex */
final class CalendarItemStyle {
    private final ColorStateList backgroundColor;
    private final Rect insets;
    private final ShapeAppearanceModel itemShape;
    private final ColorStateList strokeColor;
    private final int strokeWidth;
    private final ColorStateList textColor;

    private CalendarItemStyle(ColorStateList backgroundColor, ColorStateList textColor, ColorStateList strokeColor, int strokeWidth, ShapeAppearanceModel itemShape, Rect insets) {
        Preconditions.checkArgumentNonnegative(insets.left);
        Preconditions.checkArgumentNonnegative(insets.top);
        Preconditions.checkArgumentNonnegative(insets.right);
        Preconditions.checkArgumentNonnegative(insets.bottom);
        this.insets = insets;
        this.textColor = textColor;
        this.backgroundColor = backgroundColor;
        this.strokeColor = strokeColor;
        this.strokeWidth = strokeWidth;
        this.itemShape = itemShape;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CalendarItemStyle create(Context context, int materialCalendarItemStyle) {
        Preconditions.checkArgument(materialCalendarItemStyle != 0, "Cannot create a CalendarItemStyle with a styleResId of 0");
        TypedArray styleableArray = context.obtainStyledAttributes(materialCalendarItemStyle, R.styleable.MaterialCalendarItem);
        int insetLeft = styleableArray.getDimensionPixelOffset(R.styleable.MaterialCalendarItem_android_insetLeft, 0);
        int insetTop = styleableArray.getDimensionPixelOffset(R.styleable.MaterialCalendarItem_android_insetTop, 0);
        int insetRight = styleableArray.getDimensionPixelOffset(R.styleable.MaterialCalendarItem_android_insetRight, 0);
        int insetBottom = styleableArray.getDimensionPixelOffset(R.styleable.MaterialCalendarItem_android_insetBottom, 0);
        Rect insets = new Rect(insetLeft, insetTop, insetRight, insetBottom);
        ColorStateList backgroundColor = MaterialResources.getColorStateList(context, styleableArray, R.styleable.MaterialCalendarItem_itemFillColor);
        ColorStateList textColor = MaterialResources.getColorStateList(context, styleableArray, R.styleable.MaterialCalendarItem_itemTextColor);
        ColorStateList strokeColor = MaterialResources.getColorStateList(context, styleableArray, R.styleable.MaterialCalendarItem_itemStrokeColor);
        int strokeWidth = styleableArray.getDimensionPixelSize(R.styleable.MaterialCalendarItem_itemStrokeWidth, 0);
        int shapeAppearanceResId = styleableArray.getResourceId(R.styleable.MaterialCalendarItem_itemShapeAppearance, 0);
        int shapeAppearanceOverlayResId = styleableArray.getResourceId(R.styleable.MaterialCalendarItem_itemShapeAppearanceOverlay, 0);
        ShapeAppearanceModel itemShape = ShapeAppearanceModel.builder(context, shapeAppearanceResId, shapeAppearanceOverlayResId).build();
        styleableArray.recycle();
        return new CalendarItemStyle(backgroundColor, textColor, strokeColor, strokeWidth, itemShape, insets);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void styleItem(TextView item) {
        Drawable d;
        MaterialShapeDrawable backgroundDrawable = new MaterialShapeDrawable();
        MaterialShapeDrawable shapeMask = new MaterialShapeDrawable();
        backgroundDrawable.setShapeAppearanceModel(this.itemShape);
        shapeMask.setShapeAppearanceModel(this.itemShape);
        backgroundDrawable.setFillColor(this.backgroundColor);
        backgroundDrawable.setStroke(this.strokeWidth, this.strokeColor);
        item.setTextColor(this.textColor);
        if (Build.VERSION.SDK_INT >= 21) {
            d = new RippleDrawable(this.textColor.withAlpha(30), backgroundDrawable, shapeMask);
        } else {
            d = backgroundDrawable;
        }
        ViewCompat.setBackground(item, new InsetDrawable(d, this.insets.left, this.insets.top, this.insets.right, this.insets.bottom));
    }

    int getLeftInset() {
        return this.insets.left;
    }

    int getRightInset() {
        return this.insets.right;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getTopInset() {
        return this.insets.top;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getBottomInset() {
        return this.insets.bottom;
    }
}
