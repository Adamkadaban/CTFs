package com.google.android.material.divider;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.ShapeDrawable;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.R;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.MaterialResources;
/* loaded from: classes.dex */
public class MaterialDividerItemDecoration extends RecyclerView.ItemDecoration {
    private static final int DEF_STYLE_RES = R.style.Widget_MaterialComponents_MaterialDivider;
    public static final int HORIZONTAL = 0;
    public static final int VERTICAL = 1;
    private int color;
    private Drawable dividerDrawable;
    private int insetEnd;
    private int insetStart;
    private boolean lastItemDecorated;
    private int orientation;
    private final Rect tempRect;
    private int thickness;

    public MaterialDividerItemDecoration(Context context, int orientation) {
        this(context, null, orientation);
    }

    public MaterialDividerItemDecoration(Context context, AttributeSet attrs, int orientation) {
        this(context, attrs, R.attr.materialDividerStyle, orientation);
    }

    public MaterialDividerItemDecoration(Context context, AttributeSet attrs, int defStyleAttr, int orientation) {
        this.tempRect = new Rect();
        TypedArray attributes = ThemeEnforcement.obtainStyledAttributes(context, attrs, R.styleable.MaterialDivider, defStyleAttr, DEF_STYLE_RES, new int[0]);
        this.color = MaterialResources.getColorStateList(context, attributes, R.styleable.MaterialDivider_dividerColor).getDefaultColor();
        this.thickness = attributes.getDimensionPixelSize(R.styleable.MaterialDivider_dividerThickness, context.getResources().getDimensionPixelSize(R.dimen.material_divider_thickness));
        this.insetStart = attributes.getDimensionPixelOffset(R.styleable.MaterialDivider_dividerInsetStart, 0);
        this.insetEnd = attributes.getDimensionPixelOffset(R.styleable.MaterialDivider_dividerInsetEnd, 0);
        this.lastItemDecorated = attributes.getBoolean(R.styleable.MaterialDivider_lastItemDecorated, true);
        attributes.recycle();
        this.dividerDrawable = new ShapeDrawable();
        setDividerColor(this.color);
        setOrientation(orientation);
    }

    public void setOrientation(int orientation) {
        if (orientation != 0 && orientation != 1) {
            throw new IllegalArgumentException("Invalid orientation: " + orientation + ". It should be either HORIZONTAL or VERTICAL");
        }
        this.orientation = orientation;
    }

    public int getOrientation() {
        return this.orientation;
    }

    public void setDividerThickness(int thickness) {
        this.thickness = thickness;
    }

    public void setDividerThicknessResource(Context context, int thicknessId) {
        setDividerThickness(context.getResources().getDimensionPixelSize(thicknessId));
    }

    public int getDividerThickness() {
        return this.thickness;
    }

    public void setDividerColor(int color) {
        this.color = color;
        Drawable wrap = DrawableCompat.wrap(this.dividerDrawable);
        this.dividerDrawable = wrap;
        DrawableCompat.setTint(wrap, color);
    }

    public void setDividerColorResource(Context context, int colorId) {
        setDividerColor(ContextCompat.getColor(context, colorId));
    }

    public int getDividerColor() {
        return this.color;
    }

    public void setDividerInsetStart(int insetStart) {
        this.insetStart = insetStart;
    }

    public void setDividerInsetStartResource(Context context, int insetStartId) {
        setDividerInsetStart(context.getResources().getDimensionPixelOffset(insetStartId));
    }

    public int getDividerInsetStart() {
        return this.insetStart;
    }

    public void setDividerInsetEnd(int insetEnd) {
        this.insetEnd = insetEnd;
    }

    public void setDividerInsetEndResource(Context context, int insetEndId) {
        setDividerInsetEnd(context.getResources().getDimensionPixelOffset(insetEndId));
    }

    public int getDividerInsetEnd() {
        return this.insetEnd;
    }

    public void setLastItemDecorated(boolean lastItemDecorated) {
        this.lastItemDecorated = lastItemDecorated;
    }

    public boolean isLastItemDecorated() {
        return this.lastItemDecorated;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(Canvas canvas, RecyclerView parent, RecyclerView.State state) {
        if (parent.getLayoutManager() == null) {
            return;
        }
        if (this.orientation == 1) {
            drawForVerticalOrientation(canvas, parent);
        } else {
            drawForHorizontalOrientation(canvas, parent);
        }
    }

    private void drawForVerticalOrientation(Canvas canvas, RecyclerView parent) {
        int left;
        int right;
        canvas.save();
        if (parent.getClipToPadding()) {
            left = parent.getPaddingLeft();
            right = parent.getWidth() - parent.getPaddingRight();
            canvas.clipRect(left, parent.getPaddingTop(), right, parent.getHeight() - parent.getPaddingBottom());
        } else {
            left = 0;
            right = parent.getWidth();
        }
        boolean isRtl = ViewCompat.getLayoutDirection(parent) == 1;
        int left2 = left + (isRtl ? this.insetEnd : this.insetStart);
        int right2 = right - (isRtl ? this.insetStart : this.insetEnd);
        int childCount = parent.getChildCount();
        int dividerCount = this.lastItemDecorated ? childCount : childCount - 1;
        for (int i = 0; i < dividerCount; i++) {
            View child = parent.getChildAt(i);
            parent.getDecoratedBoundsWithMargins(child, this.tempRect);
            int bottom = this.tempRect.bottom + Math.round(child.getTranslationY());
            int top = (bottom - this.dividerDrawable.getIntrinsicHeight()) - this.thickness;
            this.dividerDrawable.setBounds(left2, top, right2, bottom);
            this.dividerDrawable.draw(canvas);
        }
        canvas.restore();
    }

    private void drawForHorizontalOrientation(Canvas canvas, RecyclerView parent) {
        int top;
        int bottom;
        canvas.save();
        if (parent.getClipToPadding()) {
            top = parent.getPaddingTop();
            bottom = parent.getHeight() - parent.getPaddingBottom();
            canvas.clipRect(parent.getPaddingLeft(), top, parent.getWidth() - parent.getPaddingRight(), bottom);
        } else {
            top = 0;
            bottom = parent.getHeight();
        }
        int top2 = top + this.insetStart;
        int bottom2 = bottom - this.insetEnd;
        int childCount = parent.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            parent.getLayoutManager().getDecoratedBoundsWithMargins(child, this.tempRect);
            int right = this.tempRect.right + Math.round(child.getTranslationX());
            int left = (right - this.dividerDrawable.getIntrinsicWidth()) - this.thickness;
            this.dividerDrawable.setBounds(left, top2, right, bottom2);
            this.dividerDrawable.draw(canvas);
        }
        canvas.restore();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
        outRect.set(0, 0, 0, 0);
        if (this.orientation == 1) {
            outRect.bottom = this.dividerDrawable.getIntrinsicHeight() + this.thickness;
        } else {
            outRect.right = this.dividerDrawable.getIntrinsicWidth() + this.thickness;
        }
    }
}
