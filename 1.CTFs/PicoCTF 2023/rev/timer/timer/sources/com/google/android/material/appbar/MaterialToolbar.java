package com.google.android.material.appbar;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.internal.ToolbarUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.MaterialShapeUtils;
/* loaded from: classes.dex */
public class MaterialToolbar extends Toolbar {
    private static final int DEF_STYLE_RES = R.style.Widget_MaterialComponents_Toolbar;
    private static final ImageView.ScaleType[] LOGO_SCALE_TYPE_ARRAY = {ImageView.ScaleType.MATRIX, ImageView.ScaleType.FIT_XY, ImageView.ScaleType.FIT_START, ImageView.ScaleType.FIT_CENTER, ImageView.ScaleType.FIT_END, ImageView.ScaleType.CENTER, ImageView.ScaleType.CENTER_CROP, ImageView.ScaleType.CENTER_INSIDE};
    private Boolean logoAdjustViewBounds;
    private ImageView.ScaleType logoScaleType;
    private Integer navigationIconTint;
    private boolean subtitleCentered;
    private boolean titleCentered;

    public MaterialToolbar(Context context) {
        this(context, null);
    }

    public MaterialToolbar(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.toolbarStyle);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public MaterialToolbar(android.content.Context r8, android.util.AttributeSet r9, int r10) {
        /*
            r7 = this;
            int r4 = com.google.android.material.appbar.MaterialToolbar.DEF_STYLE_RES
            android.content.Context r0 = com.google.android.material.theme.overlay.MaterialThemeOverlay.wrap(r8, r9, r10, r4)
            r7.<init>(r0, r9, r10)
            android.content.Context r8 = r7.getContext()
            int[] r2 = com.google.android.material.R.styleable.MaterialToolbar
            r6 = 0
            int[] r5 = new int[r6]
            r0 = r8
            r1 = r9
            r3 = r10
            android.content.res.TypedArray r0 = com.google.android.material.internal.ThemeEnforcement.obtainStyledAttributes(r0, r1, r2, r3, r4, r5)
            int r1 = com.google.android.material.R.styleable.MaterialToolbar_navigationIconTint
            boolean r1 = r0.hasValue(r1)
            r2 = -1
            if (r1 == 0) goto L2b
            int r1 = com.google.android.material.R.styleable.MaterialToolbar_navigationIconTint
            int r1 = r0.getColor(r1, r2)
            r7.setNavigationIconTint(r1)
        L2b:
            int r1 = com.google.android.material.R.styleable.MaterialToolbar_titleCentered
            boolean r1 = r0.getBoolean(r1, r6)
            r7.titleCentered = r1
            int r1 = com.google.android.material.R.styleable.MaterialToolbar_subtitleCentered
            boolean r1 = r0.getBoolean(r1, r6)
            r7.subtitleCentered = r1
            int r1 = com.google.android.material.R.styleable.MaterialToolbar_logoScaleType
            int r1 = r0.getInt(r1, r2)
            if (r1 < 0) goto L4c
            android.widget.ImageView$ScaleType[] r2 = com.google.android.material.appbar.MaterialToolbar.LOGO_SCALE_TYPE_ARRAY
            int r3 = r2.length
            if (r1 >= r3) goto L4c
            r2 = r2[r1]
            r7.logoScaleType = r2
        L4c:
            int r2 = com.google.android.material.R.styleable.MaterialToolbar_logoAdjustViewBounds
            boolean r2 = r0.hasValue(r2)
            if (r2 == 0) goto L60
            int r2 = com.google.android.material.R.styleable.MaterialToolbar_logoAdjustViewBounds
            boolean r2 = r0.getBoolean(r2, r6)
            java.lang.Boolean r2 = java.lang.Boolean.valueOf(r2)
            r7.logoAdjustViewBounds = r2
        L60:
            r0.recycle()
            r7.initBackground(r8)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.appbar.MaterialToolbar.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        maybeCenterTitleViews();
        updateLogoImageView();
    }

    private void maybeCenterTitleViews() {
        if (!this.titleCentered && !this.subtitleCentered) {
            return;
        }
        TextView titleTextView = ToolbarUtils.getTitleTextView(this);
        TextView subtitleTextView = ToolbarUtils.getSubtitleTextView(this);
        if (titleTextView == null && subtitleTextView == null) {
            return;
        }
        Pair<Integer, Integer> titleBoundLimits = calculateTitleBoundLimits(titleTextView, subtitleTextView);
        if (this.titleCentered && titleTextView != null) {
            layoutTitleCenteredHorizontally(titleTextView, titleBoundLimits);
        }
        if (this.subtitleCentered && subtitleTextView != null) {
            layoutTitleCenteredHorizontally(subtitleTextView, titleBoundLimits);
        }
    }

    private Pair<Integer, Integer> calculateTitleBoundLimits(TextView titleTextView, TextView subtitleTextView) {
        int width = getMeasuredWidth();
        int midpoint = width / 2;
        int leftLimit = getPaddingLeft();
        int rightLimit = width - getPaddingRight();
        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8 && child != titleTextView && child != subtitleTextView) {
                if (child.getRight() < midpoint && child.getRight() > leftLimit) {
                    leftLimit = child.getRight();
                }
                if (child.getLeft() > midpoint && child.getLeft() < rightLimit) {
                    rightLimit = child.getLeft();
                }
            }
        }
        return new Pair<>(Integer.valueOf(leftLimit), Integer.valueOf(rightLimit));
    }

    private void layoutTitleCenteredHorizontally(View titleView, Pair<Integer, Integer> titleBoundLimits) {
        int width = getMeasuredWidth();
        int titleWidth = titleView.getMeasuredWidth();
        int titleLeft = (width / 2) - (titleWidth / 2);
        int titleRight = titleLeft + titleWidth;
        int leftOverlap = Math.max(((Integer) titleBoundLimits.first).intValue() - titleLeft, 0);
        int rightOverlap = Math.max(titleRight - ((Integer) titleBoundLimits.second).intValue(), 0);
        int overlap = Math.max(leftOverlap, rightOverlap);
        if (overlap > 0) {
            titleLeft += overlap;
            titleRight -= overlap;
            titleView.measure(View.MeasureSpec.makeMeasureSpec(titleRight - titleLeft, BasicMeasure.EXACTLY), titleView.getMeasuredHeightAndState());
        }
        titleView.layout(titleLeft, titleView.getTop(), titleRight, titleView.getBottom());
    }

    private void updateLogoImageView() {
        ImageView logoImageView = ToolbarUtils.getLogoImageView(this);
        if (logoImageView != null) {
            Boolean bool = this.logoAdjustViewBounds;
            if (bool != null) {
                logoImageView.setAdjustViewBounds(bool.booleanValue());
            }
            ImageView.ScaleType scaleType = this.logoScaleType;
            if (scaleType != null) {
                logoImageView.setScaleType(scaleType);
            }
        }
    }

    public ImageView.ScaleType getLogoScaleType() {
        return this.logoScaleType;
    }

    public void setLogoScaleType(ImageView.ScaleType logoScaleType) {
        if (this.logoScaleType != logoScaleType) {
            this.logoScaleType = logoScaleType;
            requestLayout();
        }
    }

    public boolean isLogoAdjustViewBounds() {
        Boolean bool = this.logoAdjustViewBounds;
        return bool != null && bool.booleanValue();
    }

    public void setLogoAdjustViewBounds(boolean logoAdjustViewBounds) {
        Boolean bool = this.logoAdjustViewBounds;
        if (bool == null || bool.booleanValue() != logoAdjustViewBounds) {
            this.logoAdjustViewBounds = Boolean.valueOf(logoAdjustViewBounds);
            requestLayout();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        MaterialShapeUtils.setParentAbsoluteElevation(this);
    }

    @Override // android.view.View
    public void setElevation(float elevation) {
        super.setElevation(elevation);
        MaterialShapeUtils.setElevation(this, elevation);
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setNavigationIcon(Drawable drawable) {
        super.setNavigationIcon(maybeTintNavigationIcon(drawable));
    }

    public void setNavigationIconTint(int navigationIconTint) {
        this.navigationIconTint = Integer.valueOf(navigationIconTint);
        Drawable navigationIcon = getNavigationIcon();
        if (navigationIcon != null) {
            setNavigationIcon(navigationIcon);
        }
    }

    public Integer getNavigationIconTint() {
        return this.navigationIconTint;
    }

    public void setTitleCentered(boolean titleCentered) {
        if (this.titleCentered != titleCentered) {
            this.titleCentered = titleCentered;
            requestLayout();
        }
    }

    public boolean isTitleCentered() {
        return this.titleCentered;
    }

    public void setSubtitleCentered(boolean subtitleCentered) {
        if (this.subtitleCentered != subtitleCentered) {
            this.subtitleCentered = subtitleCentered;
            requestLayout();
        }
    }

    public boolean isSubtitleCentered() {
        return this.subtitleCentered;
    }

    private void initBackground(Context context) {
        Drawable background = getBackground();
        if (background != null && !(background instanceof ColorDrawable)) {
            return;
        }
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable();
        int backgroundColor = background != null ? ((ColorDrawable) background).getColor() : 0;
        materialShapeDrawable.setFillColor(ColorStateList.valueOf(backgroundColor));
        materialShapeDrawable.initializeElevationOverlay(context);
        materialShapeDrawable.setElevation(ViewCompat.getElevation(this));
        ViewCompat.setBackground(this, materialShapeDrawable);
    }

    private Drawable maybeTintNavigationIcon(Drawable navigationIcon) {
        if (navigationIcon != null && this.navigationIconTint != null) {
            Drawable wrappedNavigationIcon = DrawableCompat.wrap(navigationIcon.mutate());
            DrawableCompat.setTint(wrappedNavigationIcon, this.navigationIconTint.intValue());
            return wrappedNavigationIcon;
        }
        return navigationIcon;
    }
}
