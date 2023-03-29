package com.google.android.material.timepicker;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.RelativeCornerSize;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class RadialViewGroup extends ConstraintLayout {
    private static final String SKIP_TAG = "skip";
    private MaterialShapeDrawable background;
    private int radius;
    private final Runnable updateLayoutParametersRunnable;

    public RadialViewGroup(Context context) {
        this(context, null);
    }

    public RadialViewGroup(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public RadialViewGroup(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        LayoutInflater.from(context).inflate(R.layout.material_radial_view_group, this);
        ViewCompat.setBackground(this, createBackground());
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.RadialViewGroup, defStyleAttr, 0);
        this.radius = a.getDimensionPixelSize(R.styleable.RadialViewGroup_materialCircleRadius, 0);
        this.updateLayoutParametersRunnable = new Runnable() { // from class: com.google.android.material.timepicker.RadialViewGroup.1
            @Override // java.lang.Runnable
            public void run() {
                RadialViewGroup.this.updateLayoutParams();
            }
        };
        a.recycle();
    }

    private Drawable createBackground() {
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable();
        this.background = materialShapeDrawable;
        materialShapeDrawable.setCornerSize(new RelativeCornerSize(0.5f));
        this.background.setFillColor(ColorStateList.valueOf(-1));
        return this.background;
    }

    @Override // android.view.View
    public void setBackgroundColor(int color) {
        this.background.setFillColor(ColorStateList.valueOf(color));
    }

    @Override // android.view.ViewGroup
    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        super.addView(child, index, params);
        if (child.getId() == -1) {
            child.setId(ViewCompat.generateViewId());
        }
        updateLayoutParamsAsync();
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup
    public void onViewRemoved(View view) {
        super.onViewRemoved(view);
        updateLayoutParamsAsync();
    }

    private void updateLayoutParamsAsync() {
        Handler handler = getHandler();
        if (handler != null) {
            handler.removeCallbacks(this.updateLayoutParametersRunnable);
            handler.post(this.updateLayoutParametersRunnable);
        }
    }

    @Override // android.view.View
    protected void onFinishInflate() {
        super.onFinishInflate();
        updateLayoutParams();
    }

    protected void updateLayoutParams() {
        int skippedChildren = 1;
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            if (shouldSkipView(getChildAt(i))) {
                skippedChildren++;
            }
        }
        ConstraintSet constraintSet = new ConstraintSet();
        constraintSet.clone(this);
        float currentAngle = 0.0f;
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = getChildAt(i2);
            if (childAt.getId() != R.id.circle_center && !shouldSkipView(childAt)) {
                constraintSet.constrainCircle(childAt.getId(), R.id.circle_center, this.radius, currentAngle);
                currentAngle += 360.0f / (childCount - skippedChildren);
            }
        }
        constraintSet.applyTo(this);
    }

    public void setRadius(int radius) {
        this.radius = radius;
        updateLayoutParams();
    }

    public int getRadius() {
        return this.radius;
    }

    private static boolean shouldSkipView(View child) {
        return SKIP_TAG.equals(child.getTag());
    }
}
