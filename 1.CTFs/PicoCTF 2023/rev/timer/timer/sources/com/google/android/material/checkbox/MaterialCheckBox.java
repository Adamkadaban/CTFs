package com.google.android.material.checkbox;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.widget.CompoundButtonCompat;
import com.google.android.material.R;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.internal.ViewUtils;
/* loaded from: classes.dex */
public class MaterialCheckBox extends AppCompatCheckBox {
    private static final int DEF_STYLE_RES = R.style.Widget_MaterialComponents_CompoundButton_CheckBox;
    private static final int[][] ENABLED_CHECKED_STATES = {new int[]{16842910, 16842912}, new int[]{16842910, -16842912}, new int[]{-16842910, 16842912}, new int[]{-16842910, -16842912}};
    private boolean centerIfNoTextEnabled;
    private ColorStateList materialThemeColorsTintList;
    private boolean useMaterialThemeColors;

    public MaterialCheckBox(Context context) {
        this(context, null);
    }

    public MaterialCheckBox(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.checkboxStyle);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public MaterialCheckBox(android.content.Context r8, android.util.AttributeSet r9, int r10) {
        /*
            r7 = this;
            int r4 = com.google.android.material.checkbox.MaterialCheckBox.DEF_STYLE_RES
            android.content.Context r0 = com.google.android.material.theme.overlay.MaterialThemeOverlay.wrap(r8, r9, r10, r4)
            r7.<init>(r0, r9, r10)
            android.content.Context r8 = r7.getContext()
            int[] r2 = com.google.android.material.R.styleable.MaterialCheckBox
            r6 = 0
            int[] r5 = new int[r6]
            r0 = r8
            r1 = r9
            r3 = r10
            android.content.res.TypedArray r0 = com.google.android.material.internal.ThemeEnforcement.obtainStyledAttributes(r0, r1, r2, r3, r4, r5)
            int r1 = com.google.android.material.R.styleable.MaterialCheckBox_buttonTint
            boolean r1 = r0.hasValue(r1)
            if (r1 == 0) goto L2a
            int r1 = com.google.android.material.R.styleable.MaterialCheckBox_buttonTint
            android.content.res.ColorStateList r1 = com.google.android.material.resources.MaterialResources.getColorStateList(r8, r0, r1)
            androidx.core.widget.CompoundButtonCompat.setButtonTintList(r7, r1)
        L2a:
            int r1 = com.google.android.material.R.styleable.MaterialCheckBox_useMaterialThemeColors
            boolean r1 = r0.getBoolean(r1, r6)
            r7.useMaterialThemeColors = r1
            int r1 = com.google.android.material.R.styleable.MaterialCheckBox_centerIfNoTextEnabled
            r2 = 1
            boolean r1 = r0.getBoolean(r1, r2)
            r7.centerIfNoTextEnabled = r1
            r0.recycle()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.checkbox.MaterialCheckBox.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        Drawable drawable;
        if (this.centerIfNoTextEnabled && TextUtils.isEmpty(getText()) && (drawable = CompoundButtonCompat.getButtonDrawable(this)) != null) {
            int direction = ViewUtils.isLayoutRtl(this) ? -1 : 1;
            int dx = ((getWidth() - drawable.getIntrinsicWidth()) / 2) * direction;
            int saveCount = canvas.save();
            canvas.translate(dx, 0.0f);
            super.onDraw(canvas);
            canvas.restoreToCount(saveCount);
            if (getBackground() != null) {
                Rect bounds = drawable.getBounds();
                DrawableCompat.setHotspotBounds(getBackground(), bounds.left + dx, bounds.top, bounds.right + dx, bounds.bottom);
                return;
            }
            return;
        }
        super.onDraw(canvas);
    }

    @Override // android.widget.TextView, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.useMaterialThemeColors && CompoundButtonCompat.getButtonTintList(this) == null) {
            setUseMaterialThemeColors(true);
        }
    }

    public void setUseMaterialThemeColors(boolean useMaterialThemeColors) {
        this.useMaterialThemeColors = useMaterialThemeColors;
        if (useMaterialThemeColors) {
            CompoundButtonCompat.setButtonTintList(this, getMaterialThemeColorsTintList());
        } else {
            CompoundButtonCompat.setButtonTintList(this, null);
        }
    }

    public boolean isUseMaterialThemeColors() {
        return this.useMaterialThemeColors;
    }

    public void setCenterIfNoTextEnabled(boolean centerIfNoTextEnabled) {
        this.centerIfNoTextEnabled = centerIfNoTextEnabled;
    }

    public boolean isCenterIfNoTextEnabled() {
        return this.centerIfNoTextEnabled;
    }

    private ColorStateList getMaterialThemeColorsTintList() {
        if (this.materialThemeColorsTintList == null) {
            int[][] iArr = ENABLED_CHECKED_STATES;
            int[] checkBoxColorsList = new int[iArr.length];
            int colorControlActivated = MaterialColors.getColor(this, R.attr.colorControlActivated);
            int colorSurface = MaterialColors.getColor(this, R.attr.colorSurface);
            int colorOnSurface = MaterialColors.getColor(this, R.attr.colorOnSurface);
            checkBoxColorsList[0] = MaterialColors.layer(colorSurface, colorControlActivated, 1.0f);
            checkBoxColorsList[1] = MaterialColors.layer(colorSurface, colorOnSurface, 0.54f);
            checkBoxColorsList[2] = MaterialColors.layer(colorSurface, colorOnSurface, 0.38f);
            checkBoxColorsList[3] = MaterialColors.layer(colorSurface, colorOnSurface, 0.38f);
            this.materialThemeColorsTintList = new ColorStateList(iArr, checkBoxColorsList);
        }
        return this.materialThemeColorsTintList;
    }
}
