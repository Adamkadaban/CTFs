package com.google.android.material.textfield;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.internal.CheckableImageButton;
import java.util.Arrays;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class IconHelper {
    private IconHelper() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setIconOnClickListener(CheckableImageButton iconView, View.OnClickListener onClickListener, View.OnLongClickListener onLongClickListener) {
        iconView.setOnClickListener(onClickListener);
        setIconClickable(iconView, onLongClickListener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void setIconOnLongClickListener(CheckableImageButton iconView, View.OnLongClickListener onLongClickListener) {
        iconView.setOnLongClickListener(onLongClickListener);
        setIconClickable(iconView, onLongClickListener);
    }

    private static void setIconClickable(CheckableImageButton iconView, View.OnLongClickListener onLongClickListener) {
        boolean iconClickable = ViewCompat.hasOnClickListeners(iconView);
        boolean iconFocusable = false;
        boolean iconLongClickable = onLongClickListener != null;
        iconFocusable = (iconClickable || iconLongClickable) ? true : true;
        iconView.setFocusable(iconFocusable);
        iconView.setClickable(iconClickable);
        iconView.setPressable(iconClickable);
        iconView.setLongClickable(iconLongClickable);
        ViewCompat.setImportantForAccessibility(iconView, iconFocusable ? 1 : 2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void applyIconTint(TextInputLayout textInputLayout, CheckableImageButton iconView, ColorStateList iconTintList, PorterDuff.Mode iconTintMode) {
        Drawable icon = iconView.getDrawable();
        if (icon != null) {
            icon = DrawableCompat.wrap(icon).mutate();
            if (iconTintList != null && iconTintList.isStateful()) {
                int color = iconTintList.getColorForState(mergeIconState(textInputLayout, iconView), iconTintList.getDefaultColor());
                DrawableCompat.setTintList(icon, ColorStateList.valueOf(color));
            } else {
                DrawableCompat.setTintList(icon, iconTintList);
            }
            if (iconTintMode != null) {
                DrawableCompat.setTintMode(icon, iconTintMode);
            }
        }
        if (iconView.getDrawable() != icon) {
            iconView.setImageDrawable(icon);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void refreshIconDrawableState(TextInputLayout textInputLayout, CheckableImageButton iconView, ColorStateList colorStateList) {
        Drawable icon = iconView.getDrawable();
        if (iconView.getDrawable() == null || colorStateList == null || !colorStateList.isStateful()) {
            return;
        }
        int color = colorStateList.getColorForState(mergeIconState(textInputLayout, iconView), colorStateList.getDefaultColor());
        Drawable icon2 = DrawableCompat.wrap(icon).mutate();
        DrawableCompat.setTintList(icon2, ColorStateList.valueOf(color));
        iconView.setImageDrawable(icon2);
    }

    private static int[] mergeIconState(TextInputLayout textInputLayout, CheckableImageButton iconView) {
        int[] textInputStates = textInputLayout.getDrawableState();
        int[] iconStates = iconView.getDrawableState();
        int index = textInputStates.length;
        int[] states = Arrays.copyOf(textInputStates, textInputStates.length + iconStates.length);
        System.arraycopy(iconStates, 0, states, index, iconStates.length);
        return states;
    }
}
