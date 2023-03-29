package com.google.android.material.dialog;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.database.Cursor;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.TypedValue;
import android.view.View;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.ListAdapter;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.view.ContextThemeWrapper;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.resources.MaterialAttributes;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.theme.overlay.MaterialThemeOverlay;
/* loaded from: classes.dex */
public class MaterialAlertDialogBuilder extends AlertDialog.Builder {
    private static final int DEF_STYLE_ATTR = R.attr.alertDialogStyle;
    private static final int DEF_STYLE_RES = R.style.MaterialAlertDialog_MaterialComponents;
    private static final int MATERIAL_ALERT_DIALOG_THEME_OVERLAY = R.attr.materialAlertDialogTheme;
    private Drawable background;
    private final Rect backgroundInsets;

    private static int getMaterialAlertDialogThemeOverlay(Context context) {
        TypedValue materialAlertDialogThemeOverlay = MaterialAttributes.resolve(context, MATERIAL_ALERT_DIALOG_THEME_OVERLAY);
        if (materialAlertDialogThemeOverlay == null) {
            return 0;
        }
        return materialAlertDialogThemeOverlay.data;
    }

    private static Context createMaterialAlertDialogThemedContext(Context context) {
        int themeOverlayId = getMaterialAlertDialogThemeOverlay(context);
        Context themedContext = MaterialThemeOverlay.wrap(context, null, DEF_STYLE_ATTR, DEF_STYLE_RES);
        if (themeOverlayId == 0) {
            return themedContext;
        }
        return new ContextThemeWrapper(themedContext, themeOverlayId);
    }

    private static int getOverridingThemeResId(Context context, int overrideThemeResId) {
        if (overrideThemeResId == 0) {
            return getMaterialAlertDialogThemeOverlay(context);
        }
        return overrideThemeResId;
    }

    public MaterialAlertDialogBuilder(Context context) {
        this(context, 0);
    }

    public MaterialAlertDialogBuilder(Context context, int overrideThemeResId) {
        super(createMaterialAlertDialogThemedContext(context), getOverridingThemeResId(context, overrideThemeResId));
        Context context2 = getContext();
        Resources.Theme theme = context2.getTheme();
        int i = DEF_STYLE_ATTR;
        int i2 = DEF_STYLE_RES;
        this.backgroundInsets = MaterialDialogs.getDialogBackgroundInsets(context2, i, i2);
        int surfaceColor = MaterialColors.getColor(context2, R.attr.colorSurface, getClass().getCanonicalName());
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable(context2, null, i, i2);
        materialShapeDrawable.initializeElevationOverlay(context2);
        materialShapeDrawable.setFillColor(ColorStateList.valueOf(surfaceColor));
        if (Build.VERSION.SDK_INT >= 28) {
            TypedValue dialogCornerRadiusValue = new TypedValue();
            theme.resolveAttribute(16844145, dialogCornerRadiusValue, true);
            float dialogCornerRadius = dialogCornerRadiusValue.getDimension(getContext().getResources().getDisplayMetrics());
            if (dialogCornerRadiusValue.type == 5 && dialogCornerRadius >= 0.0f) {
                materialShapeDrawable.setCornerSize(dialogCornerRadius);
            }
        }
        this.background = materialShapeDrawable;
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public AlertDialog create() {
        AlertDialog alertDialog = super.create();
        Window window = alertDialog.getWindow();
        View decorView = window.getDecorView();
        Drawable drawable = this.background;
        if (drawable instanceof MaterialShapeDrawable) {
            ((MaterialShapeDrawable) drawable).setElevation(ViewCompat.getElevation(decorView));
        }
        Drawable insetDrawable = MaterialDialogs.insetDrawable(this.background, this.backgroundInsets);
        window.setBackgroundDrawable(insetDrawable);
        decorView.setOnTouchListener(new InsetDialogOnTouchListener(alertDialog, this.backgroundInsets));
        return alertDialog;
    }

    public Drawable getBackground() {
        return this.background;
    }

    public MaterialAlertDialogBuilder setBackground(Drawable background) {
        this.background = background;
        return this;
    }

    public MaterialAlertDialogBuilder setBackgroundInsetStart(int backgroundInsetStart) {
        if (Build.VERSION.SDK_INT >= 17 && getContext().getResources().getConfiguration().getLayoutDirection() == 1) {
            this.backgroundInsets.right = backgroundInsetStart;
        } else {
            this.backgroundInsets.left = backgroundInsetStart;
        }
        return this;
    }

    public MaterialAlertDialogBuilder setBackgroundInsetTop(int backgroundInsetTop) {
        this.backgroundInsets.top = backgroundInsetTop;
        return this;
    }

    public MaterialAlertDialogBuilder setBackgroundInsetEnd(int backgroundInsetEnd) {
        if (Build.VERSION.SDK_INT >= 17 && getContext().getResources().getConfiguration().getLayoutDirection() == 1) {
            this.backgroundInsets.left = backgroundInsetEnd;
        } else {
            this.backgroundInsets.right = backgroundInsetEnd;
        }
        return this;
    }

    public MaterialAlertDialogBuilder setBackgroundInsetBottom(int backgroundInsetBottom) {
        this.backgroundInsets.bottom = backgroundInsetBottom;
        return this;
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setTitle(int titleId) {
        return (MaterialAlertDialogBuilder) super.setTitle(titleId);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setTitle(CharSequence title) {
        return (MaterialAlertDialogBuilder) super.setTitle(title);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setCustomTitle(View customTitleView) {
        return (MaterialAlertDialogBuilder) super.setCustomTitle(customTitleView);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setMessage(int messageId) {
        return (MaterialAlertDialogBuilder) super.setMessage(messageId);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setMessage(CharSequence message) {
        return (MaterialAlertDialogBuilder) super.setMessage(message);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setIcon(int iconId) {
        return (MaterialAlertDialogBuilder) super.setIcon(iconId);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setIcon(Drawable icon) {
        return (MaterialAlertDialogBuilder) super.setIcon(icon);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setIconAttribute(int attrId) {
        return (MaterialAlertDialogBuilder) super.setIconAttribute(attrId);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setPositiveButton(int textId, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setPositiveButton(textId, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setPositiveButton(CharSequence text, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setPositiveButton(text, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setPositiveButtonIcon(Drawable icon) {
        return (MaterialAlertDialogBuilder) super.setPositiveButtonIcon(icon);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNegativeButton(int textId, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setNegativeButton(textId, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNegativeButton(CharSequence text, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setNegativeButton(text, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNegativeButtonIcon(Drawable icon) {
        return (MaterialAlertDialogBuilder) super.setNegativeButtonIcon(icon);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNeutralButton(int textId, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setNeutralButton(textId, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNeutralButton(CharSequence text, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setNeutralButton(text, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setNeutralButtonIcon(Drawable icon) {
        return (MaterialAlertDialogBuilder) super.setNeutralButtonIcon(icon);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setCancelable(boolean cancelable) {
        return (MaterialAlertDialogBuilder) super.setCancelable(cancelable);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setOnCancelListener(DialogInterface.OnCancelListener onCancelListener) {
        return (MaterialAlertDialogBuilder) super.setOnCancelListener(onCancelListener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setOnDismissListener(DialogInterface.OnDismissListener onDismissListener) {
        return (MaterialAlertDialogBuilder) super.setOnDismissListener(onDismissListener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setOnKeyListener(DialogInterface.OnKeyListener onKeyListener) {
        return (MaterialAlertDialogBuilder) super.setOnKeyListener(onKeyListener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setItems(int itemsId, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setItems(itemsId, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setItems(CharSequence[] items, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setItems(items, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setAdapter(ListAdapter adapter, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setAdapter(adapter, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setCursor(Cursor cursor, DialogInterface.OnClickListener listener, String labelColumn) {
        return (MaterialAlertDialogBuilder) super.setCursor(cursor, listener, labelColumn);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setMultiChoiceItems(int itemsId, boolean[] checkedItems, DialogInterface.OnMultiChoiceClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setMultiChoiceItems(itemsId, checkedItems, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setMultiChoiceItems(CharSequence[] items, boolean[] checkedItems, DialogInterface.OnMultiChoiceClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setMultiChoiceItems(items, checkedItems, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setMultiChoiceItems(Cursor cursor, String isCheckedColumn, String labelColumn, DialogInterface.OnMultiChoiceClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setMultiChoiceItems(cursor, isCheckedColumn, labelColumn, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setSingleChoiceItems(int itemsId, int checkedItem, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setSingleChoiceItems(itemsId, checkedItem, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setSingleChoiceItems(Cursor cursor, int checkedItem, String labelColumn, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setSingleChoiceItems(cursor, checkedItem, labelColumn, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setSingleChoiceItems(CharSequence[] items, int checkedItem, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setSingleChoiceItems(items, checkedItem, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setSingleChoiceItems(ListAdapter adapter, int checkedItem, DialogInterface.OnClickListener listener) {
        return (MaterialAlertDialogBuilder) super.setSingleChoiceItems(adapter, checkedItem, listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setOnItemSelectedListener(AdapterView.OnItemSelectedListener listener) {
        return (MaterialAlertDialogBuilder) super.setOnItemSelectedListener(listener);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setView(int layoutResId) {
        return (MaterialAlertDialogBuilder) super.setView(layoutResId);
    }

    @Override // androidx.appcompat.app.AlertDialog.Builder
    public MaterialAlertDialogBuilder setView(View view) {
        return (MaterialAlertDialogBuilder) super.setView(view);
    }
}
