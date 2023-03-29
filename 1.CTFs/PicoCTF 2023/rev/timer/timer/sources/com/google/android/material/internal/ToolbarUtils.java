package com.google.android.material.internal;

import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.view.menu.ActionMenuItemView;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
/* loaded from: classes.dex */
public class ToolbarUtils {
    private static final Comparator<View> VIEW_TOP_COMPARATOR = new Comparator<View>() { // from class: com.google.android.material.internal.ToolbarUtils.1
        @Override // java.util.Comparator
        public int compare(View view1, View view2) {
            return view1.getTop() - view2.getTop();
        }
    };

    private ToolbarUtils() {
    }

    public static TextView getTitleTextView(Toolbar toolbar) {
        List<TextView> textViews = getTextViewsWithText(toolbar, toolbar.getTitle());
        if (textViews.isEmpty()) {
            return null;
        }
        return (TextView) Collections.min(textViews, VIEW_TOP_COMPARATOR);
    }

    public static TextView getSubtitleTextView(Toolbar toolbar) {
        List<TextView> textViews = getTextViewsWithText(toolbar, toolbar.getSubtitle());
        if (textViews.isEmpty()) {
            return null;
        }
        return (TextView) Collections.max(textViews, VIEW_TOP_COMPARATOR);
    }

    private static List<TextView> getTextViewsWithText(Toolbar toolbar, CharSequence text) {
        List<TextView> textViews = new ArrayList<>();
        for (int i = 0; i < toolbar.getChildCount(); i++) {
            View child = toolbar.getChildAt(i);
            if (child instanceof TextView) {
                TextView textView = (TextView) child;
                if (TextUtils.equals(textView.getText(), text)) {
                    textViews.add(textView);
                }
            }
        }
        return textViews;
    }

    public static ImageView getLogoImageView(Toolbar toolbar) {
        return getImageView(toolbar, toolbar.getLogo());
    }

    private static ImageView getImageView(Toolbar toolbar, Drawable content) {
        ImageView imageView;
        Drawable drawable;
        if (content == null) {
            return null;
        }
        for (int i = 0; i < toolbar.getChildCount(); i++) {
            View child = toolbar.getChildAt(i);
            if ((child instanceof ImageView) && (drawable = (imageView = (ImageView) child).getDrawable()) != null && drawable.getConstantState() != null && drawable.getConstantState().equals(content.getConstantState())) {
                return imageView;
            }
        }
        return null;
    }

    public static View getSecondaryActionMenuItemView(Toolbar toolbar) {
        ActionMenuView actionMenuView = getActionMenuView(toolbar);
        if (actionMenuView != null && actionMenuView.getChildCount() > 1) {
            return actionMenuView.getChildAt(0);
        }
        return null;
    }

    public static ActionMenuView getActionMenuView(Toolbar toolbar) {
        for (int i = 0; i < toolbar.getChildCount(); i++) {
            View child = toolbar.getChildAt(i);
            if (child instanceof ActionMenuView) {
                return (ActionMenuView) child;
            }
        }
        return null;
    }

    public static ImageButton getNavigationIconButton(Toolbar toolbar) {
        Drawable navigationIcon = toolbar.getNavigationIcon();
        if (navigationIcon == null) {
            return null;
        }
        for (int i = 0; i < toolbar.getChildCount(); i++) {
            View child = toolbar.getChildAt(i);
            if (child instanceof ImageButton) {
                ImageButton imageButton = (ImageButton) child;
                if (imageButton.getDrawable() == navigationIcon) {
                    return imageButton;
                }
            }
        }
        return null;
    }

    public static ActionMenuItemView getActionMenuItemView(Toolbar toolbar, int menuItemId) {
        ActionMenuView actionMenuView = getActionMenuView(toolbar);
        if (actionMenuView != null) {
            for (int i = 0; i < actionMenuView.getChildCount(); i++) {
                View child = actionMenuView.getChildAt(i);
                if (child instanceof ActionMenuItemView) {
                    ActionMenuItemView actionMenuItemView = (ActionMenuItemView) child;
                    if (actionMenuItemView.getItemData().getItemId() == menuItemId) {
                        return actionMenuItemView;
                    }
                }
            }
            return null;
        }
        return null;
    }
}
