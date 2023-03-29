package com.google.android.material.badge;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import com.google.android.material.R;
import com.google.android.material.badge.BadgeState;
import com.google.android.material.internal.TextDrawableHelper;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.TextAppearance;
import com.google.android.material.shape.MaterialShapeDrawable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.text.NumberFormat;
import java.util.Locale;
/* loaded from: classes.dex */
public class BadgeDrawable extends Drawable implements TextDrawableHelper.TextDrawableDelegate {
    public static final int BOTTOM_END = 8388693;
    public static final int BOTTOM_START = 8388691;
    static final String DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX = "+";
    private static final int DEFAULT_STYLE = R.style.Widget_MaterialComponents_Badge;
    private static final int DEFAULT_THEME_ATTR = R.attr.badgeStyle;
    private static final int MAX_CIRCULAR_BADGE_NUMBER_COUNT = 9;
    public static final int TOP_END = 8388661;
    public static final int TOP_START = 8388659;
    private WeakReference<View> anchorViewRef;
    private final Rect badgeBounds;
    private float badgeCenterX;
    private float badgeCenterY;
    private final WeakReference<Context> contextRef;
    private float cornerRadius;
    private WeakReference<FrameLayout> customBadgeParentRef;
    private float halfBadgeHeight;
    private float halfBadgeWidth;
    private int maxBadgeNumber;
    private final MaterialShapeDrawable shapeDrawable;
    private final BadgeState state;
    private final TextDrawableHelper textDrawableHelper;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface BadgeGravity {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BadgeState.State getSavedState() {
        return this.state.getOverridingState();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static BadgeDrawable createFromSavedState(Context context, BadgeState.State savedState) {
        return new BadgeDrawable(context, 0, DEFAULT_THEME_ATTR, DEFAULT_STYLE, savedState);
    }

    public static BadgeDrawable create(Context context) {
        return new BadgeDrawable(context, 0, DEFAULT_THEME_ATTR, DEFAULT_STYLE, null);
    }

    public static BadgeDrawable createFromResource(Context context, int id) {
        return new BadgeDrawable(context, id, DEFAULT_THEME_ATTR, DEFAULT_STYLE, null);
    }

    public void setVisible(boolean visible) {
        this.state.setVisible(visible);
        onVisibilityUpdated();
    }

    private void onVisibilityUpdated() {
        boolean visible = this.state.isVisible();
        setVisible(visible, false);
        if (BadgeUtils.USE_COMPAT_PARENT && getCustomBadgeParent() != null && !visible) {
            ((ViewGroup) getCustomBadgeParent().getParent()).invalidate();
        }
    }

    private void restoreState() {
        onMaxCharacterCountUpdated();
        onNumberUpdated();
        onAlphaUpdated();
        onBackgroundColorUpdated();
        onBadgeTextColorUpdated();
        onBadgeGravityUpdated();
        updateCenterAndBounds();
        onVisibilityUpdated();
    }

    private BadgeDrawable(Context context, int badgeResId, int defStyleAttr, int defStyleRes, BadgeState.State savedState) {
        this.contextRef = new WeakReference<>(context);
        ThemeEnforcement.checkMaterialTheme(context);
        this.badgeBounds = new Rect();
        this.shapeDrawable = new MaterialShapeDrawable();
        TextDrawableHelper textDrawableHelper = new TextDrawableHelper(this);
        this.textDrawableHelper = textDrawableHelper;
        textDrawableHelper.getTextPaint().setTextAlign(Paint.Align.CENTER);
        setTextAppearanceResource(R.style.TextAppearance_MaterialComponents_Badge);
        this.state = new BadgeState(context, badgeResId, defStyleAttr, defStyleRes, savedState);
        restoreState();
    }

    @Deprecated
    public void updateBadgeCoordinates(View anchorView, ViewGroup customBadgeParent) {
        if (!(customBadgeParent instanceof FrameLayout)) {
            throw new IllegalArgumentException("customBadgeParent must be a FrameLayout");
        }
        updateBadgeCoordinates(anchorView, (FrameLayout) customBadgeParent);
    }

    public void updateBadgeCoordinates(View anchorView) {
        updateBadgeCoordinates(anchorView, (FrameLayout) null);
    }

    public void updateBadgeCoordinates(View anchorView, FrameLayout customBadgeParent) {
        this.anchorViewRef = new WeakReference<>(anchorView);
        if (BadgeUtils.USE_COMPAT_PARENT && customBadgeParent == null) {
            tryWrapAnchorInCompatParent(anchorView);
        } else {
            this.customBadgeParentRef = new WeakReference<>(customBadgeParent);
        }
        if (!BadgeUtils.USE_COMPAT_PARENT) {
            updateAnchorParentToNotClip(anchorView);
        }
        updateCenterAndBounds();
        invalidateSelf();
    }

    public FrameLayout getCustomBadgeParent() {
        WeakReference<FrameLayout> weakReference = this.customBadgeParentRef;
        if (weakReference != null) {
            return weakReference.get();
        }
        return null;
    }

    private void tryWrapAnchorInCompatParent(final View anchorView) {
        ViewGroup anchorViewParent = (ViewGroup) anchorView.getParent();
        if (anchorViewParent == null || anchorViewParent.getId() != R.id.mtrl_anchor_parent) {
            WeakReference<FrameLayout> weakReference = this.customBadgeParentRef;
            if (weakReference != null && weakReference.get() == anchorViewParent) {
                return;
            }
            updateAnchorParentToNotClip(anchorView);
            final FrameLayout frameLayout = new FrameLayout(anchorView.getContext());
            frameLayout.setId(R.id.mtrl_anchor_parent);
            frameLayout.setClipChildren(false);
            frameLayout.setClipToPadding(false);
            frameLayout.setLayoutParams(anchorView.getLayoutParams());
            frameLayout.setMinimumWidth(anchorView.getWidth());
            frameLayout.setMinimumHeight(anchorView.getHeight());
            int anchorIndex = anchorViewParent.indexOfChild(anchorView);
            anchorViewParent.removeViewAt(anchorIndex);
            anchorView.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
            frameLayout.addView(anchorView);
            anchorViewParent.addView(frameLayout, anchorIndex);
            this.customBadgeParentRef = new WeakReference<>(frameLayout);
            frameLayout.post(new Runnable() { // from class: com.google.android.material.badge.BadgeDrawable.1
                @Override // java.lang.Runnable
                public void run() {
                    BadgeDrawable.this.updateBadgeCoordinates(anchorView, frameLayout);
                }
            });
        }
    }

    private static void updateAnchorParentToNotClip(View anchorView) {
        ViewGroup anchorViewParent = (ViewGroup) anchorView.getParent();
        anchorViewParent.setClipChildren(false);
        anchorViewParent.setClipToPadding(false);
    }

    public int getBackgroundColor() {
        return this.shapeDrawable.getFillColor().getDefaultColor();
    }

    public void setBackgroundColor(int backgroundColor) {
        this.state.setBackgroundColor(backgroundColor);
        onBackgroundColorUpdated();
    }

    private void onBackgroundColorUpdated() {
        ColorStateList backgroundColorStateList = ColorStateList.valueOf(this.state.getBackgroundColor());
        if (this.shapeDrawable.getFillColor() != backgroundColorStateList) {
            this.shapeDrawable.setFillColor(backgroundColorStateList);
            invalidateSelf();
        }
    }

    public int getBadgeTextColor() {
        return this.textDrawableHelper.getTextPaint().getColor();
    }

    public void setBadgeTextColor(int badgeTextColor) {
        if (this.textDrawableHelper.getTextPaint().getColor() != badgeTextColor) {
            this.state.setBadgeTextColor(badgeTextColor);
            onBadgeTextColorUpdated();
        }
    }

    private void onBadgeTextColorUpdated() {
        this.textDrawableHelper.getTextPaint().setColor(this.state.getBadgeTextColor());
        invalidateSelf();
    }

    public Locale getBadgeNumberLocale() {
        return this.state.getNumberLocale();
    }

    public void setBadgeNumberLocale(Locale locale) {
        if (!locale.equals(this.state.getNumberLocale())) {
            this.state.setNumberLocale(locale);
            invalidateSelf();
        }
    }

    public boolean hasNumber() {
        return this.state.hasNumber();
    }

    public int getNumber() {
        if (hasNumber()) {
            return this.state.getNumber();
        }
        return 0;
    }

    public void setNumber(int number) {
        int number2 = Math.max(0, number);
        if (this.state.getNumber() != number2) {
            this.state.setNumber(number2);
            onNumberUpdated();
        }
    }

    public void clearNumber() {
        if (hasNumber()) {
            this.state.clearNumber();
            onNumberUpdated();
        }
    }

    private void onNumberUpdated() {
        this.textDrawableHelper.setTextWidthDirty(true);
        updateCenterAndBounds();
        invalidateSelf();
    }

    public int getMaxCharacterCount() {
        return this.state.getMaxCharacterCount();
    }

    public void setMaxCharacterCount(int maxCharacterCount) {
        if (this.state.getMaxCharacterCount() != maxCharacterCount) {
            this.state.setMaxCharacterCount(maxCharacterCount);
            onMaxCharacterCountUpdated();
        }
    }

    private void onMaxCharacterCountUpdated() {
        updateMaxBadgeNumber();
        this.textDrawableHelper.setTextWidthDirty(true);
        updateCenterAndBounds();
        invalidateSelf();
    }

    public int getBadgeGravity() {
        return this.state.getBadgeGravity();
    }

    public void setBadgeGravity(int gravity) {
        if (this.state.getBadgeGravity() != gravity) {
            this.state.setBadgeGravity(gravity);
            onBadgeGravityUpdated();
        }
    }

    private void onBadgeGravityUpdated() {
        WeakReference<View> weakReference = this.anchorViewRef;
        if (weakReference != null && weakReference.get() != null) {
            View view = this.anchorViewRef.get();
            WeakReference<FrameLayout> weakReference2 = this.customBadgeParentRef;
            updateBadgeCoordinates(view, weakReference2 != null ? weakReference2.get() : null);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isStateful() {
        return false;
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.state.getAlpha();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.state.setAlpha(alpha);
        onAlphaUpdated();
    }

    private void onAlphaUpdated() {
        this.textDrawableHelper.getTextPaint().setAlpha(getAlpha());
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return this.badgeBounds.height();
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return this.badgeBounds.width();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        if (bounds.isEmpty() || getAlpha() == 0 || !isVisible()) {
            return;
        }
        this.shapeDrawable.draw(canvas);
        if (hasNumber()) {
            drawText(canvas);
        }
    }

    @Override // com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public void onTextSizeChange() {
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable, com.google.android.material.internal.TextDrawableHelper.TextDrawableDelegate
    public boolean onStateChange(int[] state) {
        return super.onStateChange(state);
    }

    public void setContentDescriptionNumberless(CharSequence charSequence) {
        this.state.setContentDescriptionNumberless(charSequence);
    }

    public void setContentDescriptionQuantityStringsResource(int stringsResource) {
        this.state.setContentDescriptionQuantityStringsResource(stringsResource);
    }

    public void setContentDescriptionExceedsMaxBadgeNumberStringResource(int stringsResource) {
        this.state.setContentDescriptionExceedsMaxBadgeNumberStringResource(stringsResource);
    }

    public CharSequence getContentDescription() {
        Context context;
        if (isVisible()) {
            if (hasNumber()) {
                if (this.state.getContentDescriptionQuantityStrings() == 0 || (context = this.contextRef.get()) == null) {
                    return null;
                }
                if (getNumber() <= this.maxBadgeNumber) {
                    return context.getResources().getQuantityString(this.state.getContentDescriptionQuantityStrings(), getNumber(), Integer.valueOf(getNumber()));
                }
                return context.getString(this.state.getContentDescriptionExceedsMaxBadgeNumberStringResource(), Integer.valueOf(this.maxBadgeNumber));
            }
            return this.state.getContentDescriptionNumberless();
        }
        return null;
    }

    public void setHorizontalOffset(int px) {
        setHorizontalOffsetWithoutText(px);
        setHorizontalOffsetWithText(px);
    }

    public int getHorizontalOffset() {
        return this.state.getHorizontalOffsetWithoutText();
    }

    public void setHorizontalOffsetWithoutText(int px) {
        this.state.setHorizontalOffsetWithoutText(px);
        updateCenterAndBounds();
    }

    public int getHorizontalOffsetWithoutText() {
        return this.state.getHorizontalOffsetWithoutText();
    }

    public void setHorizontalOffsetWithText(int px) {
        this.state.setHorizontalOffsetWithText(px);
        updateCenterAndBounds();
    }

    public int getHorizontalOffsetWithText() {
        return this.state.getHorizontalOffsetWithText();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAdditionalHorizontalOffset(int px) {
        this.state.setAdditionalHorizontalOffset(px);
        updateCenterAndBounds();
    }

    int getAdditionalHorizontalOffset() {
        return this.state.getAdditionalHorizontalOffset();
    }

    public void setVerticalOffset(int px) {
        setVerticalOffsetWithoutText(px);
        setVerticalOffsetWithText(px);
    }

    public int getVerticalOffset() {
        return this.state.getVerticalOffsetWithoutText();
    }

    public void setVerticalOffsetWithoutText(int px) {
        this.state.setVerticalOffsetWithoutText(px);
        updateCenterAndBounds();
    }

    public int getVerticalOffsetWithoutText() {
        return this.state.getVerticalOffsetWithoutText();
    }

    public void setVerticalOffsetWithText(int px) {
        this.state.setVerticalOffsetWithText(px);
        updateCenterAndBounds();
    }

    public int getVerticalOffsetWithText() {
        return this.state.getVerticalOffsetWithText();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setAdditionalVerticalOffset(int px) {
        this.state.setAdditionalVerticalOffset(px);
        updateCenterAndBounds();
    }

    int getAdditionalVerticalOffset() {
        return this.state.getAdditionalVerticalOffset();
    }

    private void setTextAppearanceResource(int id) {
        Context context = this.contextRef.get();
        if (context == null) {
            return;
        }
        setTextAppearance(new TextAppearance(context, id));
    }

    private void setTextAppearance(TextAppearance textAppearance) {
        Context context;
        if (this.textDrawableHelper.getTextAppearance() == textAppearance || (context = this.contextRef.get()) == null) {
            return;
        }
        this.textDrawableHelper.setTextAppearance(textAppearance, context);
        updateCenterAndBounds();
    }

    private void updateCenterAndBounds() {
        Context context = this.contextRef.get();
        WeakReference<View> weakReference = this.anchorViewRef;
        View anchorView = weakReference != null ? weakReference.get() : null;
        if (context == null || anchorView == null) {
            return;
        }
        Rect tmpRect = new Rect();
        tmpRect.set(this.badgeBounds);
        Rect anchorRect = new Rect();
        anchorView.getDrawingRect(anchorRect);
        WeakReference<FrameLayout> weakReference2 = this.customBadgeParentRef;
        ViewGroup customBadgeParent = weakReference2 != null ? (FrameLayout) weakReference2.get() : null;
        if (customBadgeParent != null || BadgeUtils.USE_COMPAT_PARENT) {
            ViewGroup viewGroup = customBadgeParent == null ? (ViewGroup) anchorView.getParent() : customBadgeParent;
            viewGroup.offsetDescendantRectToMyCoords(anchorView, anchorRect);
        }
        calculateCenterAndBounds(context, anchorRect, anchorView);
        BadgeUtils.updateBadgeBounds(this.badgeBounds, this.badgeCenterX, this.badgeCenterY, this.halfBadgeWidth, this.halfBadgeHeight);
        this.shapeDrawable.setCornerSize(this.cornerRadius);
        if (!tmpRect.equals(this.badgeBounds)) {
            this.shapeDrawable.setBounds(this.badgeBounds);
        }
    }

    private int getTotalVerticalOffsetForState() {
        int vOffset = hasNumber() ? this.state.getVerticalOffsetWithText() : this.state.getVerticalOffsetWithoutText();
        return this.state.getAdditionalVerticalOffset() + vOffset;
    }

    private int getTotalHorizontalOffsetForState() {
        int hOffset = hasNumber() ? this.state.getHorizontalOffsetWithText() : this.state.getHorizontalOffsetWithoutText();
        return this.state.getAdditionalHorizontalOffset() + hOffset;
    }

    private void calculateCenterAndBounds(Context context, Rect anchorRect, View anchorView) {
        int i;
        float f;
        float f2;
        int totalVerticalOffset = getTotalVerticalOffsetForState();
        switch (this.state.getBadgeGravity()) {
            case 8388691:
            case 8388693:
                this.badgeCenterY = anchorRect.bottom - totalVerticalOffset;
                break;
            case 8388692:
            default:
                this.badgeCenterY = anchorRect.top + totalVerticalOffset;
                break;
        }
        if (getNumber() <= 9) {
            float f3 = !hasNumber() ? this.state.badgeRadius : this.state.badgeWithTextRadius;
            this.cornerRadius = f3;
            this.halfBadgeHeight = f3;
            this.halfBadgeWidth = f3;
        } else {
            float f4 = this.state.badgeWithTextRadius;
            this.cornerRadius = f4;
            this.halfBadgeHeight = f4;
            String badgeText = getBadgeText();
            this.halfBadgeWidth = (this.textDrawableHelper.getTextWidth(badgeText) / 2.0f) + this.state.badgeWidePadding;
        }
        Resources resources = context.getResources();
        if (hasNumber()) {
            i = R.dimen.mtrl_badge_text_horizontal_edge_offset;
        } else {
            i = R.dimen.mtrl_badge_horizontal_edge_offset;
        }
        int inset = resources.getDimensionPixelSize(i);
        int totalHorizontalOffset = getTotalHorizontalOffsetForState();
        switch (this.state.getBadgeGravity()) {
            case 8388659:
            case 8388691:
                if (ViewCompat.getLayoutDirection(anchorView) == 0) {
                    f = (anchorRect.left - this.halfBadgeWidth) + inset + totalHorizontalOffset;
                } else {
                    f = ((anchorRect.right + this.halfBadgeWidth) - inset) - totalHorizontalOffset;
                }
                this.badgeCenterX = f;
                return;
            default:
                if (ViewCompat.getLayoutDirection(anchorView) == 0) {
                    f2 = ((anchorRect.right + this.halfBadgeWidth) - inset) - totalHorizontalOffset;
                } else {
                    f2 = (anchorRect.left - this.halfBadgeWidth) + inset + totalHorizontalOffset;
                }
                this.badgeCenterX = f2;
                return;
        }
    }

    private void drawText(Canvas canvas) {
        Rect textBounds = new Rect();
        String badgeText = getBadgeText();
        this.textDrawableHelper.getTextPaint().getTextBounds(badgeText, 0, badgeText.length(), textBounds);
        canvas.drawText(badgeText, this.badgeCenterX, this.badgeCenterY + (textBounds.height() / 2), this.textDrawableHelper.getTextPaint());
    }

    private String getBadgeText() {
        if (getNumber() <= this.maxBadgeNumber) {
            return NumberFormat.getInstance(this.state.getNumberLocale()).format(getNumber());
        }
        Context context = this.contextRef.get();
        if (context == null) {
            return "";
        }
        return String.format(this.state.getNumberLocale(), context.getString(R.string.mtrl_exceed_max_badge_number_suffix), Integer.valueOf(this.maxBadgeNumber), DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX);
    }

    private void updateMaxBadgeNumber() {
        this.maxBadgeNumber = ((int) Math.pow(10.0d, getMaxCharacterCount() - 1.0d)) - 1;
    }
}
