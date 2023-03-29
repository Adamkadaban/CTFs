package com.google.android.material.navigation;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.FrameLayout;
import androidx.appcompat.view.SupportMenuInflater;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuView;
import androidx.appcompat.widget.TintTypedArray;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import androidx.customview.view.AbsSavedState;
import com.google.android.material.R;
import com.google.android.material.badge.BadgeDrawable;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.ripple.RippleUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.MaterialShapeUtils;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.theme.overlay.MaterialThemeOverlay;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
/* loaded from: classes.dex */
public abstract class NavigationBarView extends FrameLayout {
    public static final int LABEL_VISIBILITY_AUTO = -1;
    public static final int LABEL_VISIBILITY_LABELED = 1;
    public static final int LABEL_VISIBILITY_SELECTED = 0;
    public static final int LABEL_VISIBILITY_UNLABELED = 2;
    private static final int MENU_PRESENTER_ID = 1;
    private ColorStateList itemRippleColor;
    private final NavigationBarMenu menu;
    private MenuInflater menuInflater;
    private final NavigationBarMenuView menuView;
    private final NavigationBarPresenter presenter;
    private OnItemReselectedListener reselectedListener;
    private OnItemSelectedListener selectedListener;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface LabelVisibility {
    }

    /* loaded from: classes.dex */
    public interface OnItemReselectedListener {
        void onNavigationItemReselected(MenuItem menuItem);
    }

    /* loaded from: classes.dex */
    public interface OnItemSelectedListener {
        boolean onNavigationItemSelected(MenuItem menuItem);
    }

    protected abstract NavigationBarMenuView createNavigationBarMenuView(Context context);

    public abstract int getMaxItemCount();

    public NavigationBarView(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(MaterialThemeOverlay.wrap(context, attrs, defStyleAttr, defStyleRes), attrs, defStyleAttr);
        NavigationBarPresenter navigationBarPresenter = new NavigationBarPresenter();
        this.presenter = navigationBarPresenter;
        Context context2 = getContext();
        TintTypedArray attributes = ThemeEnforcement.obtainTintedStyledAttributes(context2, attrs, R.styleable.NavigationBarView, defStyleAttr, defStyleRes, R.styleable.NavigationBarView_itemTextAppearanceInactive, R.styleable.NavigationBarView_itemTextAppearanceActive);
        NavigationBarMenu navigationBarMenu = new NavigationBarMenu(context2, getClass(), getMaxItemCount());
        this.menu = navigationBarMenu;
        NavigationBarMenuView createNavigationBarMenuView = createNavigationBarMenuView(context2);
        this.menuView = createNavigationBarMenuView;
        navigationBarPresenter.setMenuView(createNavigationBarMenuView);
        navigationBarPresenter.setId(1);
        createNavigationBarMenuView.setPresenter(navigationBarPresenter);
        navigationBarMenu.addMenuPresenter(navigationBarPresenter);
        navigationBarPresenter.initForMenu(getContext(), navigationBarMenu);
        if (attributes.hasValue(R.styleable.NavigationBarView_itemIconTint)) {
            createNavigationBarMenuView.setIconTintList(attributes.getColorStateList(R.styleable.NavigationBarView_itemIconTint));
        } else {
            createNavigationBarMenuView.setIconTintList(createNavigationBarMenuView.createDefaultColorStateList(16842808));
        }
        setItemIconSize(attributes.getDimensionPixelSize(R.styleable.NavigationBarView_itemIconSize, getResources().getDimensionPixelSize(R.dimen.mtrl_navigation_bar_item_default_icon_size)));
        if (attributes.hasValue(R.styleable.NavigationBarView_itemTextAppearanceInactive)) {
            setItemTextAppearanceInactive(attributes.getResourceId(R.styleable.NavigationBarView_itemTextAppearanceInactive, 0));
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_itemTextAppearanceActive)) {
            setItemTextAppearanceActive(attributes.getResourceId(R.styleable.NavigationBarView_itemTextAppearanceActive, 0));
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_itemTextColor)) {
            setItemTextColor(attributes.getColorStateList(R.styleable.NavigationBarView_itemTextColor));
        }
        if (getBackground() == null || (getBackground() instanceof ColorDrawable)) {
            ViewCompat.setBackground(this, createMaterialShapeDrawableBackground(context2));
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_itemPaddingTop)) {
            setItemPaddingTop(attributes.getDimensionPixelSize(R.styleable.NavigationBarView_itemPaddingTop, 0));
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_itemPaddingBottom)) {
            setItemPaddingBottom(attributes.getDimensionPixelSize(R.styleable.NavigationBarView_itemPaddingBottom, 0));
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_elevation)) {
            setElevation(attributes.getDimensionPixelSize(R.styleable.NavigationBarView_elevation, 0));
        }
        ColorStateList backgroundTint = MaterialResources.getColorStateList(context2, attributes, R.styleable.NavigationBarView_backgroundTint);
        DrawableCompat.setTintList(getBackground().mutate(), backgroundTint);
        setLabelVisibilityMode(attributes.getInteger(R.styleable.NavigationBarView_labelVisibilityMode, -1));
        int itemBackground = attributes.getResourceId(R.styleable.NavigationBarView_itemBackground, 0);
        if (itemBackground != 0) {
            createNavigationBarMenuView.setItemBackgroundRes(itemBackground);
        } else {
            setItemRippleColor(MaterialResources.getColorStateList(context2, attributes, R.styleable.NavigationBarView_itemRippleColor));
        }
        int activeIndicatorStyleResId = attributes.getResourceId(R.styleable.NavigationBarView_itemActiveIndicatorStyle, 0);
        if (activeIndicatorStyleResId != 0) {
            setItemActiveIndicatorEnabled(true);
            TypedArray activeIndicatorAttributes = context2.obtainStyledAttributes(activeIndicatorStyleResId, R.styleable.NavigationBarActiveIndicator);
            int itemActiveIndicatorWidth = activeIndicatorAttributes.getDimensionPixelSize(R.styleable.NavigationBarActiveIndicator_android_width, 0);
            setItemActiveIndicatorWidth(itemActiveIndicatorWidth);
            int itemActiveIndicatorHeight = activeIndicatorAttributes.getDimensionPixelSize(R.styleable.NavigationBarActiveIndicator_android_height, 0);
            setItemActiveIndicatorHeight(itemActiveIndicatorHeight);
            int itemActiveIndicatorMarginHorizontal = activeIndicatorAttributes.getDimensionPixelOffset(R.styleable.NavigationBarActiveIndicator_marginHorizontal, 0);
            setItemActiveIndicatorMarginHorizontal(itemActiveIndicatorMarginHorizontal);
            ColorStateList itemActiveIndicatorColor = MaterialResources.getColorStateList(context2, activeIndicatorAttributes, R.styleable.NavigationBarActiveIndicator_android_color);
            setItemActiveIndicatorColor(itemActiveIndicatorColor);
            int shapeAppearanceResId = activeIndicatorAttributes.getResourceId(R.styleable.NavigationBarActiveIndicator_shapeAppearance, 0);
            ShapeAppearanceModel itemActiveIndicatorShapeAppearance = ShapeAppearanceModel.builder(context2, shapeAppearanceResId, 0).build();
            setItemActiveIndicatorShapeAppearance(itemActiveIndicatorShapeAppearance);
            activeIndicatorAttributes.recycle();
        }
        if (attributes.hasValue(R.styleable.NavigationBarView_menu)) {
            inflateMenu(attributes.getResourceId(R.styleable.NavigationBarView_menu, 0));
        }
        attributes.recycle();
        addView(createNavigationBarMenuView);
        navigationBarMenu.setCallback(new MenuBuilder.Callback() { // from class: com.google.android.material.navigation.NavigationBarView.1
            @Override // androidx.appcompat.view.menu.MenuBuilder.Callback
            public boolean onMenuItemSelected(MenuBuilder menu, MenuItem item) {
                if (NavigationBarView.this.reselectedListener == null || item.getItemId() != NavigationBarView.this.getSelectedItemId()) {
                    return (NavigationBarView.this.selectedListener == null || NavigationBarView.this.selectedListener.onNavigationItemSelected(item)) ? false : true;
                }
                NavigationBarView.this.reselectedListener.onNavigationItemReselected(item);
                return true;
            }

            @Override // androidx.appcompat.view.menu.MenuBuilder.Callback
            public void onMenuModeChange(MenuBuilder menu) {
            }
        });
    }

    private MaterialShapeDrawable createMaterialShapeDrawableBackground(Context context) {
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable();
        Drawable originalBackground = getBackground();
        if (originalBackground instanceof ColorDrawable) {
            materialShapeDrawable.setFillColor(ColorStateList.valueOf(((ColorDrawable) originalBackground).getColor()));
        }
        materialShapeDrawable.initializeElevationOverlay(context);
        return materialShapeDrawable;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        MaterialShapeUtils.setParentAbsoluteElevation(this);
    }

    @Override // android.view.View
    public void setElevation(float elevation) {
        if (Build.VERSION.SDK_INT >= 21) {
            super.setElevation(elevation);
        }
        MaterialShapeUtils.setElevation(this, elevation);
    }

    public void setOnItemSelectedListener(OnItemSelectedListener listener) {
        this.selectedListener = listener;
    }

    public void setOnItemReselectedListener(OnItemReselectedListener listener) {
        this.reselectedListener = listener;
    }

    public Menu getMenu() {
        return this.menu;
    }

    public MenuView getMenuView() {
        return this.menuView;
    }

    public void inflateMenu(int resId) {
        this.presenter.setUpdateSuspended(true);
        getMenuInflater().inflate(resId, this.menu);
        this.presenter.setUpdateSuspended(false);
        this.presenter.updateMenuView(true);
    }

    public ColorStateList getItemIconTintList() {
        return this.menuView.getIconTintList();
    }

    public void setItemIconTintList(ColorStateList tint) {
        this.menuView.setIconTintList(tint);
    }

    public void setItemIconSize(int iconSize) {
        this.menuView.setItemIconSize(iconSize);
    }

    public void setItemIconSizeRes(int iconSizeRes) {
        setItemIconSize(getResources().getDimensionPixelSize(iconSizeRes));
    }

    public int getItemIconSize() {
        return this.menuView.getItemIconSize();
    }

    public ColorStateList getItemTextColor() {
        return this.menuView.getItemTextColor();
    }

    public void setItemTextColor(ColorStateList textColor) {
        this.menuView.setItemTextColor(textColor);
    }

    @Deprecated
    public int getItemBackgroundResource() {
        return this.menuView.getItemBackgroundRes();
    }

    public void setItemBackgroundResource(int resId) {
        this.menuView.setItemBackgroundRes(resId);
        this.itemRippleColor = null;
    }

    public Drawable getItemBackground() {
        return this.menuView.getItemBackground();
    }

    public void setItemBackground(Drawable background) {
        this.menuView.setItemBackground(background);
        this.itemRippleColor = null;
    }

    public ColorStateList getItemRippleColor() {
        return this.itemRippleColor;
    }

    public void setItemRippleColor(ColorStateList itemRippleColor) {
        if (this.itemRippleColor == itemRippleColor) {
            if (itemRippleColor == null && this.menuView.getItemBackground() != null) {
                this.menuView.setItemBackground(null);
                return;
            }
            return;
        }
        this.itemRippleColor = itemRippleColor;
        if (itemRippleColor == null) {
            this.menuView.setItemBackground(null);
            return;
        }
        ColorStateList rippleDrawableColor = RippleUtils.convertToRippleDrawableColor(itemRippleColor);
        if (Build.VERSION.SDK_INT >= 21) {
            this.menuView.setItemBackground(new RippleDrawable(rippleDrawableColor, null, null));
            return;
        }
        GradientDrawable rippleDrawable = new GradientDrawable();
        rippleDrawable.setCornerRadius(1.0E-5f);
        Drawable rippleDrawableCompat = DrawableCompat.wrap(rippleDrawable);
        DrawableCompat.setTintList(rippleDrawableCompat, rippleDrawableColor);
        this.menuView.setItemBackground(rippleDrawableCompat);
    }

    public int getItemPaddingTop() {
        return this.menuView.getItemPaddingTop();
    }

    public void setItemPaddingTop(int paddingTop) {
        this.menuView.setItemPaddingTop(paddingTop);
    }

    public int getItemPaddingBottom() {
        return this.menuView.getItemPaddingBottom();
    }

    public void setItemPaddingBottom(int paddingBottom) {
        this.menuView.setItemPaddingBottom(paddingBottom);
    }

    public boolean isItemActiveIndicatorEnabled() {
        return this.menuView.getItemActiveIndicatorEnabled();
    }

    public void setItemActiveIndicatorEnabled(boolean enabled) {
        this.menuView.setItemActiveIndicatorEnabled(enabled);
    }

    public int getItemActiveIndicatorWidth() {
        return this.menuView.getItemActiveIndicatorWidth();
    }

    public void setItemActiveIndicatorWidth(int width) {
        this.menuView.setItemActiveIndicatorWidth(width);
    }

    public int getItemActiveIndicatorHeight() {
        return this.menuView.getItemActiveIndicatorHeight();
    }

    public void setItemActiveIndicatorHeight(int height) {
        this.menuView.setItemActiveIndicatorHeight(height);
    }

    public int getItemActiveIndicatorMarginHorizontal() {
        return this.menuView.getItemActiveIndicatorMarginHorizontal();
    }

    public void setItemActiveIndicatorMarginHorizontal(int horizontalMargin) {
        this.menuView.setItemActiveIndicatorMarginHorizontal(horizontalMargin);
    }

    public ShapeAppearanceModel getItemActiveIndicatorShapeAppearance() {
        return this.menuView.getItemActiveIndicatorShapeAppearance();
    }

    public void setItemActiveIndicatorShapeAppearance(ShapeAppearanceModel shapeAppearance) {
        this.menuView.setItemActiveIndicatorShapeAppearance(shapeAppearance);
    }

    public ColorStateList getItemActiveIndicatorColor() {
        return this.menuView.getItemActiveIndicatorColor();
    }

    public void setItemActiveIndicatorColor(ColorStateList csl) {
        this.menuView.setItemActiveIndicatorColor(csl);
    }

    public int getSelectedItemId() {
        return this.menuView.getSelectedItemId();
    }

    public void setSelectedItemId(int itemId) {
        MenuItem item = this.menu.findItem(itemId);
        if (item != null && !this.menu.performItemAction(item, this.presenter, 0)) {
            item.setChecked(true);
        }
    }

    public void setLabelVisibilityMode(int labelVisibilityMode) {
        if (this.menuView.getLabelVisibilityMode() != labelVisibilityMode) {
            this.menuView.setLabelVisibilityMode(labelVisibilityMode);
            this.presenter.updateMenuView(false);
        }
    }

    public int getLabelVisibilityMode() {
        return this.menuView.getLabelVisibilityMode();
    }

    public void setItemTextAppearanceInactive(int textAppearanceRes) {
        this.menuView.setItemTextAppearanceInactive(textAppearanceRes);
    }

    public int getItemTextAppearanceInactive() {
        return this.menuView.getItemTextAppearanceInactive();
    }

    public void setItemTextAppearanceActive(int textAppearanceRes) {
        this.menuView.setItemTextAppearanceActive(textAppearanceRes);
    }

    public int getItemTextAppearanceActive() {
        return this.menuView.getItemTextAppearanceActive();
    }

    public void setItemOnTouchListener(int menuItemId, View.OnTouchListener onTouchListener) {
        this.menuView.setItemOnTouchListener(menuItemId, onTouchListener);
    }

    public BadgeDrawable getBadge(int menuItemId) {
        return this.menuView.getBadge(menuItemId);
    }

    public BadgeDrawable getOrCreateBadge(int menuItemId) {
        return this.menuView.getOrCreateBadge(menuItemId);
    }

    public void removeBadge(int menuItemId) {
        this.menuView.removeBadge(menuItemId);
    }

    private MenuInflater getMenuInflater() {
        if (this.menuInflater == null) {
            this.menuInflater = new SupportMenuInflater(getContext());
        }
        return this.menuInflater;
    }

    public NavigationBarPresenter getPresenter() {
        return this.presenter;
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        Parcelable superState = super.onSaveInstanceState();
        SavedState savedState = new SavedState(superState);
        savedState.menuPresenterState = new Bundle();
        this.menu.savePresenterStates(savedState.menuPresenterState);
        return savedState;
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState savedState = (SavedState) state;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.menu.restorePresenterStates(savedState.menuPresenterState);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() { // from class: com.google.android.material.navigation.NavigationBarView.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.ClassLoaderCreator
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        Bundle menuPresenterState;

        public SavedState(Parcelable superState) {
            super(superState);
        }

        public SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            readFromParcel(source, loader == null ? getClass().getClassLoader() : loader);
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeBundle(this.menuPresenterState);
        }

        private void readFromParcel(Parcel in, ClassLoader loader) {
            this.menuPresenterState = in.readBundle(loader);
        }
    }
}
