package com.google.android.material.navigation;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.util.SparseArray;
import android.util.TypedValue;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuItemImpl;
import androidx.appcompat.view.menu.MenuView;
import androidx.core.util.Pools;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.transition.AutoTransition;
import androidx.transition.TransitionManager;
import androidx.transition.TransitionSet;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.badge.BadgeDrawable;
import com.google.android.material.internal.TextScale;
import com.google.android.material.motion.MotionUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import java.util.HashSet;
/* loaded from: classes.dex */
public abstract class NavigationBarMenuView extends ViewGroup implements MenuView {
    private static final int[] CHECKED_STATE_SET = {16842912};
    private static final int[] DISABLED_STATE_SET = {-16842910};
    private static final int ITEM_POOL_SIZE = 5;
    private static final int NO_PADDING = -1;
    private final SparseArray<BadgeDrawable> badgeDrawables;
    private NavigationBarItemView[] buttons;
    private ColorStateList itemActiveIndicatorColor;
    private boolean itemActiveIndicatorEnabled;
    private int itemActiveIndicatorHeight;
    private int itemActiveIndicatorMarginHorizontal;
    private boolean itemActiveIndicatorResizeable;
    private ShapeAppearanceModel itemActiveIndicatorShapeAppearance;
    private int itemActiveIndicatorWidth;
    private Drawable itemBackground;
    private int itemBackgroundRes;
    private int itemIconSize;
    private ColorStateList itemIconTint;
    private int itemPaddingBottom;
    private int itemPaddingTop;
    private final Pools.Pool<NavigationBarItemView> itemPool;
    private int itemTextAppearanceActive;
    private int itemTextAppearanceInactive;
    private final ColorStateList itemTextColorDefault;
    private ColorStateList itemTextColorFromUser;
    private int labelVisibilityMode;
    private MenuBuilder menu;
    private final View.OnClickListener onClickListener;
    private final SparseArray<View.OnTouchListener> onTouchListeners;
    private NavigationBarPresenter presenter;
    private int selectedItemId;
    private int selectedItemPosition;
    private final TransitionSet set;

    protected abstract NavigationBarItemView createNavigationBarItemView(Context context);

    public NavigationBarMenuView(Context context) {
        super(context);
        this.itemPool = new Pools.SynchronizedPool(5);
        this.onTouchListeners = new SparseArray<>(5);
        this.selectedItemId = 0;
        this.selectedItemPosition = 0;
        this.badgeDrawables = new SparseArray<>(5);
        this.itemPaddingTop = -1;
        this.itemPaddingBottom = -1;
        this.itemActiveIndicatorResizeable = false;
        this.itemTextColorDefault = createDefaultColorStateList(16842808);
        if (isInEditMode()) {
            this.set = null;
        } else {
            AutoTransition autoTransition = new AutoTransition();
            this.set = autoTransition;
            autoTransition.setOrdering(0);
            autoTransition.setDuration(MotionUtils.resolveThemeDuration(getContext(), R.attr.motionDurationLong1, getResources().getInteger(R.integer.material_motion_duration_long_1)));
            autoTransition.setInterpolator(MotionUtils.resolveThemeInterpolator(getContext(), R.attr.motionEasingStandard, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
            autoTransition.addTransition(new TextScale());
        }
        this.onClickListener = new View.OnClickListener() { // from class: com.google.android.material.navigation.NavigationBarMenuView.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                NavigationBarItemView itemView = (NavigationBarItemView) v;
                MenuItem item = itemView.getItemData();
                if (!NavigationBarMenuView.this.menu.performItemAction(item, NavigationBarMenuView.this.presenter, 0)) {
                    item.setChecked(true);
                }
            }
        };
        ViewCompat.setImportantForAccessibility(this, 1);
    }

    @Override // androidx.appcompat.view.menu.MenuView
    public void initialize(MenuBuilder menu) {
        this.menu = menu;
    }

    @Override // androidx.appcompat.view.menu.MenuView
    public int getWindowAnimations() {
        return 0;
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        AccessibilityNodeInfoCompat infoCompat = AccessibilityNodeInfoCompat.wrap(info);
        infoCompat.setCollectionInfo(AccessibilityNodeInfoCompat.CollectionInfoCompat.obtain(1, this.menu.getVisibleItems().size(), false, 1));
    }

    public void setIconTintList(ColorStateList tint) {
        this.itemIconTint = tint;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setIconTintList(tint);
            }
        }
    }

    public ColorStateList getIconTintList() {
        return this.itemIconTint;
    }

    public void setItemIconSize(int iconSize) {
        this.itemIconSize = iconSize;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setIconSize(iconSize);
            }
        }
    }

    public int getItemIconSize() {
        return this.itemIconSize;
    }

    public void setItemTextColor(ColorStateList color) {
        this.itemTextColorFromUser = color;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setTextColor(color);
            }
        }
    }

    public ColorStateList getItemTextColor() {
        return this.itemTextColorFromUser;
    }

    public void setItemTextAppearanceInactive(int textAppearanceRes) {
        this.itemTextAppearanceInactive = textAppearanceRes;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setTextAppearanceInactive(textAppearanceRes);
                ColorStateList colorStateList = this.itemTextColorFromUser;
                if (colorStateList != null) {
                    item.setTextColor(colorStateList);
                }
            }
        }
    }

    public int getItemTextAppearanceInactive() {
        return this.itemTextAppearanceInactive;
    }

    public void setItemTextAppearanceActive(int textAppearanceRes) {
        this.itemTextAppearanceActive = textAppearanceRes;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setTextAppearanceActive(textAppearanceRes);
                ColorStateList colorStateList = this.itemTextColorFromUser;
                if (colorStateList != null) {
                    item.setTextColor(colorStateList);
                }
            }
        }
    }

    public int getItemTextAppearanceActive() {
        return this.itemTextAppearanceActive;
    }

    public void setItemBackgroundRes(int background) {
        this.itemBackgroundRes = background;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setItemBackground(background);
            }
        }
    }

    public int getItemPaddingTop() {
        return this.itemPaddingTop;
    }

    public void setItemPaddingTop(int paddingTop) {
        this.itemPaddingTop = paddingTop;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setItemPaddingTop(paddingTop);
            }
        }
    }

    public int getItemPaddingBottom() {
        return this.itemPaddingBottom;
    }

    public void setItemPaddingBottom(int paddingBottom) {
        this.itemPaddingBottom = paddingBottom;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setItemPaddingBottom(paddingBottom);
            }
        }
    }

    public boolean getItemActiveIndicatorEnabled() {
        return this.itemActiveIndicatorEnabled;
    }

    public void setItemActiveIndicatorEnabled(boolean enabled) {
        this.itemActiveIndicatorEnabled = enabled;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorEnabled(enabled);
            }
        }
    }

    public int getItemActiveIndicatorWidth() {
        return this.itemActiveIndicatorWidth;
    }

    public void setItemActiveIndicatorWidth(int width) {
        this.itemActiveIndicatorWidth = width;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorWidth(width);
            }
        }
    }

    public int getItemActiveIndicatorHeight() {
        return this.itemActiveIndicatorHeight;
    }

    public void setItemActiveIndicatorHeight(int height) {
        this.itemActiveIndicatorHeight = height;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorHeight(height);
            }
        }
    }

    public int getItemActiveIndicatorMarginHorizontal() {
        return this.itemActiveIndicatorMarginHorizontal;
    }

    public void setItemActiveIndicatorMarginHorizontal(int marginHorizontal) {
        this.itemActiveIndicatorMarginHorizontal = marginHorizontal;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorMarginHorizontal(marginHorizontal);
            }
        }
    }

    public ShapeAppearanceModel getItemActiveIndicatorShapeAppearance() {
        return this.itemActiveIndicatorShapeAppearance;
    }

    public void setItemActiveIndicatorShapeAppearance(ShapeAppearanceModel shapeAppearance) {
        this.itemActiveIndicatorShapeAppearance = shapeAppearance;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorDrawable(createItemActiveIndicatorDrawable());
            }
        }
    }

    protected boolean isItemActiveIndicatorResizeable() {
        return this.itemActiveIndicatorResizeable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setItemActiveIndicatorResizeable(boolean resizeable) {
        this.itemActiveIndicatorResizeable = resizeable;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorResizeable(resizeable);
            }
        }
    }

    public ColorStateList getItemActiveIndicatorColor() {
        return this.itemActiveIndicatorColor;
    }

    public void setItemActiveIndicatorColor(ColorStateList csl) {
        this.itemActiveIndicatorColor = csl;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setActiveIndicatorDrawable(createItemActiveIndicatorDrawable());
            }
        }
    }

    private Drawable createItemActiveIndicatorDrawable() {
        if (this.itemActiveIndicatorShapeAppearance != null && this.itemActiveIndicatorColor != null) {
            MaterialShapeDrawable drawable = new MaterialShapeDrawable(this.itemActiveIndicatorShapeAppearance);
            drawable.setFillColor(this.itemActiveIndicatorColor);
            return drawable;
        }
        return null;
    }

    @Deprecated
    public int getItemBackgroundRes() {
        return this.itemBackgroundRes;
    }

    public void setItemBackground(Drawable background) {
        this.itemBackground = background;
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                item.setItemBackground(background);
            }
        }
    }

    public Drawable getItemBackground() {
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null && navigationBarItemViewArr.length > 0) {
            return navigationBarItemViewArr[0].getBackground();
        }
        return this.itemBackground;
    }

    public void setLabelVisibilityMode(int labelVisibilityMode) {
        this.labelVisibilityMode = labelVisibilityMode;
    }

    public int getLabelVisibilityMode() {
        return this.labelVisibilityMode;
    }

    public void setItemOnTouchListener(int menuItemId, View.OnTouchListener onTouchListener) {
        if (onTouchListener == null) {
            this.onTouchListeners.remove(menuItemId);
        } else {
            this.onTouchListeners.put(menuItemId, onTouchListener);
        }
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                if (item.getItemData().getItemId() == menuItemId) {
                    item.setOnTouchListener(onTouchListener);
                }
            }
        }
    }

    public ColorStateList createDefaultColorStateList(int baseColorThemeAttr) {
        TypedValue value = new TypedValue();
        if (getContext().getTheme().resolveAttribute(baseColorThemeAttr, value, true)) {
            ColorStateList baseColor = AppCompatResources.getColorStateList(getContext(), value.resourceId);
            if (getContext().getTheme().resolveAttribute(androidx.appcompat.R.attr.colorPrimary, value, true)) {
                int colorPrimary = value.data;
                int defaultColor = baseColor.getDefaultColor();
                int[] iArr = DISABLED_STATE_SET;
                return new ColorStateList(new int[][]{iArr, CHECKED_STATE_SET, EMPTY_STATE_SET}, new int[]{baseColor.getColorForState(iArr, defaultColor), colorPrimary, defaultColor});
            }
            return null;
        }
        return null;
    }

    public void setPresenter(NavigationBarPresenter presenter) {
        this.presenter = presenter;
    }

    public void buildMenuView() {
        removeAllViews();
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView item : navigationBarItemViewArr) {
                if (item != null) {
                    this.itemPool.release(item);
                    item.clear();
                }
            }
        }
        if (this.menu.size() == 0) {
            this.selectedItemId = 0;
            this.selectedItemPosition = 0;
            this.buttons = null;
            return;
        }
        removeUnusedBadges();
        this.buttons = new NavigationBarItemView[this.menu.size()];
        boolean shifting = isShifting(this.labelVisibilityMode, this.menu.getVisibleItems().size());
        for (int i = 0; i < this.menu.size(); i++) {
            this.presenter.setUpdateSuspended(true);
            this.menu.getItem(i).setCheckable(true);
            this.presenter.setUpdateSuspended(false);
            NavigationBarItemView child = getNewItem();
            this.buttons[i] = child;
            child.setIconTintList(this.itemIconTint);
            child.setIconSize(this.itemIconSize);
            child.setTextColor(this.itemTextColorDefault);
            child.setTextAppearanceInactive(this.itemTextAppearanceInactive);
            child.setTextAppearanceActive(this.itemTextAppearanceActive);
            child.setTextColor(this.itemTextColorFromUser);
            int i2 = this.itemPaddingTop;
            if (i2 != -1) {
                child.setItemPaddingTop(i2);
            }
            int i3 = this.itemPaddingBottom;
            if (i3 != -1) {
                child.setItemPaddingBottom(i3);
            }
            child.setActiveIndicatorWidth(this.itemActiveIndicatorWidth);
            child.setActiveIndicatorHeight(this.itemActiveIndicatorHeight);
            child.setActiveIndicatorMarginHorizontal(this.itemActiveIndicatorMarginHorizontal);
            child.setActiveIndicatorDrawable(createItemActiveIndicatorDrawable());
            child.setActiveIndicatorResizeable(this.itemActiveIndicatorResizeable);
            child.setActiveIndicatorEnabled(this.itemActiveIndicatorEnabled);
            Drawable drawable = this.itemBackground;
            if (drawable != null) {
                child.setItemBackground(drawable);
            } else {
                child.setItemBackground(this.itemBackgroundRes);
            }
            child.setShifting(shifting);
            child.setLabelVisibilityMode(this.labelVisibilityMode);
            MenuItemImpl item2 = (MenuItemImpl) this.menu.getItem(i);
            child.initialize(item2, 0);
            child.setItemPosition(i);
            int itemId = item2.getItemId();
            child.setOnTouchListener(this.onTouchListeners.get(itemId));
            child.setOnClickListener(this.onClickListener);
            int i4 = this.selectedItemId;
            if (i4 != 0 && itemId == i4) {
                this.selectedItemPosition = i;
            }
            setBadgeIfNeeded(child);
            addView(child);
        }
        int min = Math.min(this.menu.size() - 1, this.selectedItemPosition);
        this.selectedItemPosition = min;
        this.menu.getItem(min).setChecked(true);
    }

    public void updateMenuView() {
        TransitionSet transitionSet;
        MenuBuilder menuBuilder = this.menu;
        if (menuBuilder == null || this.buttons == null) {
            return;
        }
        int menuSize = menuBuilder.size();
        if (menuSize != this.buttons.length) {
            buildMenuView();
            return;
        }
        int previousSelectedId = this.selectedItemId;
        for (int i = 0; i < menuSize; i++) {
            MenuItem item = this.menu.getItem(i);
            if (item.isChecked()) {
                this.selectedItemId = item.getItemId();
                this.selectedItemPosition = i;
            }
        }
        int i2 = this.selectedItemId;
        if (previousSelectedId != i2 && (transitionSet = this.set) != null) {
            TransitionManager.beginDelayedTransition(this, transitionSet);
        }
        boolean shifting = isShifting(this.labelVisibilityMode, this.menu.getVisibleItems().size());
        for (int i3 = 0; i3 < menuSize; i3++) {
            this.presenter.setUpdateSuspended(true);
            this.buttons[i3].setLabelVisibilityMode(this.labelVisibilityMode);
            this.buttons[i3].setShifting(shifting);
            this.buttons[i3].initialize((MenuItemImpl) this.menu.getItem(i3), 0);
            this.presenter.setUpdateSuspended(false);
        }
    }

    private NavigationBarItemView getNewItem() {
        NavigationBarItemView item = this.itemPool.acquire();
        if (item == null) {
            return createNavigationBarItemView(getContext());
        }
        return item;
    }

    public int getSelectedItemId() {
        return this.selectedItemId;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean isShifting(int labelVisibilityMode, int childCount) {
        return labelVisibilityMode == -1 ? childCount > 3 : labelVisibilityMode == 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void tryRestoreSelectedItemId(int itemId) {
        int size = this.menu.size();
        for (int i = 0; i < size; i++) {
            MenuItem item = this.menu.getItem(i);
            if (itemId == item.getItemId()) {
                this.selectedItemId = itemId;
                this.selectedItemPosition = i;
                item.setChecked(true);
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SparseArray<BadgeDrawable> getBadgeDrawables() {
        return this.badgeDrawables;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void restoreBadgeDrawables(SparseArray<BadgeDrawable> badgeDrawables) {
        for (int i = 0; i < badgeDrawables.size(); i++) {
            int key = badgeDrawables.keyAt(i);
            if (this.badgeDrawables.indexOfKey(key) < 0) {
                this.badgeDrawables.append(key, badgeDrawables.get(key));
            }
        }
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView itemView : navigationBarItemViewArr) {
                itemView.setBadge(this.badgeDrawables.get(itemView.getId()));
            }
        }
    }

    public BadgeDrawable getBadge(int menuItemId) {
        return this.badgeDrawables.get(menuItemId);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BadgeDrawable getOrCreateBadge(int menuItemId) {
        validateMenuItemId(menuItemId);
        BadgeDrawable badgeDrawable = this.badgeDrawables.get(menuItemId);
        if (badgeDrawable == null) {
            badgeDrawable = BadgeDrawable.create(getContext());
            this.badgeDrawables.put(menuItemId, badgeDrawable);
        }
        NavigationBarItemView itemView = findItemView(menuItemId);
        if (itemView != null) {
            itemView.setBadge(badgeDrawable);
        }
        return badgeDrawable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeBadge(int menuItemId) {
        validateMenuItemId(menuItemId);
        BadgeDrawable badgeDrawable = this.badgeDrawables.get(menuItemId);
        NavigationBarItemView itemView = findItemView(menuItemId);
        if (itemView != null) {
            itemView.removeBadge();
        }
        if (badgeDrawable != null) {
            this.badgeDrawables.remove(menuItemId);
        }
    }

    private void setBadgeIfNeeded(NavigationBarItemView child) {
        BadgeDrawable badgeDrawable;
        int childId = child.getId();
        if (isValidId(childId) && (badgeDrawable = this.badgeDrawables.get(childId)) != null) {
            child.setBadge(badgeDrawable);
        }
    }

    private void removeUnusedBadges() {
        HashSet<Integer> activeKeys = new HashSet<>();
        for (int i = 0; i < this.menu.size(); i++) {
            activeKeys.add(Integer.valueOf(this.menu.getItem(i).getItemId()));
        }
        for (int i2 = 0; i2 < this.badgeDrawables.size(); i2++) {
            int key = this.badgeDrawables.keyAt(i2);
            if (!activeKeys.contains(Integer.valueOf(key))) {
                this.badgeDrawables.delete(key);
            }
        }
    }

    public NavigationBarItemView findItemView(int menuItemId) {
        validateMenuItemId(menuItemId);
        NavigationBarItemView[] navigationBarItemViewArr = this.buttons;
        if (navigationBarItemViewArr != null) {
            for (NavigationBarItemView itemView : navigationBarItemViewArr) {
                if (itemView.getId() == menuItemId) {
                    return itemView;
                }
            }
            return null;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public int getSelectedItemPosition() {
        return this.selectedItemPosition;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public MenuBuilder getMenu() {
        return this.menu;
    }

    private boolean isValidId(int viewId) {
        return viewId != -1;
    }

    private void validateMenuItemId(int viewId) {
        if (!isValidId(viewId)) {
            throw new IllegalArgumentException(viewId + " is not a valid view id");
        }
    }
}
