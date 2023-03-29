package com.google.android.material.bottomnavigation;

import android.content.Context;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import androidx.appcompat.widget.TintTypedArray;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.R;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.navigation.NavigationBarMenuView;
import com.google.android.material.navigation.NavigationBarView;
import com.google.android.material.shape.MaterialShapeDrawable;
/* loaded from: classes.dex */
public class BottomNavigationView extends NavigationBarView {
    static final int MAX_ITEM_COUNT = 5;

    @Deprecated
    /* loaded from: classes.dex */
    public interface OnNavigationItemReselectedListener extends NavigationBarView.OnItemReselectedListener {
    }

    @Deprecated
    /* loaded from: classes.dex */
    public interface OnNavigationItemSelectedListener extends NavigationBarView.OnItemSelectedListener {
    }

    public BottomNavigationView(Context context) {
        this(context, null);
    }

    public BottomNavigationView(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.bottomNavigationStyle);
    }

    public BottomNavigationView(Context context, AttributeSet attrs, int defStyleAttr) {
        this(context, attrs, defStyleAttr, R.style.Widget_Design_BottomNavigationView);
    }

    public BottomNavigationView(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        Context context2 = getContext();
        TintTypedArray attributes = ThemeEnforcement.obtainTintedStyledAttributes(context2, attrs, R.styleable.BottomNavigationView, defStyleAttr, defStyleRes, new int[0]);
        setItemHorizontalTranslationEnabled(attributes.getBoolean(R.styleable.BottomNavigationView_itemHorizontalTranslationEnabled, true));
        if (attributes.hasValue(R.styleable.BottomNavigationView_android_minHeight)) {
            setMinimumHeight(attributes.getDimensionPixelSize(R.styleable.BottomNavigationView_android_minHeight, 0));
        }
        attributes.recycle();
        if (shouldDrawCompatibilityTopDivider()) {
            addCompatibilityTopDivider(context2);
        }
        applyWindowInsets();
    }

    private void applyWindowInsets() {
        ViewUtils.doOnApplyWindowInsets(this, new ViewUtils.OnApplyWindowInsetsListener() { // from class: com.google.android.material.bottomnavigation.BottomNavigationView.1
            @Override // com.google.android.material.internal.ViewUtils.OnApplyWindowInsetsListener
            public WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat insets, ViewUtils.RelativePadding initialPadding) {
                initialPadding.bottom += insets.getSystemWindowInsetBottom();
                boolean isRtl = ViewCompat.getLayoutDirection(view) == 1;
                int systemWindowInsetLeft = insets.getSystemWindowInsetLeft();
                int systemWindowInsetRight = insets.getSystemWindowInsetRight();
                initialPadding.start += isRtl ? systemWindowInsetRight : systemWindowInsetLeft;
                initialPadding.end += isRtl ? systemWindowInsetLeft : systemWindowInsetRight;
                initialPadding.applyToView(view);
                return insets;
            }
        });
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int minHeightSpec = makeMinHeightSpec(heightMeasureSpec);
        super.onMeasure(widthMeasureSpec, minHeightSpec);
    }

    private int makeMinHeightSpec(int measureSpec) {
        int minHeight = getSuggestedMinimumHeight();
        if (View.MeasureSpec.getMode(measureSpec) != 1073741824 && minHeight > 0) {
            return View.MeasureSpec.makeMeasureSpec(Math.min(View.MeasureSpec.getSize(measureSpec), minHeight + getPaddingTop() + getPaddingBottom()), BasicMeasure.EXACTLY);
        }
        return measureSpec;
    }

    public void setItemHorizontalTranslationEnabled(boolean itemHorizontalTranslationEnabled) {
        BottomNavigationMenuView menuView = (BottomNavigationMenuView) getMenuView();
        if (menuView.isItemHorizontalTranslationEnabled() != itemHorizontalTranslationEnabled) {
            menuView.setItemHorizontalTranslationEnabled(itemHorizontalTranslationEnabled);
            getPresenter().updateMenuView(false);
        }
    }

    public boolean isItemHorizontalTranslationEnabled() {
        return ((BottomNavigationMenuView) getMenuView()).isItemHorizontalTranslationEnabled();
    }

    @Override // com.google.android.material.navigation.NavigationBarView
    public int getMaxItemCount() {
        return 5;
    }

    @Override // com.google.android.material.navigation.NavigationBarView
    protected NavigationBarMenuView createNavigationBarMenuView(Context context) {
        return new BottomNavigationMenuView(context);
    }

    private boolean shouldDrawCompatibilityTopDivider() {
        return Build.VERSION.SDK_INT < 21 && !(getBackground() instanceof MaterialShapeDrawable);
    }

    private void addCompatibilityTopDivider(Context context) {
        View divider = new View(context);
        divider.setBackgroundColor(ContextCompat.getColor(context, R.color.design_bottom_navigation_shadow_color));
        FrameLayout.LayoutParams dividerParams = new FrameLayout.LayoutParams(-1, getResources().getDimensionPixelSize(R.dimen.design_bottom_navigation_shadow_height));
        divider.setLayoutParams(dividerParams);
        addView(divider);
    }

    @Deprecated
    public void setOnNavigationItemSelectedListener(OnNavigationItemSelectedListener listener) {
        setOnItemSelectedListener(listener);
    }

    @Deprecated
    public void setOnNavigationItemReselectedListener(OnNavigationItemReselectedListener listener) {
        setOnItemReselectedListener(listener);
    }
}
