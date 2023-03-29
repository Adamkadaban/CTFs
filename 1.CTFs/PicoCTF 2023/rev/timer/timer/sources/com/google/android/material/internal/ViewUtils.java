package com.google.android.material.internal;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import android.view.inputmethod.InputMethodManager;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.R;
/* loaded from: classes.dex */
public class ViewUtils {

    /* loaded from: classes.dex */
    public interface OnApplyWindowInsetsListener {
        WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat windowInsetsCompat, RelativePadding relativePadding);
    }

    private ViewUtils() {
    }

    public static PorterDuff.Mode parseTintMode(int value, PorterDuff.Mode defaultMode) {
        switch (value) {
            case 3:
                return PorterDuff.Mode.SRC_OVER;
            case 5:
                return PorterDuff.Mode.SRC_IN;
            case 9:
                return PorterDuff.Mode.SRC_ATOP;
            case 14:
                return PorterDuff.Mode.MULTIPLY;
            case 15:
                return PorterDuff.Mode.SCREEN;
            case 16:
                return PorterDuff.Mode.ADD;
            default:
                return defaultMode;
        }
    }

    public static boolean isLayoutRtl(View view) {
        return ViewCompat.getLayoutDirection(view) == 1;
    }

    public static float dpToPx(Context context, int dp) {
        Resources r = context.getResources();
        return TypedValue.applyDimension(1, dp, r.getDisplayMetrics());
    }

    public static void requestFocusAndShowKeyboard(final View view) {
        view.requestFocus();
        view.post(new Runnable() { // from class: com.google.android.material.internal.ViewUtils.1
            @Override // java.lang.Runnable
            public void run() {
                InputMethodManager inputMethodManager = (InputMethodManager) view.getContext().getSystemService("input_method");
                inputMethodManager.showSoftInput(view, 1);
            }
        });
    }

    /* loaded from: classes.dex */
    public static class RelativePadding {
        public int bottom;
        public int end;
        public int start;
        public int top;

        public RelativePadding(int start, int top, int end, int bottom) {
            this.start = start;
            this.top = top;
            this.end = end;
            this.bottom = bottom;
        }

        public RelativePadding(RelativePadding other) {
            this.start = other.start;
            this.top = other.top;
            this.end = other.end;
            this.bottom = other.bottom;
        }

        public void applyToView(View view) {
            ViewCompat.setPaddingRelative(view, this.start, this.top, this.end, this.bottom);
        }
    }

    public static void doOnApplyWindowInsets(View view, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        doOnApplyWindowInsets(view, attrs, defStyleAttr, defStyleRes, null);
    }

    public static void doOnApplyWindowInsets(View view, AttributeSet attrs, int defStyleAttr, int defStyleRes, final OnApplyWindowInsetsListener listener) {
        TypedArray a = view.getContext().obtainStyledAttributes(attrs, R.styleable.Insets, defStyleAttr, defStyleRes);
        final boolean paddingBottomSystemWindowInsets = a.getBoolean(R.styleable.Insets_paddingBottomSystemWindowInsets, false);
        final boolean paddingLeftSystemWindowInsets = a.getBoolean(R.styleable.Insets_paddingLeftSystemWindowInsets, false);
        final boolean paddingRightSystemWindowInsets = a.getBoolean(R.styleable.Insets_paddingRightSystemWindowInsets, false);
        a.recycle();
        doOnApplyWindowInsets(view, new OnApplyWindowInsetsListener() { // from class: com.google.android.material.internal.ViewUtils.2
            @Override // com.google.android.material.internal.ViewUtils.OnApplyWindowInsetsListener
            public WindowInsetsCompat onApplyWindowInsets(View view2, WindowInsetsCompat insets, RelativePadding initialPadding) {
                if (paddingBottomSystemWindowInsets) {
                    initialPadding.bottom += insets.getSystemWindowInsetBottom();
                }
                boolean isRtl = ViewUtils.isLayoutRtl(view2);
                if (paddingLeftSystemWindowInsets) {
                    if (isRtl) {
                        initialPadding.end += insets.getSystemWindowInsetLeft();
                    } else {
                        initialPadding.start += insets.getSystemWindowInsetLeft();
                    }
                }
                if (paddingRightSystemWindowInsets) {
                    if (isRtl) {
                        initialPadding.start += insets.getSystemWindowInsetRight();
                    } else {
                        initialPadding.end += insets.getSystemWindowInsetRight();
                    }
                }
                initialPadding.applyToView(view2);
                OnApplyWindowInsetsListener onApplyWindowInsetsListener = listener;
                if (onApplyWindowInsetsListener != null) {
                    return onApplyWindowInsetsListener.onApplyWindowInsets(view2, insets, initialPadding);
                }
                return insets;
            }
        });
    }

    public static void doOnApplyWindowInsets(View view, final OnApplyWindowInsetsListener listener) {
        final RelativePadding initialPadding = new RelativePadding(ViewCompat.getPaddingStart(view), view.getPaddingTop(), ViewCompat.getPaddingEnd(view), view.getPaddingBottom());
        ViewCompat.setOnApplyWindowInsetsListener(view, new androidx.core.view.OnApplyWindowInsetsListener() { // from class: com.google.android.material.internal.ViewUtils.3
            @Override // androidx.core.view.OnApplyWindowInsetsListener
            public WindowInsetsCompat onApplyWindowInsets(View view2, WindowInsetsCompat insets) {
                return OnApplyWindowInsetsListener.this.onApplyWindowInsets(view2, insets, new RelativePadding(initialPadding));
            }
        });
        requestApplyInsetsWhenAttached(view);
    }

    public static void requestApplyInsetsWhenAttached(View view) {
        if (ViewCompat.isAttachedToWindow(view)) {
            ViewCompat.requestApplyInsets(view);
        } else {
            view.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: com.google.android.material.internal.ViewUtils.4
                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewAttachedToWindow(View v) {
                    v.removeOnAttachStateChangeListener(this);
                    ViewCompat.requestApplyInsets(v);
                }

                @Override // android.view.View.OnAttachStateChangeListener
                public void onViewDetachedFromWindow(View v) {
                }
            });
        }
    }

    public static float getParentAbsoluteElevation(View view) {
        float absoluteElevation = 0.0f;
        for (ViewParent viewParent = view.getParent(); viewParent instanceof View; viewParent = viewParent.getParent()) {
            absoluteElevation += ViewCompat.getElevation((View) viewParent);
        }
        return absoluteElevation;
    }

    public static ViewOverlayImpl getOverlay(View view) {
        if (view == null) {
            return null;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            return new ViewOverlayApi18(view);
        }
        return ViewOverlayApi14.createFrom(view);
    }

    public static ViewGroup getContentView(View view) {
        if (view == null) {
            return null;
        }
        View rootView = view.getRootView();
        ViewGroup contentView = (ViewGroup) rootView.findViewById(16908290);
        if (contentView != null) {
            return contentView;
        }
        if (rootView == view || !(rootView instanceof ViewGroup)) {
            return null;
        }
        return (ViewGroup) rootView;
    }

    public static ViewOverlayImpl getContentViewOverlay(View view) {
        return getOverlay(getContentView(view));
    }

    public static void addOnGlobalLayoutListener(View view, ViewTreeObserver.OnGlobalLayoutListener victim) {
        if (view != null) {
            view.getViewTreeObserver().addOnGlobalLayoutListener(victim);
        }
    }

    public static void removeOnGlobalLayoutListener(View view, ViewTreeObserver.OnGlobalLayoutListener victim) {
        if (view != null) {
            removeOnGlobalLayoutListener(view.getViewTreeObserver(), victim);
        }
    }

    public static void removeOnGlobalLayoutListener(ViewTreeObserver viewTreeObserver, ViewTreeObserver.OnGlobalLayoutListener victim) {
        if (Build.VERSION.SDK_INT >= 16) {
            viewTreeObserver.removeOnGlobalLayoutListener(victim);
        } else {
            viewTreeObserver.removeGlobalOnLayoutListener(victim);
        }
    }

    public static Integer getBackgroundColor(View view) {
        if (view.getBackground() instanceof ColorDrawable) {
            return Integer.valueOf(((ColorDrawable) view.getBackground()).getColor());
        }
        return null;
    }
}
