package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.view.ViewCompat;
/* loaded from: classes.dex */
public class ContentFrameLayout extends FrameLayout {
    private OnAttachListener mAttachListener;
    private final Rect mDecorPadding;
    private TypedValue mFixedHeightMajor;
    private TypedValue mFixedHeightMinor;
    private TypedValue mFixedWidthMajor;
    private TypedValue mFixedWidthMinor;
    private TypedValue mMinWidthMajor;
    private TypedValue mMinWidthMinor;

    /* loaded from: classes.dex */
    public interface OnAttachListener {
        void onAttachedFromWindow();

        void onDetachedFromWindow();
    }

    public ContentFrameLayout(Context context) {
        this(context, null);
    }

    public ContentFrameLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public ContentFrameLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mDecorPadding = new Rect();
    }

    public void dispatchFitSystemWindows(Rect insets) {
        fitSystemWindows(insets);
    }

    public void setAttachListener(OnAttachListener attachListener) {
        this.mAttachListener = attachListener;
    }

    public void setDecorPadding(int left, int top, int right, int bottom) {
        this.mDecorPadding.set(left, top, right, bottom);
        if (ViewCompat.isLaidOut(this)) {
            requestLayout();
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        DisplayMetrics metrics = getContext().getResources().getDisplayMetrics();
        boolean isPortrait = metrics.widthPixels < metrics.heightPixels;
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        boolean fixedWidth = false;
        if (widthMode == Integer.MIN_VALUE) {
            TypedValue tvw = isPortrait ? this.mFixedWidthMinor : this.mFixedWidthMajor;
            if (tvw != null && tvw.type != 0) {
                int w = 0;
                if (tvw.type != 5) {
                    if (tvw.type == 6) {
                        w = (int) tvw.getFraction(metrics.widthPixels, metrics.widthPixels);
                    }
                } else {
                    w = (int) tvw.getDimension(metrics);
                }
                if (w > 0) {
                    int w2 = w - (this.mDecorPadding.left + this.mDecorPadding.right);
                    int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                    widthMeasureSpec = View.MeasureSpec.makeMeasureSpec(Math.min(w2, widthSize), BasicMeasure.EXACTLY);
                    fixedWidth = true;
                }
            }
        }
        if (heightMode == Integer.MIN_VALUE) {
            TypedValue tvh = isPortrait ? this.mFixedHeightMajor : this.mFixedHeightMinor;
            if (tvh != null && tvh.type != 0) {
                int h = 0;
                if (tvh.type != 5) {
                    if (tvh.type == 6) {
                        h = (int) tvh.getFraction(metrics.heightPixels, metrics.heightPixels);
                    }
                } else {
                    h = (int) tvh.getDimension(metrics);
                }
                if (h > 0) {
                    int h2 = h - (this.mDecorPadding.top + this.mDecorPadding.bottom);
                    int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                    heightMeasureSpec = View.MeasureSpec.makeMeasureSpec(Math.min(h2, heightSize), BasicMeasure.EXACTLY);
                }
            }
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int width = getMeasuredWidth();
        boolean measure = false;
        int widthMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(width, BasicMeasure.EXACTLY);
        if (!fixedWidth && widthMode == Integer.MIN_VALUE) {
            TypedValue tv = isPortrait ? this.mMinWidthMinor : this.mMinWidthMajor;
            if (tv != null && tv.type != 0) {
                int min = 0;
                if (tv.type != 5) {
                    if (tv.type == 6) {
                        min = (int) tv.getFraction(metrics.widthPixels, metrics.widthPixels);
                    }
                } else {
                    min = (int) tv.getDimension(metrics);
                }
                if (min > 0) {
                    min -= this.mDecorPadding.left + this.mDecorPadding.right;
                }
                if (width < min) {
                    widthMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(min, BasicMeasure.EXACTLY);
                    measure = true;
                }
            }
        }
        if (measure) {
            super.onMeasure(widthMeasureSpec2, heightMeasureSpec);
        }
    }

    public TypedValue getMinWidthMajor() {
        if (this.mMinWidthMajor == null) {
            this.mMinWidthMajor = new TypedValue();
        }
        return this.mMinWidthMajor;
    }

    public TypedValue getMinWidthMinor() {
        if (this.mMinWidthMinor == null) {
            this.mMinWidthMinor = new TypedValue();
        }
        return this.mMinWidthMinor;
    }

    public TypedValue getFixedWidthMajor() {
        if (this.mFixedWidthMajor == null) {
            this.mFixedWidthMajor = new TypedValue();
        }
        return this.mFixedWidthMajor;
    }

    public TypedValue getFixedWidthMinor() {
        if (this.mFixedWidthMinor == null) {
            this.mFixedWidthMinor = new TypedValue();
        }
        return this.mFixedWidthMinor;
    }

    public TypedValue getFixedHeightMajor() {
        if (this.mFixedHeightMajor == null) {
            this.mFixedHeightMajor = new TypedValue();
        }
        return this.mFixedHeightMajor;
    }

    public TypedValue getFixedHeightMinor() {
        if (this.mFixedHeightMinor == null) {
            this.mFixedHeightMinor = new TypedValue();
        }
        return this.mFixedHeightMinor;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        OnAttachListener onAttachListener = this.mAttachListener;
        if (onAttachListener != null) {
            onAttachListener.onAttachedFromWindow();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        OnAttachListener onAttachListener = this.mAttachListener;
        if (onAttachListener != null) {
            onAttachListener.onDetachedFromWindow();
        }
    }
}
