package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.View;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.core.widgets.HelperWidget;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.ConstraintSet;
import androidx.constraintlayout.widget.R;
import androidx.constraintlayout.widget.VirtualLayout;
/* loaded from: classes.dex */
public class Flow extends VirtualLayout {
    public static final int CHAIN_PACKED = 2;
    public static final int CHAIN_SPREAD = 0;
    public static final int CHAIN_SPREAD_INSIDE = 1;
    public static final int HORIZONTAL = 0;
    public static final int HORIZONTAL_ALIGN_CENTER = 2;
    public static final int HORIZONTAL_ALIGN_END = 1;
    public static final int HORIZONTAL_ALIGN_START = 0;
    private static final String TAG = "Flow";
    public static final int VERTICAL = 1;
    public static final int VERTICAL_ALIGN_BASELINE = 3;
    public static final int VERTICAL_ALIGN_BOTTOM = 1;
    public static final int VERTICAL_ALIGN_CENTER = 2;
    public static final int VERTICAL_ALIGN_TOP = 0;
    public static final int WRAP_ALIGNED = 2;
    public static final int WRAP_CHAIN = 1;
    public static final int WRAP_NONE = 0;
    private androidx.constraintlayout.core.widgets.Flow mFlow;

    public Flow(Context context) {
        super(context);
    }

    public Flow(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public Flow(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void resolveRtl(ConstraintWidget widget, boolean isRtl) {
        this.mFlow.applyRtl(isRtl);
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        onMeasure(this.mFlow, widthMeasureSpec, heightMeasureSpec);
    }

    @Override // androidx.constraintlayout.widget.VirtualLayout
    public void onMeasure(androidx.constraintlayout.core.widgets.VirtualLayout layout, int widthMeasureSpec, int heightMeasureSpec) {
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        if (layout != null) {
            layout.measure(widthMode, widthSize, heightMode, heightSize);
            setMeasuredDimension(layout.getMeasuredWidth(), layout.getMeasuredHeight());
            return;
        }
        setMeasuredDimension(0, 0);
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void loadParameters(ConstraintSet.Constraint constraint, HelperWidget child, ConstraintLayout.LayoutParams layoutParams, SparseArray<ConstraintWidget> mapIdToWidget) {
        super.loadParameters(constraint, child, layoutParams, mapIdToWidget);
        if (child instanceof androidx.constraintlayout.core.widgets.Flow) {
            androidx.constraintlayout.core.widgets.Flow flow = (androidx.constraintlayout.core.widgets.Flow) child;
            if (layoutParams.orientation != -1) {
                flow.setOrientation(layoutParams.orientation);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.VirtualLayout, androidx.constraintlayout.widget.ConstraintHelper
    public void init(AttributeSet attrs) {
        super.init(attrs);
        this.mFlow = new androidx.constraintlayout.core.widgets.Flow();
        if (attrs != null) {
            TypedArray a = getContext().obtainStyledAttributes(attrs, R.styleable.ConstraintLayout_Layout);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.ConstraintLayout_Layout_android_orientation) {
                    this.mFlow.setOrientation(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_padding) {
                    this.mFlow.setPadding(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingStart) {
                    if (Build.VERSION.SDK_INT >= 17) {
                        this.mFlow.setPaddingStart(a.getDimensionPixelSize(attr, 0));
                    }
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingEnd) {
                    if (Build.VERSION.SDK_INT >= 17) {
                        this.mFlow.setPaddingEnd(a.getDimensionPixelSize(attr, 0));
                    }
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingLeft) {
                    this.mFlow.setPaddingLeft(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingTop) {
                    this.mFlow.setPaddingTop(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingRight) {
                    this.mFlow.setPaddingRight(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_paddingBottom) {
                    this.mFlow.setPaddingBottom(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_wrapMode) {
                    this.mFlow.setWrapMode(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_horizontalStyle) {
                    this.mFlow.setHorizontalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_verticalStyle) {
                    this.mFlow.setVerticalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_firstHorizontalStyle) {
                    this.mFlow.setFirstHorizontalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_lastHorizontalStyle) {
                    this.mFlow.setLastHorizontalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_firstVerticalStyle) {
                    this.mFlow.setFirstVerticalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_lastVerticalStyle) {
                    this.mFlow.setLastVerticalStyle(a.getInt(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_horizontalBias) {
                    this.mFlow.setHorizontalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_firstHorizontalBias) {
                    this.mFlow.setFirstHorizontalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_lastHorizontalBias) {
                    this.mFlow.setLastHorizontalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_firstVerticalBias) {
                    this.mFlow.setFirstVerticalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_lastVerticalBias) {
                    this.mFlow.setLastVerticalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_verticalBias) {
                    this.mFlow.setVerticalBias(a.getFloat(attr, 0.5f));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_horizontalAlign) {
                    this.mFlow.setHorizontalAlign(a.getInt(attr, 2));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_verticalAlign) {
                    this.mFlow.setVerticalAlign(a.getInt(attr, 2));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_horizontalGap) {
                    this.mFlow.setHorizontalGap(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_verticalGap) {
                    this.mFlow.setVerticalGap(a.getDimensionPixelSize(attr, 0));
                } else if (attr == R.styleable.ConstraintLayout_Layout_flow_maxElementsWrap) {
                    this.mFlow.setMaxElementsWrap(a.getInt(attr, -1));
                }
            }
            a.recycle();
        }
        this.mHelperWidget = this.mFlow;
        validateParams();
    }

    public void setOrientation(int orientation) {
        this.mFlow.setOrientation(orientation);
        requestLayout();
    }

    public void setPadding(int padding) {
        this.mFlow.setPadding(padding);
        requestLayout();
    }

    public void setPaddingLeft(int paddingLeft) {
        this.mFlow.setPaddingLeft(paddingLeft);
        requestLayout();
    }

    public void setPaddingTop(int paddingTop) {
        this.mFlow.setPaddingTop(paddingTop);
        requestLayout();
    }

    public void setPaddingRight(int paddingRight) {
        this.mFlow.setPaddingRight(paddingRight);
        requestLayout();
    }

    public void setPaddingBottom(int paddingBottom) {
        this.mFlow.setPaddingBottom(paddingBottom);
        requestLayout();
    }

    public void setLastHorizontalStyle(int style) {
        this.mFlow.setLastHorizontalStyle(style);
        requestLayout();
    }

    public void setLastVerticalStyle(int style) {
        this.mFlow.setLastVerticalStyle(style);
        requestLayout();
    }

    public void setLastHorizontalBias(float bias) {
        this.mFlow.setLastHorizontalBias(bias);
        requestLayout();
    }

    public void setLastVerticalBias(float bias) {
        this.mFlow.setLastVerticalBias(bias);
        requestLayout();
    }

    public void setWrapMode(int mode) {
        this.mFlow.setWrapMode(mode);
        requestLayout();
    }

    public void setHorizontalStyle(int style) {
        this.mFlow.setHorizontalStyle(style);
        requestLayout();
    }

    public void setVerticalStyle(int style) {
        this.mFlow.setVerticalStyle(style);
        requestLayout();
    }

    public void setHorizontalBias(float bias) {
        this.mFlow.setHorizontalBias(bias);
        requestLayout();
    }

    public void setVerticalBias(float bias) {
        this.mFlow.setVerticalBias(bias);
        requestLayout();
    }

    public void setFirstHorizontalStyle(int style) {
        this.mFlow.setFirstHorizontalStyle(style);
        requestLayout();
    }

    public void setFirstVerticalStyle(int style) {
        this.mFlow.setFirstVerticalStyle(style);
        requestLayout();
    }

    public void setFirstHorizontalBias(float bias) {
        this.mFlow.setFirstHorizontalBias(bias);
        requestLayout();
    }

    public void setFirstVerticalBias(float bias) {
        this.mFlow.setFirstVerticalBias(bias);
        requestLayout();
    }

    public void setHorizontalAlign(int align) {
        this.mFlow.setHorizontalAlign(align);
        requestLayout();
    }

    public void setVerticalAlign(int align) {
        this.mFlow.setVerticalAlign(align);
        requestLayout();
    }

    public void setHorizontalGap(int gap) {
        this.mFlow.setHorizontalGap(gap);
        requestLayout();
    }

    public void setVerticalGap(int gap) {
        this.mFlow.setVerticalGap(gap);
        requestLayout();
    }

    public void setMaxElementsWrap(int max) {
        this.mFlow.setMaxElementsWrap(max);
        requestLayout();
    }
}
