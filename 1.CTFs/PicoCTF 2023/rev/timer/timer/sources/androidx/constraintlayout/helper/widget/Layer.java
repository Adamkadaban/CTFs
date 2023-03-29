package androidx.constraintlayout.helper.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import androidx.constraintlayout.core.widgets.ConstraintWidget;
import androidx.constraintlayout.widget.ConstraintHelper;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.R;
/* loaded from: classes.dex */
public class Layer extends ConstraintHelper {
    private static final String TAG = "Layer";
    private boolean mApplyElevationOnAttach;
    private boolean mApplyVisibilityOnAttach;
    protected float mComputedCenterX;
    protected float mComputedCenterY;
    protected float mComputedMaxX;
    protected float mComputedMaxY;
    protected float mComputedMinX;
    protected float mComputedMinY;
    ConstraintLayout mContainer;
    private float mGroupRotateAngle;
    boolean mNeedBounds;
    private float mRotationCenterX;
    private float mRotationCenterY;
    private float mScaleX;
    private float mScaleY;
    private float mShiftX;
    private float mShiftY;
    View[] mViews;

    public Layer(Context context) {
        super(context);
        this.mRotationCenterX = Float.NaN;
        this.mRotationCenterY = Float.NaN;
        this.mGroupRotateAngle = Float.NaN;
        this.mScaleX = 1.0f;
        this.mScaleY = 1.0f;
        this.mComputedCenterX = Float.NaN;
        this.mComputedCenterY = Float.NaN;
        this.mComputedMaxX = Float.NaN;
        this.mComputedMaxY = Float.NaN;
        this.mComputedMinX = Float.NaN;
        this.mComputedMinY = Float.NaN;
        this.mNeedBounds = true;
        this.mViews = null;
        this.mShiftX = 0.0f;
        this.mShiftY = 0.0f;
    }

    public Layer(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mRotationCenterX = Float.NaN;
        this.mRotationCenterY = Float.NaN;
        this.mGroupRotateAngle = Float.NaN;
        this.mScaleX = 1.0f;
        this.mScaleY = 1.0f;
        this.mComputedCenterX = Float.NaN;
        this.mComputedCenterY = Float.NaN;
        this.mComputedMaxX = Float.NaN;
        this.mComputedMaxY = Float.NaN;
        this.mComputedMinX = Float.NaN;
        this.mComputedMinY = Float.NaN;
        this.mNeedBounds = true;
        this.mViews = null;
        this.mShiftX = 0.0f;
        this.mShiftY = 0.0f;
    }

    public Layer(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mRotationCenterX = Float.NaN;
        this.mRotationCenterY = Float.NaN;
        this.mGroupRotateAngle = Float.NaN;
        this.mScaleX = 1.0f;
        this.mScaleY = 1.0f;
        this.mComputedCenterX = Float.NaN;
        this.mComputedCenterY = Float.NaN;
        this.mComputedMaxX = Float.NaN;
        this.mComputedMaxY = Float.NaN;
        this.mComputedMinX = Float.NaN;
        this.mComputedMinY = Float.NaN;
        this.mNeedBounds = true;
        this.mViews = null;
        this.mShiftX = 0.0f;
        this.mShiftY = 0.0f;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void init(AttributeSet attrs) {
        super.init(attrs);
        this.mUseViewMeasure = false;
        if (attrs != null) {
            TypedArray a = getContext().obtainStyledAttributes(attrs, R.styleable.ConstraintLayout_Layout);
            int N = a.getIndexCount();
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.ConstraintLayout_Layout_android_visibility) {
                    this.mApplyVisibilityOnAttach = true;
                } else if (attr == R.styleable.ConstraintLayout_Layout_android_elevation) {
                    this.mApplyElevationOnAttach = true;
                }
            }
            a.recycle();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintHelper, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mContainer = (ConstraintLayout) getParent();
        if (this.mApplyVisibilityOnAttach || this.mApplyElevationOnAttach) {
            int visibility = getVisibility();
            float elevation = 0.0f;
            if (Build.VERSION.SDK_INT >= 21) {
                elevation = getElevation();
            }
            for (int i = 0; i < this.mCount; i++) {
                int id = this.mIds[i];
                View view = this.mContainer.getViewById(id);
                if (view != null) {
                    if (this.mApplyVisibilityOnAttach) {
                        view.setVisibility(visibility);
                    }
                    if (this.mApplyElevationOnAttach && elevation > 0.0f && Build.VERSION.SDK_INT >= 21) {
                        view.setTranslationZ(view.getTranslationZ() + elevation);
                    }
                }
            }
        }
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void updatePreDraw(ConstraintLayout container) {
        this.mContainer = container;
        float rotate = getRotation();
        if (rotate == 0.0f) {
            if (!Float.isNaN(this.mGroupRotateAngle)) {
                this.mGroupRotateAngle = rotate;
                return;
            }
            return;
        }
        this.mGroupRotateAngle = rotate;
    }

    @Override // android.view.View
    public void setRotation(float angle) {
        this.mGroupRotateAngle = angle;
        transform();
    }

    @Override // android.view.View
    public void setScaleX(float scaleX) {
        this.mScaleX = scaleX;
        transform();
    }

    @Override // android.view.View
    public void setScaleY(float scaleY) {
        this.mScaleY = scaleY;
        transform();
    }

    @Override // android.view.View
    public void setPivotX(float pivotX) {
        this.mRotationCenterX = pivotX;
        transform();
    }

    @Override // android.view.View
    public void setPivotY(float pivotY) {
        this.mRotationCenterY = pivotY;
        transform();
    }

    @Override // android.view.View
    public void setTranslationX(float dx) {
        this.mShiftX = dx;
        transform();
    }

    @Override // android.view.View
    public void setTranslationY(float dy) {
        this.mShiftY = dy;
        transform();
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        applyLayoutFeatures();
    }

    @Override // android.view.View
    public void setElevation(float elevation) {
        super.setElevation(elevation);
        applyLayoutFeatures();
    }

    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void updatePostLayout(ConstraintLayout container) {
        reCacheViews();
        this.mComputedCenterX = Float.NaN;
        this.mComputedCenterY = Float.NaN;
        ConstraintLayout.LayoutParams params = (ConstraintLayout.LayoutParams) getLayoutParams();
        ConstraintWidget widget = params.getConstraintWidget();
        widget.setWidth(0);
        widget.setHeight(0);
        calcCenters();
        int left = ((int) this.mComputedMinX) - getPaddingLeft();
        int top = ((int) this.mComputedMinY) - getPaddingTop();
        int right = ((int) this.mComputedMaxX) + getPaddingRight();
        int bottom = ((int) this.mComputedMaxY) + getPaddingBottom();
        layout(left, top, right, bottom);
        transform();
    }

    private void reCacheViews() {
        if (this.mContainer == null || this.mCount == 0) {
            return;
        }
        View[] viewArr = this.mViews;
        if (viewArr == null || viewArr.length != this.mCount) {
            this.mViews = new View[this.mCount];
        }
        for (int i = 0; i < this.mCount; i++) {
            int id = this.mIds[i];
            this.mViews[i] = this.mContainer.getViewById(id);
        }
    }

    protected void calcCenters() {
        if (this.mContainer == null) {
            return;
        }
        if (!this.mNeedBounds && !Float.isNaN(this.mComputedCenterX) && !Float.isNaN(this.mComputedCenterY)) {
            return;
        }
        if (Float.isNaN(this.mRotationCenterX) || Float.isNaN(this.mRotationCenterY)) {
            View[] views = getViews(this.mContainer);
            int minx = views[0].getLeft();
            int miny = views[0].getTop();
            int maxx = views[0].getRight();
            int maxy = views[0].getBottom();
            for (int i = 0; i < this.mCount; i++) {
                View view = views[i];
                minx = Math.min(minx, view.getLeft());
                miny = Math.min(miny, view.getTop());
                maxx = Math.max(maxx, view.getRight());
                maxy = Math.max(maxy, view.getBottom());
            }
            this.mComputedMaxX = maxx;
            this.mComputedMaxY = maxy;
            this.mComputedMinX = minx;
            this.mComputedMinY = miny;
            if (Float.isNaN(this.mRotationCenterX)) {
                this.mComputedCenterX = (minx + maxx) / 2;
            } else {
                this.mComputedCenterX = this.mRotationCenterX;
            }
            if (Float.isNaN(this.mRotationCenterY)) {
                this.mComputedCenterY = (miny + maxy) / 2;
                return;
            } else {
                this.mComputedCenterY = this.mRotationCenterY;
                return;
            }
        }
        this.mComputedCenterY = this.mRotationCenterY;
        this.mComputedCenterX = this.mRotationCenterX;
    }

    private void transform() {
        if (this.mContainer == null) {
            return;
        }
        if (this.mViews == null) {
            reCacheViews();
        }
        calcCenters();
        double rad = Float.isNaN(this.mGroupRotateAngle) ? 0.0d : Math.toRadians(this.mGroupRotateAngle);
        float sin = (float) Math.sin(rad);
        float cos = (float) Math.cos(rad);
        float f = this.mScaleX;
        float m11 = f * cos;
        float f2 = this.mScaleY;
        float m12 = (-f2) * sin;
        float m21 = f * sin;
        float m22 = f2 * cos;
        int i = 0;
        while (i < this.mCount) {
            View view = this.mViews[i];
            int x = (view.getLeft() + view.getRight()) / 2;
            int y = (view.getTop() + view.getBottom()) / 2;
            float dx = x - this.mComputedCenterX;
            float dy = y - this.mComputedCenterY;
            double rad2 = rad;
            float shiftx = (((m11 * dx) + (m12 * dy)) - dx) + this.mShiftX;
            float shifty = (((m21 * dx) + (m22 * dy)) - dy) + this.mShiftY;
            view.setTranslationX(shiftx);
            view.setTranslationY(shifty);
            view.setScaleY(this.mScaleY);
            view.setScaleX(this.mScaleX);
            if (!Float.isNaN(this.mGroupRotateAngle)) {
                view.setRotation(this.mGroupRotateAngle);
            }
            i++;
            rad = rad2;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.constraintlayout.widget.ConstraintHelper
    public void applyLayoutFeaturesInConstraintSet(ConstraintLayout container) {
        applyLayoutFeatures(container);
    }
}
