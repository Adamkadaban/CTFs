package com.google.android.material.shape;

import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.ScrollView;
/* loaded from: classes.dex */
public class InterpolateOnScrollPositionChangeHelper {
    private ScrollView containingScrollView;
    private MaterialShapeDrawable materialShapeDrawable;
    private View shapedView;
    private final int[] scrollLocation = new int[2];
    private final int[] containerLocation = new int[2];
    private final ViewTreeObserver.OnScrollChangedListener scrollChangedListener = new ViewTreeObserver.OnScrollChangedListener() { // from class: com.google.android.material.shape.InterpolateOnScrollPositionChangeHelper.1
        @Override // android.view.ViewTreeObserver.OnScrollChangedListener
        public void onScrollChanged() {
            InterpolateOnScrollPositionChangeHelper.this.updateInterpolationForScreenPosition();
        }
    };

    public InterpolateOnScrollPositionChangeHelper(View shapedView, MaterialShapeDrawable materialShapeDrawable, ScrollView containingScrollView) {
        this.shapedView = shapedView;
        this.materialShapeDrawable = materialShapeDrawable;
        this.containingScrollView = containingScrollView;
    }

    public void setMaterialShapeDrawable(MaterialShapeDrawable materialShapeDrawable) {
        this.materialShapeDrawable = materialShapeDrawable;
    }

    public void setContainingScrollView(ScrollView containingScrollView) {
        this.containingScrollView = containingScrollView;
    }

    public void startListeningForScrollChanges(ViewTreeObserver viewTreeObserver) {
        viewTreeObserver.addOnScrollChangedListener(this.scrollChangedListener);
    }

    public void stopListeningForScrollChanges(ViewTreeObserver viewTreeObserver) {
        viewTreeObserver.removeOnScrollChangedListener(this.scrollChangedListener);
    }

    public void updateInterpolationForScreenPosition() {
        ScrollView scrollView = this.containingScrollView;
        if (scrollView == null) {
            return;
        }
        if (scrollView.getChildCount() == 0) {
            throw new IllegalStateException("Scroll bar must contain a child to calculate interpolation.");
        }
        this.containingScrollView.getLocationInWindow(this.scrollLocation);
        this.containingScrollView.getChildAt(0).getLocationInWindow(this.containerLocation);
        int y = (this.shapedView.getTop() - this.scrollLocation[1]) + this.containerLocation[1];
        int viewHeight = this.shapedView.getHeight();
        int windowHeight = this.containingScrollView.getHeight();
        if (y < 0) {
            this.materialShapeDrawable.setInterpolation(Math.max(0.0f, Math.min(1.0f, (y / viewHeight) + 1.0f)));
            this.shapedView.invalidate();
        } else if (y + viewHeight > windowHeight) {
            int distanceOffScreen = (y + viewHeight) - windowHeight;
            this.materialShapeDrawable.setInterpolation(Math.max(0.0f, Math.min(1.0f, 1.0f - (distanceOffScreen / viewHeight))));
            this.shapedView.invalidate();
        } else if (this.materialShapeDrawable.getInterpolation() != 1.0f) {
            this.materialShapeDrawable.setInterpolation(1.0f);
            this.shapedView.invalidate();
        }
    }
}
