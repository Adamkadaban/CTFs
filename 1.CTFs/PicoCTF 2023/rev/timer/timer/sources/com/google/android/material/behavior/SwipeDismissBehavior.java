package com.google.android.material.behavior;

import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityViewCommand;
import androidx.customview.widget.ViewDragHelper;
/* loaded from: classes.dex */
public class SwipeDismissBehavior<V extends View> extends CoordinatorLayout.Behavior<V> {
    private static final float DEFAULT_ALPHA_END_DISTANCE = 0.5f;
    private static final float DEFAULT_ALPHA_START_DISTANCE = 0.0f;
    private static final float DEFAULT_DRAG_DISMISS_THRESHOLD = 0.5f;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_IDLE = 0;
    public static final int STATE_SETTLING = 2;
    public static final int SWIPE_DIRECTION_ANY = 2;
    public static final int SWIPE_DIRECTION_END_TO_START = 1;
    public static final int SWIPE_DIRECTION_START_TO_END = 0;
    private boolean interceptingEvents;
    OnDismissListener listener;
    private boolean sensitivitySet;
    ViewDragHelper viewDragHelper;
    private float sensitivity = 0.0f;
    int swipeDirection = 2;
    float dragDismissThreshold = 0.5f;
    float alphaStartSwipeDistance = 0.0f;
    float alphaEndSwipeDistance = 0.5f;
    private final ViewDragHelper.Callback dragCallback = new ViewDragHelper.Callback() { // from class: com.google.android.material.behavior.SwipeDismissBehavior.1
        private static final int INVALID_POINTER_ID = -1;
        private int activePointerId = -1;
        private int originalCapturedViewLeft;

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public boolean tryCaptureView(View child, int pointerId) {
            int i = this.activePointerId;
            return (i == -1 || i == pointerId) && SwipeDismissBehavior.this.canSwipeDismissView(child);
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewCaptured(View capturedChild, int activePointerId) {
            this.activePointerId = activePointerId;
            this.originalCapturedViewLeft = capturedChild.getLeft();
            ViewParent parent = capturedChild.getParent();
            if (parent != null) {
                parent.requestDisallowInterceptTouchEvent(true);
            }
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewDragStateChanged(int state) {
            if (SwipeDismissBehavior.this.listener != null) {
                SwipeDismissBehavior.this.listener.onDragStateChanged(state);
            }
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewReleased(View child, float xvel, float yvel) {
            int targetLeft;
            int i;
            this.activePointerId = -1;
            int childWidth = child.getWidth();
            boolean dismiss = false;
            if (shouldDismiss(child, xvel)) {
                int left = child.getLeft();
                int i2 = this.originalCapturedViewLeft;
                if (left < i2) {
                    i = i2 - childWidth;
                } else {
                    i = i2 + childWidth;
                }
                targetLeft = i;
                dismiss = true;
            } else {
                targetLeft = this.originalCapturedViewLeft;
            }
            if (SwipeDismissBehavior.this.viewDragHelper.settleCapturedViewAt(targetLeft, child.getTop())) {
                ViewCompat.postOnAnimation(child, new SettleRunnable(child, dismiss));
            } else if (dismiss && SwipeDismissBehavior.this.listener != null) {
                SwipeDismissBehavior.this.listener.onDismiss(child);
            }
        }

        private boolean shouldDismiss(View child, float xvel) {
            if (xvel != 0.0f) {
                boolean isRtl = ViewCompat.getLayoutDirection(child) == 1;
                if (SwipeDismissBehavior.this.swipeDirection == 2) {
                    return true;
                }
                if (SwipeDismissBehavior.this.swipeDirection == 0) {
                    if (isRtl) {
                        if (xvel >= 0.0f) {
                            return false;
                        }
                    } else if (xvel <= 0.0f) {
                        return false;
                    }
                    return true;
                } else if (SwipeDismissBehavior.this.swipeDirection == 1) {
                    if (isRtl) {
                        if (xvel <= 0.0f) {
                            return false;
                        }
                    } else if (xvel >= 0.0f) {
                        return false;
                    }
                    return true;
                } else {
                    return false;
                }
            }
            int distance = child.getLeft() - this.originalCapturedViewLeft;
            int thresholdDistance = Math.round(child.getWidth() * SwipeDismissBehavior.this.dragDismissThreshold);
            return Math.abs(distance) >= thresholdDistance;
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int getViewHorizontalDragRange(View child) {
            return child.getWidth();
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int clampViewPositionHorizontal(View child, int left, int dx) {
            int min;
            int max;
            boolean isRtl = ViewCompat.getLayoutDirection(child) == 1;
            if (SwipeDismissBehavior.this.swipeDirection == 0) {
                if (isRtl) {
                    min = this.originalCapturedViewLeft - child.getWidth();
                    max = this.originalCapturedViewLeft;
                } else {
                    min = this.originalCapturedViewLeft;
                    max = this.originalCapturedViewLeft + child.getWidth();
                }
            } else if (SwipeDismissBehavior.this.swipeDirection == 1) {
                if (isRtl) {
                    min = this.originalCapturedViewLeft;
                    max = this.originalCapturedViewLeft + child.getWidth();
                } else {
                    int min2 = this.originalCapturedViewLeft;
                    min = min2 - child.getWidth();
                    max = this.originalCapturedViewLeft;
                }
            } else {
                int min3 = this.originalCapturedViewLeft;
                min = min3 - child.getWidth();
                max = this.originalCapturedViewLeft + child.getWidth();
            }
            return SwipeDismissBehavior.clamp(min, left, max);
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public int clampViewPositionVertical(View child, int top, int dy) {
            return child.getTop();
        }

        @Override // androidx.customview.widget.ViewDragHelper.Callback
        public void onViewPositionChanged(View child, int left, int top, int dx, int dy) {
            float startAlphaDistance = this.originalCapturedViewLeft + (child.getWidth() * SwipeDismissBehavior.this.alphaStartSwipeDistance);
            float endAlphaDistance = this.originalCapturedViewLeft + (child.getWidth() * SwipeDismissBehavior.this.alphaEndSwipeDistance);
            if (left <= startAlphaDistance) {
                child.setAlpha(1.0f);
            } else if (left >= endAlphaDistance) {
                child.setAlpha(0.0f);
            } else {
                float distance = SwipeDismissBehavior.fraction(startAlphaDistance, endAlphaDistance, left);
                child.setAlpha(SwipeDismissBehavior.clamp(0.0f, 1.0f - distance, 1.0f));
            }
        }
    };

    /* loaded from: classes.dex */
    public interface OnDismissListener {
        void onDismiss(View view);

        void onDragStateChanged(int i);
    }

    public void setListener(OnDismissListener listener) {
        this.listener = listener;
    }

    public OnDismissListener getListener() {
        return this.listener;
    }

    public void setSwipeDirection(int direction) {
        this.swipeDirection = direction;
    }

    public void setDragDismissDistance(float distance) {
        this.dragDismissThreshold = clamp(0.0f, distance, 1.0f);
    }

    public void setStartAlphaSwipeDistance(float fraction) {
        this.alphaStartSwipeDistance = clamp(0.0f, fraction, 1.0f);
    }

    public void setEndAlphaSwipeDistance(float fraction) {
        this.alphaEndSwipeDistance = clamp(0.0f, fraction, 1.0f);
    }

    public void setSensitivity(float sensitivity) {
        this.sensitivity = sensitivity;
        this.sensitivitySet = true;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        boolean handled = super.onLayoutChild(parent, child, layoutDirection);
        if (ViewCompat.getImportantForAccessibility(child) == 0) {
            ViewCompat.setImportantForAccessibility(child, 1);
            updateAccessibilityActions(child);
        }
        return handled;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onInterceptTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        boolean dispatchEventToHelper = this.interceptingEvents;
        switch (event.getActionMasked()) {
            case 0:
                this.interceptingEvents = parent.isPointInChildBounds(child, (int) event.getX(), (int) event.getY());
                dispatchEventToHelper = this.interceptingEvents;
                break;
            case 1:
            case 3:
                this.interceptingEvents = false;
                break;
        }
        if (dispatchEventToHelper) {
            ensureViewDragHelper(parent);
            return this.viewDragHelper.shouldInterceptTouchEvent(event);
        }
        return false;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        ViewDragHelper viewDragHelper = this.viewDragHelper;
        if (viewDragHelper != null) {
            viewDragHelper.processTouchEvent(event);
            return true;
        }
        return false;
    }

    public boolean canSwipeDismissView(View view) {
        return true;
    }

    private void ensureViewDragHelper(ViewGroup parent) {
        ViewDragHelper create;
        if (this.viewDragHelper == null) {
            if (this.sensitivitySet) {
                create = ViewDragHelper.create(parent, this.sensitivity, this.dragCallback);
            } else {
                create = ViewDragHelper.create(parent, this.dragCallback);
            }
            this.viewDragHelper = create;
        }
    }

    /* loaded from: classes.dex */
    private class SettleRunnable implements Runnable {
        private final boolean dismiss;
        private final View view;

        SettleRunnable(View view, boolean dismiss) {
            this.view = view;
            this.dismiss = dismiss;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SwipeDismissBehavior.this.viewDragHelper != null && SwipeDismissBehavior.this.viewDragHelper.continueSettling(true)) {
                ViewCompat.postOnAnimation(this.view, this);
            } else if (this.dismiss && SwipeDismissBehavior.this.listener != null) {
                SwipeDismissBehavior.this.listener.onDismiss(this.view);
            }
        }
    }

    private void updateAccessibilityActions(View child) {
        ViewCompat.removeAccessibilityAction(child, 1048576);
        if (canSwipeDismissView(child)) {
            ViewCompat.replaceAccessibilityAction(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_DISMISS, null, new AccessibilityViewCommand() { // from class: com.google.android.material.behavior.SwipeDismissBehavior.2
                @Override // androidx.core.view.accessibility.AccessibilityViewCommand
                public boolean perform(View view, AccessibilityViewCommand.CommandArguments arguments) {
                    boolean dismissToLeft = false;
                    if (SwipeDismissBehavior.this.canSwipeDismissView(view)) {
                        boolean isRtl = ViewCompat.getLayoutDirection(view) == 1;
                        if ((SwipeDismissBehavior.this.swipeDirection == 0 && isRtl) || (SwipeDismissBehavior.this.swipeDirection == 1 && !isRtl)) {
                            dismissToLeft = true;
                        }
                        int offset = view.getWidth();
                        if (dismissToLeft) {
                            offset = -offset;
                        }
                        ViewCompat.offsetLeftAndRight(view, offset);
                        view.setAlpha(0.0f);
                        if (SwipeDismissBehavior.this.listener != null) {
                            SwipeDismissBehavior.this.listener.onDismiss(view);
                        }
                        return true;
                    }
                    return false;
                }
            });
        }
    }

    static float clamp(float min, float value, float max) {
        return Math.min(Math.max(min, value), max);
    }

    static int clamp(int min, int value, int max) {
        return Math.min(Math.max(min, value), max);
    }

    public int getDragState() {
        ViewDragHelper viewDragHelper = this.viewDragHelper;
        if (viewDragHelper != null) {
            return viewDragHelper.getViewDragState();
        }
        return 0;
    }

    static float fraction(float startValue, float endValue, float value) {
        return (value - startValue) / (endValue - startValue);
    }
}
