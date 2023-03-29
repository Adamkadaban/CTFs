package com.google.android.material.bottomsheet;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.graphics.Insets;
import androidx.core.math.MathUtils;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityViewCommand;
import androidx.customview.view.AbsSavedState;
import androidx.customview.widget.ViewDragHelper;
import com.google.android.material.R;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class BottomSheetBehavior<V extends View> extends CoordinatorLayout.Behavior<V> {
    private static final int CORNER_ANIMATION_DURATION = 500;
    private static final int DEF_STYLE_RES = R.style.Widget_Design_BottomSheet_Modal;
    private static final float HIDE_FRICTION = 0.1f;
    private static final float HIDE_THRESHOLD = 0.5f;
    private static final int NO_MAX_SIZE = -1;
    public static final int PEEK_HEIGHT_AUTO = -1;
    public static final int SAVE_ALL = -1;
    public static final int SAVE_FIT_TO_CONTENTS = 2;
    public static final int SAVE_HIDEABLE = 4;
    public static final int SAVE_NONE = 0;
    public static final int SAVE_PEEK_HEIGHT = 1;
    public static final int SAVE_SKIP_COLLAPSED = 8;
    private static final int SIGNIFICANT_VEL_THRESHOLD = 500;
    public static final int STATE_COLLAPSED = 4;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_EXPANDED = 3;
    public static final int STATE_HALF_EXPANDED = 6;
    public static final int STATE_HIDDEN = 5;
    public static final int STATE_SETTLING = 2;
    private static final String TAG = "BottomSheetBehavior";
    int activePointerId;
    private ColorStateList backgroundTint;
    private final ArrayList<BottomSheetCallback> callbacks;
    private int childHeight;
    int collapsedOffset;
    private final ViewDragHelper.Callback dragCallback;
    private boolean draggable;
    float elevation;
    private int expandHalfwayActionId;
    int expandedOffset;
    private boolean fitToContents;
    int fitToContentsOffset;
    private int gestureInsetBottom;
    private boolean gestureInsetBottomIgnored;
    int halfExpandedOffset;
    float halfExpandedRatio;
    boolean hideable;
    private boolean ignoreEvents;
    private Map<View, Integer> importantForAccessibilityMap;
    private int initialY;
    private int insetBottom;
    private int insetTop;
    private ValueAnimator interpolatorAnimator;
    private boolean isShapeExpanded;
    private int lastNestedScrollDy;
    int lastStableState;
    private boolean marginLeftSystemWindowInsets;
    private boolean marginRightSystemWindowInsets;
    private boolean marginTopSystemWindowInsets;
    private MaterialShapeDrawable materialShapeDrawable;
    private int maxHeight;
    private int maxWidth;
    private float maximumVelocity;
    private boolean nestedScrolled;
    WeakReference<View> nestedScrollingChildRef;
    private boolean paddingBottomSystemWindowInsets;
    private boolean paddingLeftSystemWindowInsets;
    private boolean paddingRightSystemWindowInsets;
    private boolean paddingTopSystemWindowInsets;
    int parentHeight;
    int parentWidth;
    private int peekHeight;
    private boolean peekHeightAuto;
    private int peekHeightGestureInsetBuffer;
    private int peekHeightMin;
    private int saveFlags;
    private ShapeAppearanceModel shapeAppearanceModelDefault;
    private boolean skipCollapsed;
    int state;
    private final BottomSheetBehavior<V>.StateSettlingTracker stateSettlingTracker;
    boolean touchingScrollingChild;
    private boolean updateImportantForAccessibilityOnSiblings;
    private VelocityTracker velocityTracker;
    ViewDragHelper viewDragHelper;
    WeakReference<V> viewRef;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface SaveFlags {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface StableState {
    }

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface State {
    }

    /* loaded from: classes.dex */
    public static abstract class BottomSheetCallback {
        public abstract void onSlide(View view, float f);

        public abstract void onStateChanged(View view, int i);

        void onLayout(View bottomSheet) {
        }
    }

    public BottomSheetBehavior() {
        this.saveFlags = 0;
        this.fitToContents = true;
        this.updateImportantForAccessibilityOnSiblings = false;
        this.maxWidth = -1;
        this.maxHeight = -1;
        this.stateSettlingTracker = new StateSettlingTracker();
        this.halfExpandedRatio = 0.5f;
        this.elevation = -1.0f;
        this.draggable = true;
        this.state = 4;
        this.lastStableState = 4;
        this.callbacks = new ArrayList<>();
        this.expandHalfwayActionId = -1;
        this.dragCallback = new ViewDragHelper.Callback() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.4
            private long viewCapturedMillis;

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public boolean tryCaptureView(View child, int pointerId) {
                if (BottomSheetBehavior.this.state == 1 || BottomSheetBehavior.this.touchingScrollingChild) {
                    return false;
                }
                if (BottomSheetBehavior.this.state == 3 && BottomSheetBehavior.this.activePointerId == pointerId) {
                    View scroll = BottomSheetBehavior.this.nestedScrollingChildRef != null ? BottomSheetBehavior.this.nestedScrollingChildRef.get() : null;
                    if (scroll != null && scroll.canScrollVertically(-1)) {
                        return false;
                    }
                }
                this.viewCapturedMillis = System.currentTimeMillis();
                return BottomSheetBehavior.this.viewRef != null && BottomSheetBehavior.this.viewRef.get() == child;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
                BottomSheetBehavior.this.dispatchOnSlide(top);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewDragStateChanged(int state) {
                if (state == 1 && BottomSheetBehavior.this.draggable) {
                    BottomSheetBehavior.this.setStateInternal(1);
                }
            }

            private boolean releasedLow(View child) {
                return child.getTop() > (BottomSheetBehavior.this.parentHeight + BottomSheetBehavior.this.getExpandedOffset()) / 2;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewReleased(View releasedChild, float xvel, float yvel) {
                int targetState;
                int targetState2;
                if (yvel < 0.0f) {
                    if (BottomSheetBehavior.this.fitToContents) {
                        targetState = 3;
                    } else {
                        int currentTop = releasedChild.getTop();
                        long dragDurationMillis = System.currentTimeMillis() - this.viewCapturedMillis;
                        if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                            float yPositionPercentage = (currentTop * 100.0f) / BottomSheetBehavior.this.parentHeight;
                            if (BottomSheetBehavior.this.shouldExpandOnUpwardDrag(dragDurationMillis, yPositionPercentage)) {
                                targetState2 = 3;
                            } else {
                                targetState2 = 4;
                            }
                            targetState = targetState2;
                        } else if (currentTop > BottomSheetBehavior.this.halfExpandedOffset) {
                            targetState = 6;
                        } else {
                            targetState = 3;
                        }
                    }
                } else if (BottomSheetBehavior.this.hideable && BottomSheetBehavior.this.shouldHide(releasedChild, yvel)) {
                    if ((Math.abs(xvel) >= Math.abs(yvel) || yvel <= 500.0f) && !releasedLow(releasedChild)) {
                        if (BottomSheetBehavior.this.fitToContents) {
                            targetState = 3;
                        } else {
                            int targetState3 = releasedChild.getTop();
                            if (Math.abs(targetState3 - BottomSheetBehavior.this.getExpandedOffset()) < Math.abs(releasedChild.getTop() - BottomSheetBehavior.this.halfExpandedOffset)) {
                                targetState = 3;
                            } else {
                                targetState = 6;
                            }
                        }
                    } else {
                        targetState = 5;
                    }
                } else {
                    int targetState4 = (yvel > 0.0f ? 1 : (yvel == 0.0f ? 0 : -1));
                    if (targetState4 != 0 && Math.abs(xvel) <= Math.abs(yvel)) {
                        if (BottomSheetBehavior.this.fitToContents) {
                            targetState = 4;
                        } else {
                            int currentTop2 = releasedChild.getTop();
                            if (Math.abs(currentTop2 - BottomSheetBehavior.this.halfExpandedOffset) < Math.abs(currentTop2 - BottomSheetBehavior.this.collapsedOffset)) {
                                if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                    targetState = 4;
                                } else {
                                    targetState = 6;
                                }
                            } else {
                                targetState = 4;
                            }
                        }
                    } else {
                        int currentTop3 = releasedChild.getTop();
                        if (BottomSheetBehavior.this.fitToContents) {
                            if (Math.abs(currentTop3 - BottomSheetBehavior.this.fitToContentsOffset) < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                                targetState = 3;
                            } else {
                                targetState = 4;
                            }
                        } else if (currentTop3 < BottomSheetBehavior.this.halfExpandedOffset) {
                            if (currentTop3 < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                                targetState = 3;
                            } else if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                targetState = 4;
                            } else {
                                targetState = 6;
                            }
                        } else if (Math.abs(currentTop3 - BottomSheetBehavior.this.halfExpandedOffset) < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                            if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                targetState = 4;
                            } else {
                                targetState = 6;
                            }
                        } else {
                            targetState = 4;
                        }
                    }
                }
                BottomSheetBehavior bottomSheetBehavior = BottomSheetBehavior.this;
                bottomSheetBehavior.startSettling(releasedChild, targetState, bottomSheetBehavior.shouldSkipSmoothAnimation());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionVertical(View child, int top, int dy) {
                return MathUtils.clamp(top, BottomSheetBehavior.this.getExpandedOffset(), BottomSheetBehavior.this.hideable ? BottomSheetBehavior.this.parentHeight : BottomSheetBehavior.this.collapsedOffset);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionHorizontal(View child, int left, int dx) {
                return child.getLeft();
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int getViewVerticalDragRange(View child) {
                if (BottomSheetBehavior.this.hideable) {
                    return BottomSheetBehavior.this.parentHeight;
                }
                return BottomSheetBehavior.this.collapsedOffset;
            }
        };
    }

    public BottomSheetBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.saveFlags = 0;
        this.fitToContents = true;
        this.updateImportantForAccessibilityOnSiblings = false;
        this.maxWidth = -1;
        this.maxHeight = -1;
        this.stateSettlingTracker = new StateSettlingTracker();
        this.halfExpandedRatio = 0.5f;
        this.elevation = -1.0f;
        this.draggable = true;
        this.state = 4;
        this.lastStableState = 4;
        this.callbacks = new ArrayList<>();
        this.expandHalfwayActionId = -1;
        this.dragCallback = new ViewDragHelper.Callback() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.4
            private long viewCapturedMillis;

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public boolean tryCaptureView(View child, int pointerId) {
                if (BottomSheetBehavior.this.state == 1 || BottomSheetBehavior.this.touchingScrollingChild) {
                    return false;
                }
                if (BottomSheetBehavior.this.state == 3 && BottomSheetBehavior.this.activePointerId == pointerId) {
                    View scroll = BottomSheetBehavior.this.nestedScrollingChildRef != null ? BottomSheetBehavior.this.nestedScrollingChildRef.get() : null;
                    if (scroll != null && scroll.canScrollVertically(-1)) {
                        return false;
                    }
                }
                this.viewCapturedMillis = System.currentTimeMillis();
                return BottomSheetBehavior.this.viewRef != null && BottomSheetBehavior.this.viewRef.get() == child;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
                BottomSheetBehavior.this.dispatchOnSlide(top);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewDragStateChanged(int state) {
                if (state == 1 && BottomSheetBehavior.this.draggable) {
                    BottomSheetBehavior.this.setStateInternal(1);
                }
            }

            private boolean releasedLow(View child) {
                return child.getTop() > (BottomSheetBehavior.this.parentHeight + BottomSheetBehavior.this.getExpandedOffset()) / 2;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewReleased(View releasedChild, float xvel, float yvel) {
                int targetState;
                int targetState2;
                if (yvel < 0.0f) {
                    if (BottomSheetBehavior.this.fitToContents) {
                        targetState = 3;
                    } else {
                        int currentTop = releasedChild.getTop();
                        long dragDurationMillis = System.currentTimeMillis() - this.viewCapturedMillis;
                        if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                            float yPositionPercentage = (currentTop * 100.0f) / BottomSheetBehavior.this.parentHeight;
                            if (BottomSheetBehavior.this.shouldExpandOnUpwardDrag(dragDurationMillis, yPositionPercentage)) {
                                targetState2 = 3;
                            } else {
                                targetState2 = 4;
                            }
                            targetState = targetState2;
                        } else if (currentTop > BottomSheetBehavior.this.halfExpandedOffset) {
                            targetState = 6;
                        } else {
                            targetState = 3;
                        }
                    }
                } else if (BottomSheetBehavior.this.hideable && BottomSheetBehavior.this.shouldHide(releasedChild, yvel)) {
                    if ((Math.abs(xvel) >= Math.abs(yvel) || yvel <= 500.0f) && !releasedLow(releasedChild)) {
                        if (BottomSheetBehavior.this.fitToContents) {
                            targetState = 3;
                        } else {
                            int targetState3 = releasedChild.getTop();
                            if (Math.abs(targetState3 - BottomSheetBehavior.this.getExpandedOffset()) < Math.abs(releasedChild.getTop() - BottomSheetBehavior.this.halfExpandedOffset)) {
                                targetState = 3;
                            } else {
                                targetState = 6;
                            }
                        }
                    } else {
                        targetState = 5;
                    }
                } else {
                    int targetState4 = (yvel > 0.0f ? 1 : (yvel == 0.0f ? 0 : -1));
                    if (targetState4 != 0 && Math.abs(xvel) <= Math.abs(yvel)) {
                        if (BottomSheetBehavior.this.fitToContents) {
                            targetState = 4;
                        } else {
                            int currentTop2 = releasedChild.getTop();
                            if (Math.abs(currentTop2 - BottomSheetBehavior.this.halfExpandedOffset) < Math.abs(currentTop2 - BottomSheetBehavior.this.collapsedOffset)) {
                                if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                    targetState = 4;
                                } else {
                                    targetState = 6;
                                }
                            } else {
                                targetState = 4;
                            }
                        }
                    } else {
                        int currentTop3 = releasedChild.getTop();
                        if (BottomSheetBehavior.this.fitToContents) {
                            if (Math.abs(currentTop3 - BottomSheetBehavior.this.fitToContentsOffset) < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                                targetState = 3;
                            } else {
                                targetState = 4;
                            }
                        } else if (currentTop3 < BottomSheetBehavior.this.halfExpandedOffset) {
                            if (currentTop3 < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                                targetState = 3;
                            } else if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                targetState = 4;
                            } else {
                                targetState = 6;
                            }
                        } else if (Math.abs(currentTop3 - BottomSheetBehavior.this.halfExpandedOffset) < Math.abs(currentTop3 - BottomSheetBehavior.this.collapsedOffset)) {
                            if (BottomSheetBehavior.this.shouldSkipHalfExpandedStateWhenDragging()) {
                                targetState = 4;
                            } else {
                                targetState = 6;
                            }
                        } else {
                            targetState = 4;
                        }
                    }
                }
                BottomSheetBehavior bottomSheetBehavior = BottomSheetBehavior.this;
                bottomSheetBehavior.startSettling(releasedChild, targetState, bottomSheetBehavior.shouldSkipSmoothAnimation());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionVertical(View child, int top, int dy) {
                return MathUtils.clamp(top, BottomSheetBehavior.this.getExpandedOffset(), BottomSheetBehavior.this.hideable ? BottomSheetBehavior.this.parentHeight : BottomSheetBehavior.this.collapsedOffset);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionHorizontal(View child, int left, int dx) {
                return child.getLeft();
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int getViewVerticalDragRange(View child) {
                if (BottomSheetBehavior.this.hideable) {
                    return BottomSheetBehavior.this.parentHeight;
                }
                return BottomSheetBehavior.this.collapsedOffset;
            }
        };
        this.peekHeightGestureInsetBuffer = context.getResources().getDimensionPixelSize(R.dimen.mtrl_min_touch_target_size);
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.BottomSheetBehavior_Layout);
        if (a.hasValue(R.styleable.BottomSheetBehavior_Layout_backgroundTint)) {
            this.backgroundTint = MaterialResources.getColorStateList(context, a, R.styleable.BottomSheetBehavior_Layout_backgroundTint);
        }
        if (a.hasValue(R.styleable.BottomSheetBehavior_Layout_shapeAppearance)) {
            this.shapeAppearanceModelDefault = ShapeAppearanceModel.builder(context, attrs, R.attr.bottomSheetStyle, DEF_STYLE_RES).build();
        }
        createMaterialShapeDrawableIfNeeded(context);
        createShapeValueAnimator();
        if (Build.VERSION.SDK_INT >= 21) {
            this.elevation = a.getDimension(R.styleable.BottomSheetBehavior_Layout_android_elevation, -1.0f);
        }
        if (a.hasValue(R.styleable.BottomSheetBehavior_Layout_android_maxWidth)) {
            setMaxWidth(a.getDimensionPixelSize(R.styleable.BottomSheetBehavior_Layout_android_maxWidth, -1));
        }
        if (a.hasValue(R.styleable.BottomSheetBehavior_Layout_android_maxHeight)) {
            setMaxHeight(a.getDimensionPixelSize(R.styleable.BottomSheetBehavior_Layout_android_maxHeight, -1));
        }
        TypedValue value = a.peekValue(R.styleable.BottomSheetBehavior_Layout_behavior_peekHeight);
        if (value != null && value.data == -1) {
            setPeekHeight(value.data);
        } else {
            setPeekHeight(a.getDimensionPixelSize(R.styleable.BottomSheetBehavior_Layout_behavior_peekHeight, -1));
        }
        setHideable(a.getBoolean(R.styleable.BottomSheetBehavior_Layout_behavior_hideable, false));
        setGestureInsetBottomIgnored(a.getBoolean(R.styleable.BottomSheetBehavior_Layout_gestureInsetBottomIgnored, false));
        setFitToContents(a.getBoolean(R.styleable.BottomSheetBehavior_Layout_behavior_fitToContents, true));
        setSkipCollapsed(a.getBoolean(R.styleable.BottomSheetBehavior_Layout_behavior_skipCollapsed, false));
        setDraggable(a.getBoolean(R.styleable.BottomSheetBehavior_Layout_behavior_draggable, true));
        setSaveFlags(a.getInt(R.styleable.BottomSheetBehavior_Layout_behavior_saveFlags, 0));
        setHalfExpandedRatio(a.getFloat(R.styleable.BottomSheetBehavior_Layout_behavior_halfExpandedRatio, 0.5f));
        TypedValue value2 = a.peekValue(R.styleable.BottomSheetBehavior_Layout_behavior_expandedOffset);
        if (value2 != null && value2.type == 16) {
            setExpandedOffset(value2.data);
        } else {
            setExpandedOffset(a.getDimensionPixelOffset(R.styleable.BottomSheetBehavior_Layout_behavior_expandedOffset, 0));
        }
        this.paddingBottomSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_paddingBottomSystemWindowInsets, false);
        this.paddingLeftSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_paddingLeftSystemWindowInsets, false);
        this.paddingRightSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_paddingRightSystemWindowInsets, false);
        this.paddingTopSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_paddingTopSystemWindowInsets, true);
        this.marginLeftSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_marginLeftSystemWindowInsets, false);
        this.marginRightSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_marginRightSystemWindowInsets, false);
        this.marginTopSystemWindowInsets = a.getBoolean(R.styleable.BottomSheetBehavior_Layout_marginTopSystemWindowInsets, false);
        a.recycle();
        ViewConfiguration configuration = ViewConfiguration.get(context);
        this.maximumVelocity = configuration.getScaledMaximumFlingVelocity();
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public Parcelable onSaveInstanceState(CoordinatorLayout parent, V child) {
        return new SavedState(super.onSaveInstanceState(parent, child), (BottomSheetBehavior<?>) this);
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onRestoreInstanceState(CoordinatorLayout parent, V child, Parcelable state) {
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(parent, child, ss.getSuperState());
        restoreOptionalState(ss);
        if (ss.state == 1 || ss.state == 2) {
            this.state = 4;
            this.lastStableState = 4;
            return;
        }
        int i = ss.state;
        this.state = i;
        this.lastStableState = i;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onAttachedToLayoutParams(CoordinatorLayout.LayoutParams layoutParams) {
        super.onAttachedToLayoutParams(layoutParams);
        this.viewRef = null;
        this.viewDragHelper = null;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onDetachedFromLayoutParams() {
        super.onDetachedFromLayoutParams();
        this.viewRef = null;
        this.viewDragHelper = null;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onMeasureChild(CoordinatorLayout parent, V child, int parentWidthMeasureSpec, int widthUsed, int parentHeightMeasureSpec, int heightUsed) {
        ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
        int childWidthMeasureSpec = getChildMeasureSpec(parentWidthMeasureSpec, parent.getPaddingLeft() + parent.getPaddingRight() + lp.leftMargin + lp.rightMargin + widthUsed, this.maxWidth, lp.width);
        int childHeightMeasureSpec = getChildMeasureSpec(parentHeightMeasureSpec, parent.getPaddingTop() + parent.getPaddingBottom() + lp.topMargin + lp.bottomMargin + heightUsed, this.maxHeight, lp.height);
        child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
        return true;
    }

    private int getChildMeasureSpec(int parentMeasureSpec, int padding, int maxSize, int childDimension) {
        int result = ViewGroup.getChildMeasureSpec(parentMeasureSpec, padding, childDimension);
        if (maxSize == -1) {
            return result;
        }
        int mode = View.MeasureSpec.getMode(result);
        int size = View.MeasureSpec.getSize(result);
        switch (mode) {
            case BasicMeasure.EXACTLY /* 1073741824 */:
                return View.MeasureSpec.makeMeasureSpec(Math.min(size, maxSize), BasicMeasure.EXACTLY);
            default:
                return View.MeasureSpec.makeMeasureSpec(size == 0 ? maxSize : Math.min(size, maxSize), Integer.MIN_VALUE);
        }
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        if (ViewCompat.getFitsSystemWindows(parent) && !ViewCompat.getFitsSystemWindows(child)) {
            child.setFitsSystemWindows(true);
        }
        if (this.viewRef == null) {
            this.peekHeightMin = parent.getResources().getDimensionPixelSize(R.dimen.design_bottom_sheet_peek_height_min);
            setWindowInsetsListener(child);
            this.viewRef = new WeakReference<>(child);
            MaterialShapeDrawable materialShapeDrawable = this.materialShapeDrawable;
            if (materialShapeDrawable != null) {
                ViewCompat.setBackground(child, materialShapeDrawable);
                MaterialShapeDrawable materialShapeDrawable2 = this.materialShapeDrawable;
                float f = this.elevation;
                if (f == -1.0f) {
                    f = ViewCompat.getElevation(child);
                }
                materialShapeDrawable2.setElevation(f);
                boolean z = this.state == 3;
                this.isShapeExpanded = z;
                this.materialShapeDrawable.setInterpolation(z ? 0.0f : 1.0f);
            } else {
                ColorStateList colorStateList = this.backgroundTint;
                if (colorStateList != null) {
                    ViewCompat.setBackgroundTintList(child, colorStateList);
                }
            }
            updateAccessibilityActions();
            if (ViewCompat.getImportantForAccessibility(child) == 0) {
                ViewCompat.setImportantForAccessibility(child, 1);
            }
        }
        if (this.viewDragHelper == null) {
            this.viewDragHelper = ViewDragHelper.create(parent, this.dragCallback);
        }
        int savedTop = child.getTop();
        parent.onLayoutChild(child, layoutDirection);
        this.parentWidth = parent.getWidth();
        this.parentHeight = parent.getHeight();
        int height = child.getHeight();
        this.childHeight = height;
        int i = this.parentHeight;
        int i2 = i - height;
        int i3 = this.insetTop;
        if (i2 < i3) {
            if (this.paddingTopSystemWindowInsets) {
                this.childHeight = i;
            } else {
                this.childHeight = i - i3;
            }
        }
        this.fitToContentsOffset = Math.max(0, i - this.childHeight);
        calculateHalfExpandedOffset();
        calculateCollapsedOffset();
        int i4 = this.state;
        if (i4 == 3) {
            ViewCompat.offsetTopAndBottom(child, getExpandedOffset());
        } else if (i4 == 6) {
            ViewCompat.offsetTopAndBottom(child, this.halfExpandedOffset);
        } else if (this.hideable && i4 == 5) {
            ViewCompat.offsetTopAndBottom(child, this.parentHeight);
        } else if (i4 == 4) {
            ViewCompat.offsetTopAndBottom(child, this.collapsedOffset);
        } else if (i4 == 1 || i4 == 2) {
            ViewCompat.offsetTopAndBottom(child, savedTop - child.getTop());
        }
        this.nestedScrollingChildRef = new WeakReference<>(findScrollingChild(child));
        for (int i5 = 0; i5 < this.callbacks.size(); i5++) {
            this.callbacks.get(i5).onLayout(child);
        }
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onInterceptTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        ViewDragHelper viewDragHelper;
        if (!child.isShown() || !this.draggable) {
            this.ignoreEvents = true;
            return false;
        }
        int action = event.getActionMasked();
        if (action == 0) {
            reset();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        switch (action) {
            case 0:
                int initialX = (int) event.getX();
                this.initialY = (int) event.getY();
                if (this.state != 2) {
                    WeakReference<View> weakReference = this.nestedScrollingChildRef;
                    View scroll = weakReference != null ? weakReference.get() : null;
                    if (scroll != null && parent.isPointInChildBounds(scroll, initialX, this.initialY)) {
                        this.activePointerId = event.getPointerId(event.getActionIndex());
                        this.touchingScrollingChild = true;
                    }
                }
                this.ignoreEvents = this.activePointerId == -1 && !parent.isPointInChildBounds(child, initialX, this.initialY);
                break;
            case 1:
            case 3:
                this.touchingScrollingChild = false;
                this.activePointerId = -1;
                if (this.ignoreEvents) {
                    this.ignoreEvents = false;
                    return false;
                }
                break;
        }
        if (this.ignoreEvents || (viewDragHelper = this.viewDragHelper) == null || !viewDragHelper.shouldInterceptTouchEvent(event)) {
            WeakReference<View> weakReference2 = this.nestedScrollingChildRef;
            View scroll2 = weakReference2 != null ? weakReference2.get() : null;
            return (action != 2 || scroll2 == null || this.ignoreEvents || this.state == 1 || parent.isPointInChildBounds(scroll2, (int) event.getX(), (int) event.getY()) || this.viewDragHelper == null || Math.abs(((float) this.initialY) - event.getY()) <= ((float) this.viewDragHelper.getTouchSlop())) ? false : true;
        }
        return true;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        if (!child.isShown()) {
            return false;
        }
        int action = event.getActionMasked();
        if (this.state == 1 && action == 0) {
            return true;
        }
        if (shouldHandleDraggingWithHelper()) {
            this.viewDragHelper.processTouchEvent(event);
        }
        if (action == 0) {
            reset();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        if (shouldHandleDraggingWithHelper() && action == 2 && !this.ignoreEvents && Math.abs(this.initialY - event.getY()) > this.viewDragHelper.getTouchSlop()) {
            this.viewDragHelper.captureChildView(child, event.getPointerId(event.getActionIndex()));
        }
        return !this.ignoreEvents;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onStartNestedScroll(CoordinatorLayout coordinatorLayout, V child, View directTargetChild, View target, int axes, int type) {
        this.lastNestedScrollDy = 0;
        this.nestedScrolled = false;
        return (axes & 2) != 0;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onNestedPreScroll(CoordinatorLayout coordinatorLayout, V child, View target, int dx, int dy, int[] consumed, int type) {
        if (type == 1) {
            return;
        }
        WeakReference<View> weakReference = this.nestedScrollingChildRef;
        View scrollingChild = weakReference != null ? weakReference.get() : null;
        if (isNestedScrollingCheckEnabled() && target != scrollingChild) {
            return;
        }
        int currentTop = child.getTop();
        int newTop = currentTop - dy;
        if (dy > 0) {
            if (newTop < getExpandedOffset()) {
                consumed[1] = currentTop - getExpandedOffset();
                ViewCompat.offsetTopAndBottom(child, -consumed[1]);
                setStateInternal(3);
            } else if (!this.draggable) {
                return;
            } else {
                consumed[1] = dy;
                ViewCompat.offsetTopAndBottom(child, -dy);
                setStateInternal(1);
            }
        } else if (dy < 0 && !target.canScrollVertically(-1)) {
            int i = this.collapsedOffset;
            if (newTop > i && !this.hideable) {
                consumed[1] = currentTop - i;
                ViewCompat.offsetTopAndBottom(child, -consumed[1]);
                setStateInternal(4);
            } else if (!this.draggable) {
                return;
            } else {
                consumed[1] = dy;
                ViewCompat.offsetTopAndBottom(child, -dy);
                setStateInternal(1);
            }
        }
        dispatchOnSlide(child.getTop());
        this.lastNestedScrollDy = dy;
        this.nestedScrolled = true;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onStopNestedScroll(CoordinatorLayout coordinatorLayout, V child, View target, int type) {
        int currentTop;
        WeakReference<View> weakReference;
        if (child.getTop() == getExpandedOffset()) {
            setStateInternal(3);
        } else if (isNestedScrollingCheckEnabled() && ((weakReference = this.nestedScrollingChildRef) == null || target != weakReference.get() || !this.nestedScrolled)) {
        } else {
            if (this.lastNestedScrollDy > 0) {
                if (this.fitToContents) {
                    currentTop = 3;
                } else if (child.getTop() > this.halfExpandedOffset) {
                    currentTop = 6;
                } else {
                    currentTop = 3;
                }
            } else if (this.hideable && shouldHide(child, getYVelocity())) {
                currentTop = 5;
            } else if (this.lastNestedScrollDy == 0) {
                int currentTop2 = child.getTop();
                if (this.fitToContents) {
                    if (Math.abs(currentTop2 - this.fitToContentsOffset) < Math.abs(currentTop2 - this.collapsedOffset)) {
                        currentTop = 3;
                    } else {
                        currentTop = 4;
                    }
                } else {
                    int targetState = this.halfExpandedOffset;
                    if (currentTop2 < targetState) {
                        if (currentTop2 < Math.abs(currentTop2 - this.collapsedOffset)) {
                            currentTop = 3;
                        } else if (shouldSkipHalfExpandedStateWhenDragging()) {
                            currentTop = 4;
                        } else {
                            currentTop = 6;
                        }
                    } else if (Math.abs(currentTop2 - targetState) < Math.abs(currentTop2 - this.collapsedOffset)) {
                        currentTop = 6;
                    } else {
                        currentTop = 4;
                    }
                }
            } else if (this.fitToContents) {
                currentTop = 4;
            } else {
                int currentTop3 = child.getTop();
                if (Math.abs(currentTop3 - this.halfExpandedOffset) < Math.abs(currentTop3 - this.collapsedOffset)) {
                    currentTop = 6;
                } else {
                    currentTop = 4;
                }
            }
            startSettling(child, currentTop, false);
            this.nestedScrolled = false;
        }
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onNestedScroll(CoordinatorLayout coordinatorLayout, V child, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type, int[] consumed) {
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onNestedPreFling(CoordinatorLayout coordinatorLayout, V child, View target, float velocityX, float velocityY) {
        WeakReference<View> weakReference;
        if (isNestedScrollingCheckEnabled() && (weakReference = this.nestedScrollingChildRef) != null && target == weakReference.get()) {
            return this.state != 3 || super.onNestedPreFling(coordinatorLayout, child, target, velocityX, velocityY);
        }
        return false;
    }

    public boolean isFitToContents() {
        return this.fitToContents;
    }

    public void setFitToContents(boolean fitToContents) {
        if (this.fitToContents == fitToContents) {
            return;
        }
        this.fitToContents = fitToContents;
        if (this.viewRef != null) {
            calculateCollapsedOffset();
        }
        setStateInternal((this.fitToContents && this.state == 6) ? 3 : this.state);
        updateAccessibilityActions();
    }

    public void setMaxWidth(int maxWidth) {
        this.maxWidth = maxWidth;
    }

    public int getMaxWidth() {
        return this.maxWidth;
    }

    public void setMaxHeight(int maxHeight) {
        this.maxHeight = maxHeight;
    }

    public int getMaxHeight() {
        return this.maxHeight;
    }

    public void setPeekHeight(int peekHeight) {
        setPeekHeight(peekHeight, false);
    }

    public final void setPeekHeight(int peekHeight, boolean animate) {
        boolean layout = false;
        if (peekHeight == -1) {
            if (!this.peekHeightAuto) {
                this.peekHeightAuto = true;
                layout = true;
            }
        } else if (this.peekHeightAuto || this.peekHeight != peekHeight) {
            this.peekHeightAuto = false;
            this.peekHeight = Math.max(0, peekHeight);
            layout = true;
        }
        if (layout) {
            updatePeekHeight(animate);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePeekHeight(boolean animate) {
        V view;
        if (this.viewRef != null) {
            calculateCollapsedOffset();
            if (this.state == 4 && (view = this.viewRef.get()) != null) {
                if (animate) {
                    setState(4);
                } else {
                    view.requestLayout();
                }
            }
        }
    }

    public int getPeekHeight() {
        if (this.peekHeightAuto) {
            return -1;
        }
        return this.peekHeight;
    }

    public void setHalfExpandedRatio(float ratio) {
        if (ratio <= 0.0f || ratio >= 1.0f) {
            throw new IllegalArgumentException("ratio must be a float value between 0 and 1");
        }
        this.halfExpandedRatio = ratio;
        if (this.viewRef != null) {
            calculateHalfExpandedOffset();
        }
    }

    public float getHalfExpandedRatio() {
        return this.halfExpandedRatio;
    }

    public void setExpandedOffset(int offset) {
        if (offset < 0) {
            throw new IllegalArgumentException("offset must be greater than or equal to 0");
        }
        this.expandedOffset = offset;
    }

    public int getExpandedOffset() {
        if (this.fitToContents) {
            return this.fitToContentsOffset;
        }
        return Math.max(this.expandedOffset, this.paddingTopSystemWindowInsets ? 0 : this.insetTop);
    }

    public void setHideable(boolean hideable) {
        if (this.hideable != hideable) {
            this.hideable = hideable;
            if (!hideable && this.state == 5) {
                setState(4);
            }
            updateAccessibilityActions();
        }
    }

    public boolean isHideable() {
        return this.hideable;
    }

    public void setSkipCollapsed(boolean skipCollapsed) {
        this.skipCollapsed = skipCollapsed;
    }

    public boolean getSkipCollapsed() {
        return this.skipCollapsed;
    }

    public void setDraggable(boolean draggable) {
        this.draggable = draggable;
    }

    public boolean isDraggable() {
        return this.draggable;
    }

    public void setSaveFlags(int flags) {
        this.saveFlags = flags;
    }

    public int getSaveFlags() {
        return this.saveFlags;
    }

    @Deprecated
    public void setBottomSheetCallback(BottomSheetCallback callback) {
        Log.w(TAG, "BottomSheetBehavior now supports multiple callbacks. `setBottomSheetCallback()` removes all existing callbacks, including ones set internally by library authors, which may result in unintended behavior. This may change in the future. Please use `addBottomSheetCallback()` and `removeBottomSheetCallback()` instead to set your own callbacks.");
        this.callbacks.clear();
        if (callback != null) {
            this.callbacks.add(callback);
        }
    }

    public void addBottomSheetCallback(BottomSheetCallback callback) {
        if (!this.callbacks.contains(callback)) {
            this.callbacks.add(callback);
        }
    }

    public void removeBottomSheetCallback(BottomSheetCallback callback) {
        this.callbacks.remove(callback);
    }

    public void setState(int state) {
        final int finalState;
        if (state == 1 || state == 2) {
            StringBuilder sb = new StringBuilder();
            sb.append("STATE_");
            sb.append(state == 1 ? "DRAGGING" : "SETTLING");
            sb.append(" should not be set externally.");
            throw new IllegalArgumentException(sb.toString());
        } else if (!this.hideable && state == 5) {
            Log.w(TAG, "Cannot set state: " + state);
        } else {
            if (state == 6 && this.fitToContents && getTopOffsetForState(state) <= this.fitToContentsOffset) {
                finalState = 3;
            } else {
                finalState = state;
            }
            WeakReference<V> weakReference = this.viewRef;
            if (weakReference == null || weakReference.get() == null) {
                setStateInternal(state);
                return;
            }
            final V child = this.viewRef.get();
            runAfterLayout(child, new Runnable() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.1
                @Override // java.lang.Runnable
                public void run() {
                    BottomSheetBehavior.this.startSettling(child, finalState, false);
                }
            });
        }
    }

    private void runAfterLayout(V child, Runnable runnable) {
        if (isLayouting(child)) {
            child.post(runnable);
        } else {
            runnable.run();
        }
    }

    private boolean isLayouting(V child) {
        ViewParent parent = child.getParent();
        return parent != null && parent.isLayoutRequested() && ViewCompat.isAttachedToWindow(child);
    }

    public void setGestureInsetBottomIgnored(boolean gestureInsetBottomIgnored) {
        this.gestureInsetBottomIgnored = gestureInsetBottomIgnored;
    }

    public boolean isGestureInsetBottomIgnored() {
        return this.gestureInsetBottomIgnored;
    }

    public int getState() {
        return this.state;
    }

    void setStateInternal(int state) {
        View bottomSheet;
        if (this.state == state) {
            return;
        }
        this.state = state;
        if (state == 4 || state == 3 || state == 6 || (this.hideable && state == 5)) {
            this.lastStableState = state;
        }
        WeakReference<V> weakReference = this.viewRef;
        if (weakReference == null || (bottomSheet = weakReference.get()) == null) {
            return;
        }
        if (state == 3) {
            updateImportantForAccessibility(true);
        } else if (state == 6 || state == 5 || state == 4) {
            updateImportantForAccessibility(false);
        }
        updateDrawableForTargetState(state);
        for (int i = 0; i < this.callbacks.size(); i++) {
            this.callbacks.get(i).onStateChanged(bottomSheet, state);
        }
        updateAccessibilityActions();
    }

    private void updateDrawableForTargetState(int state) {
        ValueAnimator valueAnimator;
        if (state == 2) {
            return;
        }
        boolean expand = state == 3;
        if (this.isShapeExpanded != expand) {
            this.isShapeExpanded = expand;
            if (this.materialShapeDrawable != null && (valueAnimator = this.interpolatorAnimator) != null) {
                if (valueAnimator.isRunning()) {
                    this.interpolatorAnimator.reverse();
                    return;
                }
                float to = expand ? 0.0f : 1.0f;
                float from = 1.0f - to;
                this.interpolatorAnimator.setFloatValues(from, to);
                this.interpolatorAnimator.start();
            }
        }
    }

    private int calculatePeekHeight() {
        int i;
        if (this.peekHeightAuto) {
            int desiredHeight = Math.max(this.peekHeightMin, this.parentHeight - ((this.parentWidth * 9) / 16));
            return Math.min(desiredHeight, this.childHeight) + this.insetBottom;
        } else if (!this.gestureInsetBottomIgnored && !this.paddingBottomSystemWindowInsets && (i = this.gestureInsetBottom) > 0) {
            return Math.max(this.peekHeight, i + this.peekHeightGestureInsetBuffer);
        } else {
            return this.peekHeight + this.insetBottom;
        }
    }

    private void calculateCollapsedOffset() {
        int peek = calculatePeekHeight();
        if (this.fitToContents) {
            this.collapsedOffset = Math.max(this.parentHeight - peek, this.fitToContentsOffset);
        } else {
            this.collapsedOffset = this.parentHeight - peek;
        }
    }

    private void calculateHalfExpandedOffset() {
        this.halfExpandedOffset = (int) (this.parentHeight * (1.0f - this.halfExpandedRatio));
    }

    private void reset() {
        this.activePointerId = -1;
        VelocityTracker velocityTracker = this.velocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.velocityTracker = null;
        }
    }

    private void restoreOptionalState(SavedState ss) {
        int i = this.saveFlags;
        if (i == 0) {
            return;
        }
        if (i == -1 || (i & 1) == 1) {
            this.peekHeight = ss.peekHeight;
        }
        int i2 = this.saveFlags;
        if (i2 == -1 || (i2 & 2) == 2) {
            this.fitToContents = ss.fitToContents;
        }
        int i3 = this.saveFlags;
        if (i3 == -1 || (i3 & 4) == 4) {
            this.hideable = ss.hideable;
        }
        int i4 = this.saveFlags;
        if (i4 == -1 || (i4 & 8) == 8) {
            this.skipCollapsed = ss.skipCollapsed;
        }
    }

    boolean shouldHide(View child, float yvel) {
        if (this.skipCollapsed) {
            return true;
        }
        if (child.getTop() < this.collapsedOffset) {
            return false;
        }
        int peek = calculatePeekHeight();
        float newTop = child.getTop() + (0.1f * yvel);
        return Math.abs(newTop - ((float) this.collapsedOffset)) / ((float) peek) > 0.5f;
    }

    View findScrollingChild(View view) {
        if (ViewCompat.isNestedScrollingEnabled(view)) {
            return view;
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            int count = group.getChildCount();
            for (int i = 0; i < count; i++) {
                View scrollingChild = findScrollingChild(group.getChildAt(i));
                if (scrollingChild != null) {
                    return scrollingChild;
                }
            }
            return null;
        }
        return null;
    }

    private boolean shouldHandleDraggingWithHelper() {
        return this.viewDragHelper != null && (this.draggable || this.state == 1);
    }

    private void createMaterialShapeDrawableIfNeeded(Context context) {
        if (this.shapeAppearanceModelDefault == null) {
            return;
        }
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable(this.shapeAppearanceModelDefault);
        this.materialShapeDrawable = materialShapeDrawable;
        materialShapeDrawable.initializeElevationOverlay(context);
        ColorStateList colorStateList = this.backgroundTint;
        if (colorStateList != null) {
            this.materialShapeDrawable.setFillColor(colorStateList);
            return;
        }
        TypedValue defaultColor = new TypedValue();
        context.getTheme().resolveAttribute(16842801, defaultColor, true);
        this.materialShapeDrawable.setTint(defaultColor.data);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MaterialShapeDrawable getMaterialShapeDrawable() {
        return this.materialShapeDrawable;
    }

    private void createShapeValueAnimator() {
        ValueAnimator ofFloat = ValueAnimator.ofFloat(0.0f, 1.0f);
        this.interpolatorAnimator = ofFloat;
        ofFloat.setDuration(500L);
        this.interpolatorAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.2
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator animation) {
                float value = ((Float) animation.getAnimatedValue()).floatValue();
                if (BottomSheetBehavior.this.materialShapeDrawable != null) {
                    BottomSheetBehavior.this.materialShapeDrawable.setInterpolation(value);
                }
            }
        });
    }

    private void setWindowInsetsListener(View child) {
        final boolean shouldHandleGestureInsets = (Build.VERSION.SDK_INT < 29 || isGestureInsetBottomIgnored() || this.peekHeightAuto) ? false : true;
        if (!this.paddingBottomSystemWindowInsets && !this.paddingLeftSystemWindowInsets && !this.paddingRightSystemWindowInsets && !this.marginLeftSystemWindowInsets && !this.marginRightSystemWindowInsets && !this.marginTopSystemWindowInsets && !shouldHandleGestureInsets) {
            return;
        }
        ViewUtils.doOnApplyWindowInsets(child, new ViewUtils.OnApplyWindowInsetsListener() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.3
            @Override // com.google.android.material.internal.ViewUtils.OnApplyWindowInsetsListener
            public WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat insets, ViewUtils.RelativePadding initialPadding) {
                Insets systemBarInsets = insets.getInsets(WindowInsetsCompat.Type.systemBars());
                Insets mandatoryGestureInsets = insets.getInsets(WindowInsetsCompat.Type.mandatorySystemGestures());
                BottomSheetBehavior.this.insetTop = systemBarInsets.top;
                boolean isRtl = ViewUtils.isLayoutRtl(view);
                int bottomPadding = view.getPaddingBottom();
                int leftPadding = view.getPaddingLeft();
                int rightPadding = view.getPaddingRight();
                if (BottomSheetBehavior.this.paddingBottomSystemWindowInsets) {
                    BottomSheetBehavior.this.insetBottom = insets.getSystemWindowInsetBottom();
                    bottomPadding = initialPadding.bottom + BottomSheetBehavior.this.insetBottom;
                }
                if (BottomSheetBehavior.this.paddingLeftSystemWindowInsets) {
                    int leftPadding2 = isRtl ? initialPadding.end : initialPadding.start;
                    leftPadding = leftPadding2 + systemBarInsets.left;
                }
                if (BottomSheetBehavior.this.paddingRightSystemWindowInsets) {
                    int rightPadding2 = isRtl ? initialPadding.start : initialPadding.end;
                    rightPadding = rightPadding2 + systemBarInsets.right;
                }
                ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
                boolean marginUpdated = false;
                if (BottomSheetBehavior.this.marginLeftSystemWindowInsets && mlp.leftMargin != systemBarInsets.left) {
                    mlp.leftMargin = systemBarInsets.left;
                    marginUpdated = true;
                }
                if (BottomSheetBehavior.this.marginRightSystemWindowInsets && mlp.rightMargin != systemBarInsets.right) {
                    mlp.rightMargin = systemBarInsets.right;
                    marginUpdated = true;
                }
                if (BottomSheetBehavior.this.marginTopSystemWindowInsets && mlp.topMargin != systemBarInsets.top) {
                    mlp.topMargin = systemBarInsets.top;
                    marginUpdated = true;
                }
                if (marginUpdated) {
                    view.setLayoutParams(mlp);
                }
                view.setPadding(leftPadding, view.getPaddingTop(), rightPadding, bottomPadding);
                if (shouldHandleGestureInsets) {
                    BottomSheetBehavior.this.gestureInsetBottom = mandatoryGestureInsets.bottom;
                }
                if (BottomSheetBehavior.this.paddingBottomSystemWindowInsets || shouldHandleGestureInsets) {
                    BottomSheetBehavior.this.updatePeekHeight(false);
                }
                return insets;
            }
        });
    }

    private float getYVelocity() {
        VelocityTracker velocityTracker = this.velocityTracker;
        if (velocityTracker == null) {
            return 0.0f;
        }
        velocityTracker.computeCurrentVelocity(1000, this.maximumVelocity);
        return this.velocityTracker.getYVelocity(this.activePointerId);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startSettling(View child, int state, boolean isReleasingView) {
        int top = getTopOffsetForState(state);
        ViewDragHelper viewDragHelper = this.viewDragHelper;
        boolean settling = viewDragHelper != null && (!isReleasingView ? !viewDragHelper.smoothSlideViewTo(child, child.getLeft(), top) : !viewDragHelper.settleCapturedViewAt(child.getLeft(), top));
        if (settling) {
            setStateInternal(2);
            updateDrawableForTargetState(state);
            this.stateSettlingTracker.continueSettlingToState(state);
            return;
        }
        setStateInternal(state);
    }

    private int getTopOffsetForState(int state) {
        switch (state) {
            case 3:
                return getExpandedOffset();
            case 4:
                return this.collapsedOffset;
            case 5:
                return this.parentHeight;
            case 6:
                return this.halfExpandedOffset;
            default:
                throw new IllegalArgumentException("Invalid state to get top offset: " + state);
        }
    }

    void dispatchOnSlide(int top) {
        float f;
        View bottomSheet = this.viewRef.get();
        if (bottomSheet != null && !this.callbacks.isEmpty()) {
            int i = this.collapsedOffset;
            if (top > i || i == getExpandedOffset()) {
                int i2 = this.collapsedOffset;
                f = (i2 - top) / (this.parentHeight - i2);
            } else {
                int i3 = this.collapsedOffset;
                f = (i3 - top) / (i3 - getExpandedOffset());
            }
            float slideOffset = f;
            for (int i4 = 0; i4 < this.callbacks.size(); i4++) {
                this.callbacks.get(i4).onSlide(bottomSheet, slideOffset);
            }
        }
    }

    int getPeekHeightMin() {
        return this.peekHeightMin;
    }

    public void disableShapeAnimations() {
        this.interpolatorAnimator = null;
    }

    public boolean isNestedScrollingCheckEnabled() {
        return true;
    }

    public boolean shouldSkipHalfExpandedStateWhenDragging() {
        return false;
    }

    public boolean shouldSkipSmoothAnimation() {
        return true;
    }

    public boolean shouldExpandOnUpwardDrag(long dragDurationMillis, float yPositionPercentage) {
        return false;
    }

    public void setHideableInternal(boolean hideable) {
        this.hideable = hideable;
    }

    public int getLastStableState() {
        return this.lastStableState;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class StateSettlingTracker {
        private final Runnable continueSettlingRunnable;
        private boolean isContinueSettlingRunnablePosted;
        private int targetState;

        private StateSettlingTracker() {
            this.continueSettlingRunnable = new Runnable() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.StateSettlingTracker.1
                @Override // java.lang.Runnable
                public void run() {
                    StateSettlingTracker.this.isContinueSettlingRunnablePosted = false;
                    if (BottomSheetBehavior.this.viewDragHelper != null && BottomSheetBehavior.this.viewDragHelper.continueSettling(true)) {
                        StateSettlingTracker stateSettlingTracker = StateSettlingTracker.this;
                        stateSettlingTracker.continueSettlingToState(stateSettlingTracker.targetState);
                    } else if (BottomSheetBehavior.this.state == 2) {
                        BottomSheetBehavior.this.setStateInternal(StateSettlingTracker.this.targetState);
                    }
                }
            };
        }

        void continueSettlingToState(int targetState) {
            if (BottomSheetBehavior.this.viewRef == null || BottomSheetBehavior.this.viewRef.get() == null) {
                return;
            }
            this.targetState = targetState;
            if (!this.isContinueSettlingRunnablePosted) {
                ViewCompat.postOnAnimation(BottomSheetBehavior.this.viewRef.get(), this.continueSettlingRunnable);
                this.isContinueSettlingRunnablePosted = true;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.ClassLoaderCreator
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, (ClassLoader) null);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        boolean fitToContents;
        boolean hideable;
        int peekHeight;
        boolean skipCollapsed;
        final int state;

        public SavedState(Parcel source) {
            this(source, (ClassLoader) null);
        }

        public SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            this.state = source.readInt();
            this.peekHeight = source.readInt();
            this.fitToContents = source.readInt() == 1;
            this.hideable = source.readInt() == 1;
            this.skipCollapsed = source.readInt() == 1;
        }

        public SavedState(Parcelable superState, BottomSheetBehavior<?> behavior) {
            super(superState);
            this.state = behavior.state;
            this.peekHeight = ((BottomSheetBehavior) behavior).peekHeight;
            this.fitToContents = ((BottomSheetBehavior) behavior).fitToContents;
            this.hideable = behavior.hideable;
            this.skipCollapsed = ((BottomSheetBehavior) behavior).skipCollapsed;
        }

        @Deprecated
        public SavedState(Parcelable superstate, int state) {
            super(superstate);
            this.state = state;
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.state);
            out.writeInt(this.peekHeight);
            out.writeInt(this.fitToContents ? 1 : 0);
            out.writeInt(this.hideable ? 1 : 0);
            out.writeInt(this.skipCollapsed ? 1 : 0);
        }
    }

    public static <V extends View> BottomSheetBehavior<V> from(V view) {
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (!(params instanceof CoordinatorLayout.LayoutParams)) {
            throw new IllegalArgumentException("The view is not a child of CoordinatorLayout");
        }
        CoordinatorLayout.Behavior<?> behavior = ((CoordinatorLayout.LayoutParams) params).getBehavior();
        if (!(behavior instanceof BottomSheetBehavior)) {
            throw new IllegalArgumentException("The view is not associated with BottomSheetBehavior");
        }
        return (BottomSheetBehavior) behavior;
    }

    public void setUpdateImportantForAccessibilityOnSiblings(boolean updateImportantForAccessibilityOnSiblings) {
        this.updateImportantForAccessibilityOnSiblings = updateImportantForAccessibilityOnSiblings;
    }

    private void updateImportantForAccessibility(boolean expanded) {
        Map<View, Integer> map;
        WeakReference<V> weakReference = this.viewRef;
        if (weakReference == null) {
            return;
        }
        ViewParent viewParent = weakReference.get().getParent();
        if (!(viewParent instanceof CoordinatorLayout)) {
            return;
        }
        CoordinatorLayout parent = (CoordinatorLayout) viewParent;
        int childCount = parent.getChildCount();
        if (Build.VERSION.SDK_INT >= 16 && expanded) {
            if (this.importantForAccessibilityMap == null) {
                this.importantForAccessibilityMap = new HashMap(childCount);
            } else {
                return;
            }
        }
        for (int i = 0; i < childCount; i++) {
            View child = parent.getChildAt(i);
            if (child != this.viewRef.get()) {
                if (expanded) {
                    if (Build.VERSION.SDK_INT >= 16) {
                        this.importantForAccessibilityMap.put(child, Integer.valueOf(child.getImportantForAccessibility()));
                    }
                    if (this.updateImportantForAccessibilityOnSiblings) {
                        ViewCompat.setImportantForAccessibility(child, 4);
                    }
                } else if (this.updateImportantForAccessibilityOnSiblings && (map = this.importantForAccessibilityMap) != null && map.containsKey(child)) {
                    ViewCompat.setImportantForAccessibility(child, this.importantForAccessibilityMap.get(child).intValue());
                }
            }
        }
        if (!expanded) {
            this.importantForAccessibilityMap = null;
        } else if (this.updateImportantForAccessibilityOnSiblings) {
            this.viewRef.get().sendAccessibilityEvent(8);
        }
    }

    private void updateAccessibilityActions() {
        V child;
        WeakReference<V> weakReference = this.viewRef;
        if (weakReference == null || (child = weakReference.get()) == null) {
            return;
        }
        ViewCompat.removeAccessibilityAction(child, 524288);
        ViewCompat.removeAccessibilityAction(child, 262144);
        ViewCompat.removeAccessibilityAction(child, 1048576);
        int i = this.expandHalfwayActionId;
        if (i != -1) {
            ViewCompat.removeAccessibilityAction(child, i);
        }
        if (!this.fitToContents && this.state != 6) {
            this.expandHalfwayActionId = addAccessibilityActionForState(child, R.string.bottomsheet_action_expand_halfway, 6);
        }
        if (this.hideable && this.state != 5) {
            replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_DISMISS, 5);
        }
        switch (this.state) {
            case 3:
                int nextState = this.fitToContents ? 4 : 6;
                replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_COLLAPSE, nextState);
                return;
            case 4:
                int nextState2 = this.fitToContents ? 3 : 6;
                replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_EXPAND, nextState2);
                return;
            case 5:
            default:
                return;
            case 6:
                replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_COLLAPSE, 4);
                replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_EXPAND, 3);
                return;
        }
    }

    private void replaceAccessibilityActionForState(V child, AccessibilityNodeInfoCompat.AccessibilityActionCompat action, int state) {
        ViewCompat.replaceAccessibilityAction(child, action, null, createAccessibilityViewCommandForState(state));
    }

    private int addAccessibilityActionForState(V child, int stringResId, int state) {
        return ViewCompat.addAccessibilityAction(child, child.getResources().getString(stringResId), createAccessibilityViewCommandForState(state));
    }

    private AccessibilityViewCommand createAccessibilityViewCommandForState(final int state) {
        return new AccessibilityViewCommand() { // from class: com.google.android.material.bottomsheet.BottomSheetBehavior.5
            @Override // androidx.core.view.accessibility.AccessibilityViewCommand
            public boolean perform(View view, AccessibilityViewCommand.CommandArguments arguments) {
                BottomSheetBehavior.this.setState(state);
                return true;
            }
        };
    }
}
